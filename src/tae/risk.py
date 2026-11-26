"""Custom risk scales: what each likelihood and impact level means, and severity bands.

ThreatAtlas scores risk as likelihood × impact (1–5 each) with fixed bands (20+
critical, 12+ high, 6+ medium, otherwise low). An organisation can define its own
scale in a framework file (``kind: framework``, key ``risk_scale``) or a standalone
file (``kind: risk-scale``). ThreatAtlas keeps its own stored scores; ``tae`` uses the
custom scale for the threats of the frameworks it applies to, in validation and in
reports.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, field_validator, model_validator

from tae.errors import InputError
from tae.models.api import SEVERITY_BANDS

LEVELS = (1, 2, 3, 4, 5)


class RiskScaleError(InputError):
    """A risk scale definition is invalid."""


class Level(BaseModel):
    model_config = ConfigDict(extra="forbid")

    label: str = Field(min_length=1, max_length=60)
    description: str | None = None


class Bands(BaseModel):
    """Minimum likelihood × impact score for each severity; anything lower is low."""

    model_config = ConfigDict(extra="forbid")

    critical: int = Field(ge=2, le=25)
    high: int = Field(ge=2, le=25)
    medium: int = Field(ge=2, le=25)

    @model_validator(mode="after")
    def _ordered(self) -> Bands:
        if not self.critical > self.high > self.medium:
            raise ValueError("bands must satisfy critical > high > medium")
        return self


DEFAULT_BANDS = Bands(**{label: minimum for minimum, label in SEVERITY_BANDS if label != "low"})


class RiskScale(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str | None = Field(None, description="Shown in reports, e.g. 'Payments risk scale'.")
    likelihood: dict[int, Level] = Field(description="Levels 1 to 5.")
    impact: dict[int, Level] = Field(description="Levels 1 to 5.")
    bands: Bands = Field(default_factory=lambda: DEFAULT_BANDS.model_copy())
    frameworks: list[str] | None = Field(
        None,
        description="Framework names this scale applies to. In a framework file it defaults to that "
        "framework; in a standalone file, to every framework.",
    )

    @field_validator("likelihood", "impact")
    @classmethod
    def _five_levels(cls, v: dict[int, Level]) -> dict[int, Level]:
        if sorted(v) != list(LEVELS):
            raise ValueError("define exactly the levels 1, 2, 3, 4 and 5")
        return dict(sorted(v.items()))

    def severity(self, score: int | None) -> str | None:
        if score is None:
            return None
        if score >= self.bands.critical:
            return "critical"
        if score >= self.bands.high:
            return "high"
        if score >= self.bands.medium:
            return "medium"
        return "low"

    def applies_to(self, framework: str | None) -> bool:
        if self.frameworks is None:
            return True
        return framework is not None and framework.casefold() in {f.casefold() for f in self.frameworks}

    def describe(self) -> str:
        """Plain-text summary, written into a framework's description in ThreatAtlas."""
        lines = [f"Risk scale{f': {self.name}' if self.name else ''} (risk = likelihood × impact)."]
        lines.append(
            "Likelihood: " + "; ".join(f"{n} {lvl.label}" for n, lvl in self.likelihood.items()) + "."
        )
        lines.append("Impact: " + "; ".join(f"{n} {lvl.label}" for n, lvl in self.impact.items()) + ".")
        b = self.bands
        lines.append(
            f"Severity: critical from {b.critical}, high from {b.high}, "
            f"medium from {b.medium}, otherwise low."
        )
        return "\n".join(lines)


class RiskScales:
    """The scales in effect for a run; picks the scale for each framework."""

    def __init__(self, scales: list[RiskScale] | None = None) -> None:
        self.scales = list(scales or [])

    def __bool__(self) -> bool:
        return bool(self.scales)

    def for_framework(self, framework: str | None) -> RiskScale | None:
        # Scales naming frameworks explicitly win over catch-all ones.
        explicit = [s for s in self.scales if s.frameworks is not None and s.applies_to(framework)]
        if explicit:
            return explicit[0]
        return next((s for s in self.scales if s.frameworks is None), None)


def scale_from_document(doc: Any, source: str) -> RiskScale | None:
    """Read the scale from a ``kind: framework`` or ``kind: risk-scale`` document."""
    if not isinstance(doc, dict):
        raise RiskScaleError(f"{source}: expected a mapping at the top level")
    kind = doc.get("kind")
    try:
        if kind == "risk-scale":
            data = {k: v for k, v in doc.items() if k != "kind"}
            return RiskScale.model_validate(data)
        if kind == "framework":
            raw = doc.get("risk_scale")
            if raw is None:
                return None
            scale = RiskScale.model_validate(raw)
            if scale.frameworks is None:
                name = (doc.get("framework") or {}).get("name")
                scale.frameworks = [name] if name else None
            return scale
    except ValidationError as exc:
        raise RiskScaleError(f"{source}: invalid risk scale: {exc}") from exc
    raise RiskScaleError(f"{source}: expected 'kind: framework' or 'kind: risk-scale', got {kind!r}")


def load_risk_scale(path: Path) -> RiskScale:
    try:
        doc = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise RiskScaleError(f"Cannot read risk scale {path}: {exc}") from exc
    scale = scale_from_document(doc, str(path))
    if scale is None:
        raise RiskScaleError(f"{path} has no risk_scale section")
    return scale


def load_risk_scales(paths: list[Path]) -> RiskScales:
    return RiskScales([load_risk_scale(p) for p in paths])
