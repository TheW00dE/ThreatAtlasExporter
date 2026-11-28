"""The two YAML documents ``tae import`` understands.

``kind: framework``
    A custom threat-modelling methodology: the framework, its threat and mitigation
    catalogue, and optionally a custom risk scale.

``kind: threat-model``
    One product's analysis: the product, its data flow diagrams, the threat models
    (frameworks applied to each diagram), and the threats and mitigations identified
    on diagram elements.

Everything is checked here, before anything is sent to ThreatAtlas.
"""

from __future__ import annotations

from datetime import date
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, ValidationError, model_validator

from tae.errors import InputError
from tae.risk import RiskScale

ElementId = Annotated[str, Field(pattern=r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,99}$")]
Score = Annotated[int, Field(ge=1, le=5)]


class ImportFileError(InputError):
    """The import file is invalid."""


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid", populate_by_name=True)


def _dupes(names: list[str]) -> list[str]:
    seen: set[str] = set()
    dupes: list[str] = []
    for n in names:
        key = n.casefold()
        if key in seen and n not in dupes:
            dupes.append(n)
        seen.add(key)
    return dupes


# ── kind: framework ─────────────────────────────────────────────────────────────


class FrameworkInfo(Strict):
    name: str = Field(min_length=1, max_length=100)
    description: str | None = None


class CatalogMitigation(Strict):
    name: str = Field(min_length=1, max_length=200)
    category: str | None = Field(None, max_length=100)
    description: str | None = None


class CatalogThreat(Strict):
    name: str = Field(min_length=1, max_length=200)
    category: str | None = Field(None, max_length=100)
    description: str | None = None
    mitigations: list[str] = Field(
        default_factory=list, description="Names of mitigations in this file that address the threat."
    )


class FrameworkDocument(Strict):
    kind: Literal["framework"]
    framework: FrameworkInfo
    categories: list[str] | None = Field(
        None, description="If given, every entry's category must be one of these."
    )
    risk_scale: RiskScale | None = None
    threats: list[CatalogThreat] = Field(default_factory=list)
    mitigations: list[CatalogMitigation] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> FrameworkDocument:
        problems: list[str] = []
        for what, names in (
            ("threat", [t.name for t in self.threats]),
            ("mitigation", [m.name for m in self.mitigations]),
        ):
            for d in _dupes(names):
                problems.append(f"duplicate {what} name {d!r}")
        mitigation_names = {m.name.casefold() for m in self.mitigations}
        for t in self.threats:
            for ref in t.mitigations:
                if ref.casefold() not in mitigation_names:
                    problems.append(f"threat {t.name!r} lists mitigation {ref!r}, which isn't in this file")
        if self.categories is not None:
            allowed = {c.casefold() for c in self.categories}
            entries: list[CatalogThreat | CatalogMitigation] = [*self.threats, *self.mitigations]
            for entry in entries:
                if entry.category is not None and entry.category.casefold() not in allowed:
                    problems.append(
                        f"{entry.name!r} has category {entry.category!r}, which isn't in categories"
                    )
        if self.risk_scale is not None and self.risk_scale.frameworks is None:
            self.risk_scale.frameworks = [self.framework.name]
        if problems:
            raise ValueError("; ".join(problems))
        return self


# ── kind: threat-model ─────────────────────────────────────────────────────────


class ProductInfo(Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    status: Literal["design", "development", "testing", "deployment", "production"] | None = None
    is_public: bool | None = None
    business_area: str | None = Field(None, max_length=200)
    owner_name: str | None = Field(None, max_length=200)
    owner_email: str | None = None
    reviewer: str | None = Field(None, max_length=500)
    contributors: str | None = None
    repository_url: str | None = Field(None, max_length=500)
    confluence_url: str | None = Field(None, max_length=500)
    application_url: str | None = Field(None, max_length=500)
    jira_project_key: str | None = Field(None, max_length=50)


class Element(Strict):
    id: ElementId
    type: Literal["process", "datastore", "external", "boundary"]
    label: str = Field(min_length=1, max_length=200)
    boundary: str | None = Field(None, description="ID of the trust boundary this element sits in.")
    position: tuple[float, float] | None = Field(
        None, description="[x, y]; laid out automatically if omitted."
    )
    size: tuple[float, float] | None = Field(
        None, description="[width, height] for a boundary; fitted if omitted."
    )


class Flow(Strict):
    id: ElementId
    from_: str = Field(alias="from")
    to: str
    label: str | None = Field(None, max_length=200)


class Residual(Strict):
    likelihood: Score
    impact: Score
    comments: str | None = None


class Acceptance(Strict):
    justification: str = Field(min_length=1)
    approver_id: int | None = Field(None, description="ThreatAtlas user ID of the approver.")
    review_date: date | None = None


class MitigationOnThreat(Strict):
    mitigation: str = Field(description="Name of a mitigation in the framework's catalogue.")
    status: Literal["proposed", "implemented", "verified"] = "proposed"
    comments: str | None = None


class ThreatOnElement(Strict):
    threat: str = Field(description="Name of a threat in the framework's catalogue.")
    element: str = Field(description="ID of the element or flow the threat applies to.")
    likelihood: Score | None = None
    impact: Score | None = None
    status: Literal["identified", "mitigated", "accepted"] = "identified"
    comments: str | None = None
    residual: Residual | None = None
    acceptance: Acceptance | None = Field(
        None, description="Risk acceptance request (status must be accepted). Approval stays in ThreatAtlas."
    )
    mitigations: list[MitigationOnThreat] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> ThreatOnElement:
        if self.acceptance is not None and self.status != "accepted":
            raise ValueError(
                f"threat {self.threat!r} on {self.element!r}: acceptance is only allowed with status accepted"
            )
        if (self.likelihood is None) != (self.impact is None):
            raise ValueError(
                f"threat {self.threat!r} on {self.element!r}: give both likelihood and impact, or neither"
            )
        dupes = _dupes([m.mitigation for m in self.mitigations])
        if dupes:
            raise ValueError(
                f"threat {self.threat!r} on {self.element!r}: mitigation listed twice: {', '.join(dupes)}"
            )
        return self


class ModelEntry(Strict):
    framework: str = Field(description="Framework name, e.g. STRIDE or an imported custom framework.")
    name: str | None = Field(
        None, max_length=200, description="Threat model name; defaults to the framework name."
    )
    description: str | None = None
    status: Literal["in_progress", "completed", "archived"] | None = None
    threats: list[ThreatOnElement] = Field(default_factory=list)

    @property
    def model_name(self) -> str:
        return self.name or self.framework


class DiagramEntry(Strict):
    name: str = Field(min_length=1, max_length=200)
    description: str | None = None
    elements: list[Element] = Field(min_length=1)
    flows: list[Flow] = Field(default_factory=list)
    models: list[ModelEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> DiagramEntry:
        problems: list[str] = []
        ids = [e.id for e in self.elements] + [f.id for f in self.flows]
        for d in _dupes(ids):
            problems.append(f"ID {d!r} is used more than once")
        elements = {e.id: e for e in self.elements}
        for e in self.elements:
            if e.boundary is not None:
                parent = elements.get(e.boundary)
                if parent is None or parent.type != "boundary":
                    problems.append(
                        f"element {e.id!r}: boundary {e.boundary!r} isn't a boundary in this diagram"
                    )
            if e.size is not None and e.type != "boundary":
                problems.append(f"element {e.id!r}: only boundaries take a size")
        for e in self.elements:  # boundary nesting must not loop
            seen, current = {e.id}, e.boundary
            while current is not None and current in elements:
                if current in seen:
                    problems.append(f"boundaries around {e.id!r} contain each other")
                    break
                seen.add(current)
                current = elements[current].boundary
        for f in self.flows:
            for end in (f.from_, f.to):
                target = elements.get(end)
                if target is None:
                    problems.append(f"flow {f.id!r}: {end!r} isn't an element in this diagram")
                elif target.type == "boundary":
                    problems.append(f"flow {f.id!r}: flows connect elements, not boundaries ({end!r})")
        targets = {e.id for e in self.elements if e.type != "boundary"} | {f.id for f in self.flows}
        for d in _dupes([m.model_name for m in self.models]):
            problems.append(f"threat model {d!r} appears twice")
        for m in self.models:
            seen_threats: set[tuple[str, str]] = set()
            for t in m.threats:
                if t.element not in targets:
                    problems.append(
                        f"model {m.model_name!r}: threat {t.threat!r} is on {t.element!r}, "
                        "not an element or flow"
                    )
                key = (t.threat.casefold(), t.element)
                if key in seen_threats:
                    problems.append(
                        f"model {m.model_name!r}: threat {t.threat!r} on {t.element!r} is listed twice"
                    )
                seen_threats.add(key)
        if problems:
            raise ValueError(f"diagram {self.name!r}: " + "; ".join(problems))
        return self


class ThreatModelDocument(Strict):
    kind: Literal["threat-model"]
    product: ProductInfo
    diagrams: list[DiagramEntry] = Field(default_factory=list)

    @model_validator(mode="after")
    def _check(self) -> ThreatModelDocument:
        dupes = _dupes([d.name for d in self.diagrams])
        if dupes:
            raise ValueError(f"diagram names appear twice: {', '.join(dupes)}")
        return self


Document = FrameworkDocument | ThreatModelDocument


def parse_document(raw: Any, source: str) -> Document:
    if not isinstance(raw, dict):
        raise ImportFileError(f"{source}: expected a mapping at the top level")
    kind = raw.get("kind")
    model: type[FrameworkDocument] | type[ThreatModelDocument]
    if kind == "framework":
        model = FrameworkDocument
    elif kind == "threat-model":
        model = ThreatModelDocument
    elif kind == "risk-scale":
        raise ImportFileError(
            f"{source}: risk-scale files aren't imported into ThreatAtlas; reference them with "
            "risk_scales in a report definition or validation config, or tae validate --risk-scale"
        )
    else:
        raise ImportFileError(f"{source}: 'kind' must be 'framework' or 'threat-model', got {kind!r}")
    try:
        return model.model_validate(raw)
    except ValidationError as exc:
        raise ImportFileError(f"{source}: {exc}") from exc


def load_document(path: Path) -> Document:
    try:
        raw = yaml.safe_load(path.read_text(encoding="utf-8"))
    except (OSError, yaml.YAMLError) as exc:
        raise ImportFileError(f"Cannot read {path}: {exc}") from exc
    return parse_document(raw, str(path))


def json_schema(kind: str) -> dict[str, Any]:
    if kind == "framework":
        schema: dict[str, Any] = FrameworkDocument.model_json_schema(by_alias=True)
    elif kind == "threat-model":
        schema = ThreatModelDocument.model_json_schema(by_alias=True)
    else:
        raise ValueError(f"Unknown kind {kind!r}")
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = f"ThreatAtlasExporter {kind} file"
    return schema
