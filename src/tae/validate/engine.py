"""Rule registry, validation config, and the runner."""

from __future__ import annotations

from collections import Counter
from collections.abc import Callable, Iterable
from dataclasses import dataclass, field
from datetime import date
from pathlib import Path
from typing import Any

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, model_validator

from tae.errors import InputError
from tae.snapshot.view import DiagramView, Element, MitigationItem, ProductView, ThreatItem
from tae.validate.findings import EntityRef, FailLevel, Finding, Level


class ValidationConfigError(InputError):
    """The validation config file is invalid."""


# ── configuration ─────────────────────────────────────────────────────────────────


class Params(BaseModel):
    """Tunable thresholds used by the built-in rules."""

    model_config = ConfigDict(extra="forbid")

    review_warning_days: int = Field(30, ge=0, description="Warn this many days before a risk review is due.")
    open_risk_severities: list[str] = Field(
        default_factory=lambda: ["high", "critical"],
        description="Severities that must not stay open (status 'identified').",
    )
    required_product_fields: list[str] = Field(
        default_factory=lambda: ["description", "owner_name", "owner_email", "reviewer"],
        description="Product fields that must be filled in.",
    )
    uncovered_element_types: list[str] = Field(
        default_factory=lambda: ["process", "datastore", "external", "flow"],
        description="Element types expected to have at least one threat.",
    )


class ValidationConfig(BaseModel):
    """Contents of a validation config file (YAML)."""

    model_config = ConfigDict(extra="forbid")

    disable: list[str] = Field(default_factory=list, description="Rule IDs to skip.")
    levels: dict[str, Level] = Field(default_factory=dict, description="Override a rule's level.")
    params: Params = Field(default_factory=Params)
    rules: list[Any] = Field(default_factory=list, description="Custom rules (see docs/validation-rules.md).")
    risk_scales: list[str] = Field(
        default_factory=list,
        description="Framework or risk-scale files whose custom scales set threat severities.",
    )
    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    def scale_paths(self) -> list[Path]:
        """``risk_scales`` entries, relative to the config file's directory."""
        return [
            p if p.is_absolute() else self._base_dir / p
            for p in (Path(x).expanduser() for x in self.risk_scales)
        ]

    @model_validator(mode="after")
    def _parse_custom(self) -> ValidationConfig:
        from tae.validate.custom import CustomRule

        self.rules = [r if isinstance(r, CustomRule) else CustomRule.model_validate(r) for r in self.rules]
        return self

    @classmethod
    def load(cls, path: Path) -> ValidationConfig:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8")) or {}
        except (OSError, yaml.YAMLError) as exc:
            raise ValidationConfigError(f"Cannot read validation config {path}: {exc}") from exc
        config = cls.from_data(raw, str(path))
        config._base_dir = path.resolve().parent
        return config

    @classmethod
    def from_data(cls, raw: Any, source: str = "validation config") -> ValidationConfig:
        if not isinstance(raw, dict):
            raise ValidationConfigError(f"{source}: expected a mapping at the top level")
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise ValidationConfigError(f"{source}: {exc}") from exc


# ── rules ─────────────────────────────────────────────────────────────────────────


@dataclass
class RuleContext:
    view: ProductView
    params: Params
    as_of: date


Hit = tuple[EntityRef, str] | tuple[EntityRef, str, dict[str, Any]]
CheckFn = Callable[[RuleContext], Iterable[Hit]]


@dataclass(frozen=True)
class Rule:
    id: str
    title: str
    family: str
    level: Level
    description: str
    check: CheckFn = field(compare=False)
    builtin: bool = True


REGISTRY: dict[str, Rule] = {}

FAMILIES = {
    "STR": "Structure",
    "REF": "References",
    "CON": "Consistency",
    "CMP": "Completeness",
    "GOV": "Governance",
    "CUSTOM": "Custom",
}


def rule(rule_id: str, title: str, level: Level, description: str) -> Callable[[CheckFn], CheckFn]:
    family = FAMILIES[rule_id.rstrip("0123456789")]

    def register(fn: CheckFn) -> CheckFn:
        if rule_id in REGISTRY:
            raise RuntimeError(f"Duplicate rule ID {rule_id}")
        REGISTRY[rule_id] = Rule(rule_id, title, family, level, description, fn)
        return fn

    return register


def builtin_rules() -> list[Rule]:
    import tae.validate.rules  # noqa: F401  (registers the built-in rules)

    return sorted(REGISTRY.values(), key=lambda r: r.id)


# ── entity references ────────────────────────────────────────────────────────────


def ref_product(view: ProductView) -> EntityRef:
    return EntityRef("product", str(view.product.id), view.product.name)


def ref_diagram(d: DiagramView) -> EntityRef:
    return EntityRef("diagram", str(d.id), d.name, d.id, d.name)


def ref_element(e: Element, d: DiagramView) -> EntityRef:
    return EntityRef("element", e.id, e.label, d.id, d.name)


def ref_model(model_id: int, name: str, d: DiagramView | None) -> EntityRef:
    return EntityRef("model", str(model_id), name, d.id if d else None, d.name if d else None)


def ref_threat(t: ThreatItem) -> EntityRef:
    label = f"{t.name} @ {t.element_label}"
    return EntityRef("diagram_threat", str(t.id), label, t.diagram.id, t.diagram.name, t.ref or None)


def ref_mitigation(m: MitigationItem) -> EntityRef:
    label = f"{m.name} @ {m.element_label}"
    return EntityRef("diagram_mitigation", str(m.id), label, m.diagram.id, m.diagram.name, m.ref or None)


# ── running ──────────────────────────────────────────────────────────────────────


@dataclass
class ValidationResult:
    findings: list[Finding]
    rules: list[Rule]
    as_of: date

    def counts(self) -> dict[str, int]:
        c = Counter(f.level.value for f in self.findings)
        return {lvl.value: c.get(lvl.value, 0) for lvl in (Level.error, Level.warning, Level.info)}

    def failing(self, fail_level: FailLevel) -> list[Finding]:
        return [f for f in self.findings if fail_level.fails(f.level)]

    def fails(self, fail_level: FailLevel) -> bool:
        return bool(self.failing(fail_level))

    def to_dict(self, fail_level: FailLevel | None = None) -> dict[str, Any]:
        data: dict[str, Any] = {
            "as_of": self.as_of.isoformat(),
            "counts": self.counts(),
            "rules_run": [r.id for r in self.rules],
            "findings": [f.to_dict() for f in self.findings],
        }
        if fail_level is not None:
            data["fail_level"] = fail_level.value
            data["passed"] = not self.fails(fail_level)
        return data


def active_rules(config: ValidationConfig) -> list[Rule]:
    builtins = builtin_rules()
    custom = [r.to_rule() for r in config.rules]
    known = {r.id for r in builtins} | {r.id for r in custom}

    clashes = {r.id for r in custom} & {r.id for r in builtins}
    if clashes:
        raise ValidationConfigError(
            f"Custom rule IDs clash with built-in rules: {', '.join(sorted(clashes))}"
        )
    dupes = [rid for rid, n in Counter(r.id for r in custom).items() if n > 1]
    if dupes:
        raise ValidationConfigError(f"Duplicate custom rule IDs: {', '.join(sorted(dupes))}")
    unknown = (set(config.disable) | set(config.levels)) - known
    if unknown:
        raise ValidationConfigError(f"Unknown rule IDs in disable/levels: {', '.join(sorted(unknown))}")

    disabled = set(config.disable)
    rules = []
    for r in [*builtins, *custom]:
        if r.id in disabled:
            continue
        if r.id in config.levels:
            r = Rule(r.id, r.title, r.family, config.levels[r.id], r.description, r.check, r.builtin)
        rules.append(r)
    return rules


def run(
    view: ProductView, config: ValidationConfig | None = None, as_of: date | None = None
) -> ValidationResult:
    config = config or ValidationConfig()
    as_of = as_of or date.today()
    ctx = RuleContext(view=view, params=config.params, as_of=as_of)
    rules = active_rules(config)

    findings: list[Finding] = []
    for r in rules:
        for hit in r.check(ctx):
            entity, message = hit[0], hit[1]
            details = hit[2] if len(hit) > 2 else {}
            findings.append(Finding(r.id, r.level, message, entity, r.title, details))
    findings.sort(key=lambda f: (-f.level.rank, f.rule_id, f.entity.diagram_name or "", f.entity.label))
    return ValidationResult(findings=findings, rules=rules, as_of=as_of)
