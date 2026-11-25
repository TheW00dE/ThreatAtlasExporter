"""Custom rules defined in YAML.

Example::

    rules:
      - id: CUSTOM-001
        level: error
        applies_to: diagram_threat
        when:    { severity: [high, critical] }
        require: { status: [mitigated, accepted] }
        message: "{ref} {name} is {severity} and must be mitigated or accepted"

``when`` selects the entities the rule applies to (all of them if omitted);
``require`` must then hold for each one, otherwise a finding is raised.

A condition value can be:

- a scalar: equality (``status: accepted``)
- a list: membership (``severity: [high, critical]``)
- a mapping of operators, all of which must hold:
  ``eq, ne, in, not_in, gt, gte, lt, lte, exists, empty, matches, contains``

Date fields accept ISO dates, ``today``, or ``today+N`` / ``today-N`` (days).
Messages may reference fields as ``{field}``. Nothing is evaluated as code.
"""

from __future__ import annotations

import re
from collections.abc import Callable, Iterator
from datetime import date, datetime, timedelta
from typing import Any, Literal

from pydantic import BaseModel, ConfigDict, Field, field_validator, model_validator

from tae.snapshot.view import DiagramView, Element, MitigationItem, ProductView, ThreatItem
from tae.validate.findings import EntityRef, Level

AppliesTo = Literal["diagram_threat", "diagram_mitigation", "diagram", "model", "element", "product"]

OPERATORS = ("eq", "ne", "in", "not_in", "gt", "gte", "lt", "lte", "exists", "empty", "matches", "contains")

_THREAT_FIELDS = [
    "id",
    "ref",
    "name",
    "description",
    "category",
    "status",
    "likelihood",
    "impact",
    "risk_score",
    "severity",
    "residual_likelihood",
    "residual_impact",
    "residual_score",
    "residual_severity",
    "residual_comments",
    "comments",
    "acceptance_justification",
    "acceptance_approver_id",
    "acceptance_approver_name",
    "acceptance_review_date",
    "acceptance_review_status",
    "acceptance_review_note",
    "accepted_at",
    "element_id",
    "element_label",
    "element_type",
    "element_kind",
    "diagram",
    "diagram_id",
    "framework",
    "model",
    "model_status",
    "mitigation_count",
    "active_mitigation_count",
    "is_custom_threat",
]
_MITIGATION_FIELDS = [
    "id",
    "ref",
    "name",
    "description",
    "category",
    "status",
    "comments",
    "element_id",
    "element_label",
    "element_type",
    "element_kind",
    "diagram",
    "diagram_id",
    "linked",
    "threat_ref",
    "threat_name",
    "threat_severity",
    "threat_status",
]
_DIAGRAM_FIELDS = [
    "id",
    "name",
    "description",
    "node_count",
    "edge_count",
    "model_count",
    "threat_count",
    "open_threat_count",
    "mitigation_count",
]
_MODEL_FIELDS = [
    "id",
    "name",
    "description",
    "status",
    "framework",
    "diagram",
    "diagram_id",
    "threat_count",
    "open_threat_count",
    "completed_at",
]
_ELEMENT_FIELDS = ["id", "label", "type", "kind", "diagram", "diagram_id", "threat_count", "mitigation_count"]
_PRODUCT_FIELDS = [
    "id",
    "name",
    "description",
    "status",
    "is_public",
    "repository_url",
    "confluence_url",
    "application_url",
    "business_area",
    "owner_name",
    "owner_email",
    "jira_project_key",
    "reviewer",
    "contributors",
    "diagram_count",
    "threat_count",
    "open_threat_count",
    "mitigation_count",
]

FIELDS: dict[str, list[str]] = {
    "diagram_threat": _THREAT_FIELDS,
    "diagram_mitigation": _MITIGATION_FIELDS,
    "diagram": _DIAGRAM_FIELDS,
    "model": _MODEL_FIELDS,
    "element": _ELEMENT_FIELDS,
    "product": _PRODUCT_FIELDS,
}


class CustomRule(BaseModel):
    model_config = ConfigDict(extra="forbid")

    id: str = Field(pattern=r"^[A-Z][A-Z0-9_-]{1,40}$")
    title: str | None = None
    description: str | None = None
    level: Level = Level.warning
    applies_to: AppliesTo
    when: dict[str, Any] = Field(default_factory=dict)
    require: dict[str, Any] = Field(min_length=1)
    message: str

    @field_validator("when", "require")
    @classmethod
    def _check_operators(cls, conditions: dict[str, Any]) -> dict[str, Any]:
        for field, cond in conditions.items():
            if isinstance(cond, dict):
                bad = set(cond) - set(OPERATORS)
                if bad:
                    raise ValueError(
                        f"{field}: unknown operator(s) {', '.join(sorted(bad))}; use {', '.join(OPERATORS)}"
                    )
                if "matches" in cond:
                    try:
                        re.compile(str(cond["matches"]))
                    except re.error as exc:
                        raise ValueError(f"{field}: invalid regular expression: {exc}") from exc
        return conditions

    @model_validator(mode="after")
    def _check_fields(self) -> CustomRule:
        allowed = set(FIELDS[self.applies_to])
        used = set(self.when) | set(self.require) | set(re.findall(r"\{(\w+)\}", self.message))
        unknown = used - allowed
        if unknown:
            raise ValueError(
                f"rule {self.id}: unknown field(s) for {self.applies_to}: {', '.join(sorted(unknown))}. "
                f"Available: {', '.join(FIELDS[self.applies_to])}"
            )
        return self

    def to_rule(self) -> Any:
        from tae.validate.engine import Rule

        return Rule(
            id=self.id,
            title=self.title or self.id,
            family="Custom",
            level=self.level,
            description=self.description or self.message,
            check=self._check,
            builtin=False,
        )

    def _check(self, ctx: Any) -> Iterator[tuple[EntityRef, str]]:
        for entity, fields in ENUMERATORS[self.applies_to](ctx.view):
            if not matches_all(self.when, fields, ctx.as_of):
                continue
            if not matches_all(self.require, fields, ctx.as_of):
                yield entity, render_message(self.message, fields)


# ── evaluation ────────────────────────────────────────────────────────────────────


def render_message(template: str, fields: dict[str, Any]) -> str:
    def sub(m: re.Match[str]) -> str:
        value = fields.get(m.group(1))
        if isinstance(value, datetime):
            return value.date().isoformat()
        return "—" if value is None else str(value)

    return re.sub(r"\{(\w+)\}", sub, template)


def matches_all(conditions: dict[str, Any], fields: dict[str, Any], today: date) -> bool:
    return all(matches(fields.get(name), cond, today) for name, cond in conditions.items())


def matches(value: Any, cond: Any, today: date) -> bool:
    if isinstance(cond, dict):
        return all(_apply(op, value, arg, today) for op, arg in cond.items())
    if isinstance(cond, list):
        return _apply("in", value, cond, today)
    return _apply("eq", value, cond, today)


def _apply(op: str, value: Any, arg: Any, today: date) -> bool:
    if op == "exists":
        return _present(value) == bool(arg)
    if op == "empty":
        return (not _present(value)) == bool(arg)
    if op in ("in", "not_in"):
        items = arg if isinstance(arg, list) else [arg]
        found = any(_eq(value, a, today) for a in items)
        return found if op == "in" else not found
    if op == "eq":
        return _eq(value, arg, today)
    if op == "ne":
        return not _eq(value, arg, today)
    if op == "matches":
        return value is not None and re.search(str(arg), str(value)) is not None
    if op == "contains":
        if value is None:
            return False
        if isinstance(value, list | tuple | set):
            return arg in value
        return str(arg).casefold() in str(value).casefold()
    # Ordering comparisons: false when either side is missing or not comparable.
    left, right = _comparable(value, arg, today)
    if left is None or right is None:
        return False
    try:
        if op == "gt":
            return bool(left > right)
        if op == "gte":
            return bool(left >= right)
        if op == "lt":
            return bool(left < right)
        if op == "lte":
            return bool(left <= right)
    except TypeError:
        return False
    raise ValueError(f"Unknown operator {op}")  # pragma: no cover - guarded by validation


def _present(value: Any) -> bool:
    if value is None:
        return False
    if isinstance(value, str):
        return bool(value.strip())
    return True


def _eq(value: Any, arg: Any, today: date) -> bool:
    left, right = _comparable(value, arg, today)
    if isinstance(left, str) and isinstance(right, str):
        return left.casefold() == right.casefold()
    return bool(left == right)


_RELATIVE = re.compile(r"^today\s*(?:([+-])\s*(\d+))?$")


def _comparable(value: Any, arg: Any, today: date) -> tuple[Any, Any]:
    if isinstance(value, datetime):
        value = value.date()
    if isinstance(value, date):
        if isinstance(arg, datetime):
            return value, arg.date()
        if isinstance(arg, date):
            return value, arg
        if isinstance(arg, str):
            m = _RELATIVE.match(arg.strip().lower())
            if m:
                delta = int(m.group(2) or 0) * (-1 if m.group(1) == "-" else 1)
                return value, today + timedelta(days=delta)
            try:
                return value, date.fromisoformat(arg.strip())
            except ValueError:
                return None, None
        return None, None
    if isinstance(value, bool) or isinstance(arg, bool):
        return value, arg
    if isinstance(value, int | float) and isinstance(arg, str):
        try:
            return value, float(arg)
        except ValueError:
            return None, None
    return value, arg


# ── entity enumerators ───────────────────────────────────────────────────────────


def _threat_fields(t: ThreatItem) -> dict[str, Any]:
    r = t.record
    return {
        "id": r.id,
        "ref": t.ref,
        "name": t.name,
        "description": t.description,
        "category": t.category,
        "status": r.status,
        "likelihood": r.likelihood,
        "impact": r.impact,
        "risk_score": t.risk_score,
        "severity": t.severity,
        "residual_likelihood": r.residual_likelihood,
        "residual_impact": r.residual_impact,
        "residual_score": t.residual_score,
        "residual_severity": t.residual_severity,
        "residual_comments": r.residual_comments,
        "comments": r.comments,
        "acceptance_justification": r.acceptance_justification,
        "acceptance_approver_id": r.acceptance_approver_id,
        "acceptance_approver_name": r.acceptance_approver_name,
        "acceptance_review_date": r.acceptance_review_date,
        "acceptance_review_status": r.acceptance_review_status,
        "acceptance_review_note": r.acceptance_review_note,
        "accepted_at": r.accepted_at,
        "element_id": r.element_id,
        "element_label": t.element_label,
        "element_type": t.element.type if t.element else None,
        "element_kind": t.element.kind if t.element else r.element_type,
        "diagram": t.diagram.name,
        "diagram_id": t.diagram.id,
        "framework": t.framework_name,
        "model": t.model.name if t.model else None,
        "model_status": t.model.status if t.model else None,
        "mitigation_count": len(t.mitigations),
        "active_mitigation_count": len(t.active_mitigations),
        "is_custom_threat": r.threat.is_custom,
    }


def _mitigation_fields(m: MitigationItem) -> dict[str, Any]:
    return {
        "id": m.id,
        "ref": m.ref,
        "name": m.name,
        "description": m.description,
        "category": m.category,
        "status": m.status,
        "comments": m.record.comments,
        "element_id": m.record.element_id,
        "element_label": m.element_label,
        "element_type": m.element.type if m.element else None,
        "element_kind": m.element.kind if m.element else m.record.element_type,
        "diagram": m.diagram.name,
        "diagram_id": m.diagram.id,
        "linked": m.threat is not None,
        "threat_ref": m.threat.ref if m.threat else None,
        "threat_name": m.threat.name if m.threat else None,
        "threat_severity": m.threat.severity if m.threat else None,
        "threat_status": m.threat.status if m.threat else None,
    }


def _diagram_fields(d: DiagramView) -> dict[str, Any]:
    return {
        "id": d.id,
        "name": d.name,
        "description": d.diagram.description,
        "node_count": len(d.nodes),
        "edge_count": len(d.edges),
        "model_count": len(d.models),
        "threat_count": len(d.threats),
        "open_threat_count": sum(t.is_open for t in d.threats),
        "mitigation_count": len(d.mitigations),
    }


def _element_fields(e: Element, d: DiagramView) -> dict[str, Any]:
    return {
        "id": e.id,
        "label": e.label,
        "type": e.type,
        "kind": e.kind,
        "diagram": d.name,
        "diagram_id": d.id,
        "threat_count": len(d.threats_on(e.id)),
        "mitigation_count": sum(1 for m in d.mitigations if m.record.element_id == e.id),
    }


def _enum_threats(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_threat

    for t in view.threats:
        yield ref_threat(t), _threat_fields(t)


def _enum_mitigations(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_mitigation

    for m in view.mitigations:
        yield ref_mitigation(m), _mitigation_fields(m)


def _enum_diagrams(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_diagram

    for d in view.diagrams:
        yield ref_diagram(d), _diagram_fields(d)


def _enum_models(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_model

    for d in view.diagrams:
        for m in d.models:
            threats = [t for t in d.threats if t.record.model_id == m.id]
            fields = {
                "id": m.id,
                "name": m.name,
                "description": m.description,
                "status": m.status,
                "framework": m.framework_name,
                "diagram": d.name,
                "diagram_id": d.id,
                "threat_count": len(threats),
                "open_threat_count": sum(t.is_open for t in threats),
                "completed_at": m.completed_at,
            }
            yield ref_model(m.id, m.name, d), fields


def _enum_elements(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_element

    for d in view.diagrams:
        for e in d.elements.values():
            yield ref_element(e, d), _element_fields(e, d)


def _enum_product(view: ProductView) -> Iterator[tuple[EntityRef, dict[str, Any]]]:
    from tae.validate.engine import ref_product

    p = view.product
    fields = {name: getattr(p, name, None) for name in _PRODUCT_FIELDS if hasattr(p, name)}
    fields.update(
        diagram_count=len(view.diagrams),
        threat_count=len(view.threats),
        open_threat_count=sum(t.is_open for t in view.threats),
        mitigation_count=len(view.mitigations),
    )
    yield ref_product(view), fields


ENUMERATORS: dict[str, Callable[[ProductView], Iterator[tuple[EntityRef, dict[str, Any]]]]] = {
    "diagram_threat": _enum_threats,
    "diagram_mitigation": _enum_mitigations,
    "diagram": _enum_diagrams,
    "model": _enum_models,
    "element": _enum_elements,
    "product": _enum_product,
}
