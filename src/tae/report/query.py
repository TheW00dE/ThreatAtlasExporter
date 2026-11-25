"""Select, filter, sort and group threats and mitigations for report sections."""

from __future__ import annotations

from collections.abc import Callable, Iterable, Sequence
from dataclasses import dataclass, field
from typing import Any, TypeVar

from tae.report.definition import Filters, Scope
from tae.snapshot.view import SEVERITY_RANK, DiagramView, MitigationItem, ProductView, ThreatItem

T = TypeVar("T")

SEVERITY_ORDER = ["critical", "high", "medium", "low"]
THREAT_STATUS_ORDER = ["identified", "accepted", "mitigated"]
MITIGATION_STATUS_ORDER = ["proposed", "implemented", "verified"]


@dataclass
class Scoped:
    """The parts of a product view that a report covers."""

    view: ProductView
    diagrams: list[DiagramView]
    threats: list[ThreatItem]
    mitigations: list[MitigationItem]


def apply_scope(view: ProductView, scope: Scope) -> Scoped:
    if scope.diagrams == "all":
        diagrams = list(view.diagrams)
    else:
        wanted = {str(x).casefold() for x in scope.diagrams}
        diagrams = [d for d in view.diagrams if str(d.id) in wanted or d.name.casefold() in wanted]
    diagram_ids = {d.id for d in diagrams}
    frameworks = {f.casefold() for f in scope.frameworks}
    statuses = set(scope.model_status)

    def threat_in_scope(t: ThreatItem) -> bool:
        if t.diagram.id not in diagram_ids:
            return False
        if frameworks and (t.framework_name or "").casefold() not in frameworks:
            return False
        return t.model is None or t.model.status in statuses

    threats = [t for t in view.threats if threat_in_scope(t)]
    kept = {t.id for t in threats}

    def mitigation_in_scope(m: MitigationItem) -> bool:
        if m.diagram.id not in diagram_ids:
            return False
        if m.threat is not None:
            return m.threat.id in kept
        model = view.models.get(m.record.model_id)
        if frameworks and model is not None and model.framework_name.casefold() not in frameworks:
            return False
        return model is None or model.status in statuses

    mitigations = [m for m in view.mitigations if mitigation_in_scope(m)]
    return Scoped(view=view, diagrams=diagrams, threats=threats, mitigations=mitigations)


def filter_threats(threats: Iterable[ThreatItem], f: Filters) -> list[ThreatItem]:
    out = []
    minimum = SEVERITY_RANK.get(f.min_severity or "", 0)
    categories = {c.casefold() for c in f.categories} if f.categories else None
    for t in threats:
        if minimum:
            if t.severity is None:
                if not f.include_unscored:
                    continue
            elif t.severity_rank < minimum:
                continue
        if f.statuses is not None and t.status not in f.statuses:
            continue
        if categories is not None and (t.category or "").casefold() not in categories:
            continue
        out.append(t)
    return out


def _ref_number(ref: str) -> int:
    digits = ref[1:]
    return int(digits) if digits.isdigit() else 0


_THREAT_KEYS: dict[str, Callable[[ThreatItem], Any]] = {
    "ref": lambda t: _ref_number(t.ref),
    "name": lambda t: t.name.casefold(),
    "severity": lambda t: t.severity_rank,
    "risk_score": lambda t: t.risk_score if t.risk_score is not None else -1,
    "residual_score": lambda t: t.residual_score if t.residual_score is not None else -1,
    "status": lambda t: THREAT_STATUS_ORDER.index(t.status) if t.status in THREAT_STATUS_ORDER else 99,
    "element": lambda t: t.element_label.casefold(),
    "category": lambda t: (t.category or "").casefold(),
    "diagram": lambda t: t.diagram.name.casefold(),
}


def sort_threats(threats: Sequence[ThreatItem], keys: Sequence[str]) -> list[ThreatItem]:
    """Stable multi-key sort; ``-key`` sorts descending."""
    result = list(threats)
    for key in reversed(keys):
        desc = key.startswith("-")
        result.sort(key=_THREAT_KEYS[key.lstrip("-")], reverse=desc)
    return result


@dataclass
class Group:
    title: str | None
    items: list[Any] = field(default_factory=list)


def group_items(
    items: Sequence[T], key: Callable[[T], str], order: Sequence[str] | None = None
) -> list[Group]:
    groups: dict[str, Group] = {}
    for item in items:
        k = key(item)
        groups.setdefault(k, Group(k)).items.append(item)
    if order:
        rank = {v: i for i, v in enumerate(order)}
        return sorted(groups.values(), key=lambda g: (rank.get(g.title or "", len(rank)), g.title or ""))
    return list(groups.values())


def group_threats(threats: Sequence[ThreatItem], by: str) -> list[Group]:
    if by == "none":
        return [Group(None, list(threats))] if threats else []
    if by == "diagram":
        return group_items(threats, lambda t: t.diagram.name)
    if by == "element":
        return group_items(threats, lambda t: f"{t.element_label} ({t.diagram.name})")
    if by == "severity":
        return group_items(threats, lambda t: t.severity or "unscored", [*SEVERITY_ORDER, "unscored"])
    if by == "category":
        return group_items(threats, lambda t: t.category or "Uncategorised")
    if by == "status":
        return group_items(threats, lambda t: t.status, THREAT_STATUS_ORDER)
    if by == "framework":
        return group_items(threats, lambda t: t.framework_name or "Unknown framework")
    raise ValueError(f"Unknown group_by {by!r}")


def group_mitigations(mitigations: Sequence[MitigationItem], by: str) -> list[Group]:
    if by == "none":
        return [Group(None, list(mitigations))] if mitigations else []
    if by == "diagram":
        return group_items(mitigations, lambda m: m.diagram.name)
    if by == "element":
        return group_items(mitigations, lambda m: f"{m.element_label} ({m.diagram.name})")
    if by == "status":
        return group_items(mitigations, lambda m: m.status, MITIGATION_STATUS_ORDER)
    raise ValueError(f"Unknown group_by {by!r}")
