"""A linked, read-only view over a snapshot, shared by validation and reports.

Resolves each diagram threat and mitigation to its diagram, its diagram element
(label and type from ``diagram_data``), its threat model and framework, and links
mitigations to the diagram threats they address. Threats and mitigations get
stable reference numbers (``T1``, ``M1``) used to cross-reference diagrams and
tables in the report.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from tae.models.api import (
    Diagram,
    DiagramMitigationWithDetails,
    DiagramThreatWithDetails,
    Framework,
    ModelWithFramework,
    Product,
    severity_for_score,
)
from tae.risk import RiskScale, RiskScales
from tae.snapshot.model import Snapshot

SEVERITY_RANK = {"critical": 4, "high": 3, "medium": 2, "low": 1}
OPEN_THREAT_STATUSES = frozenset({"identified"})
ACTIVE_MITIGATION_STATUSES = frozenset({"implemented", "verified"})


@dataclass
class Element:
    """A node or edge from a diagram's ReactFlow data."""

    id: str
    kind: str  # "node" or "edge"
    type: str  # process | datastore | external | boundary | flow | <unknown>
    label: str  # falls back to the ID when the element has no label
    raw: dict[str, Any]
    has_label: bool = True
    parent_id: str | None = None
    source: str | None = None
    target: str | None = None

    @property
    def is_boundary(self) -> bool:
        return self.type == "boundary"


@dataclass
class ThreatItem:
    record: DiagramThreatWithDetails
    diagram: DiagramView
    element: Element | None
    model: ModelWithFramework | None
    framework: Framework | None
    ref: str = ""
    mitigations: list[MitigationItem] = field(default_factory=list)
    scale: RiskScale | None = None  # custom risk scale for this threat's framework, if any

    @property
    def id(self) -> int:
        return self.record.id

    @property
    def name(self) -> str:
        return self.record.threat.name

    @property
    def description(self) -> str | None:
        return self.record.threat.description

    @property
    def category(self) -> str | None:
        return self.record.threat.category

    @property
    def status(self) -> str:
        return self.record.status

    @property
    def is_open(self) -> bool:
        return self.record.status in OPEN_THREAT_STATUSES

    @property
    def risk_score(self) -> int | None:
        r = self.record
        if r.risk_score is not None:
            return r.risk_score
        if r.likelihood is not None and r.impact is not None:
            return r.likelihood * r.impact
        return None

    @property
    def severity(self) -> str | None:
        if self.scale is not None:
            return self.scale.severity(self.risk_score)
        return self.record.severity or severity_for_score(self.risk_score)

    @property
    def residual_score(self) -> int | None:
        r = self.record
        if r.residual_risk_score is not None:
            return r.residual_risk_score
        if r.residual_likelihood is not None and r.residual_impact is not None:
            return r.residual_likelihood * r.residual_impact
        return None

    @property
    def residual_severity(self) -> str | None:
        if self.scale is not None:
            return self.scale.severity(self.residual_score)
        return self.record.residual_severity or severity_for_score(self.residual_score)

    @property
    def severity_rank(self) -> int:
        return SEVERITY_RANK.get(self.severity or "", 0)

    @property
    def element_label(self) -> str:
        return self.element.label if self.element else self.record.element_id

    @property
    def framework_name(self) -> str | None:
        if self.model is not None:
            return self.model.framework_name
        return self.framework.name if self.framework else None

    @property
    def active_mitigations(self) -> list[MitigationItem]:
        return [m for m in self.mitigations if m.status in ACTIVE_MITIGATION_STATUSES]


@dataclass
class MitigationItem:
    record: DiagramMitigationWithDetails
    diagram: DiagramView
    element: Element | None
    threat: ThreatItem | None
    ref: str = ""

    @property
    def id(self) -> int:
        return self.record.id

    @property
    def name(self) -> str:
        return self.record.mitigation.name

    @property
    def description(self) -> str | None:
        return self.record.mitigation.description

    @property
    def category(self) -> str | None:
        return self.record.mitigation.category

    @property
    def status(self) -> str:
        return self.record.status

    @property
    def element_label(self) -> str:
        return self.element.label if self.element else self.record.element_id


@dataclass
class DiagramView:
    diagram: Diagram
    elements: dict[str, Element]
    models: list[ModelWithFramework] = field(default_factory=list)
    threats: list[ThreatItem] = field(default_factory=list)
    mitigations: list[MitigationItem] = field(default_factory=list)

    @property
    def id(self) -> int:
        return self.diagram.id

    @property
    def name(self) -> str:
        return self.diagram.name

    @property
    def nodes(self) -> list[Element]:
        return [e for e in self.elements.values() if e.kind == "node"]

    @property
    def edges(self) -> list[Element]:
        return [e for e in self.elements.values() if e.kind == "edge"]

    def threats_on(self, element_id: str) -> list[ThreatItem]:
        return [t for t in self.threats if t.record.element_id == element_id]


@dataclass
class ProductView:
    snapshot: Snapshot
    diagrams: list[DiagramView]
    threats: list[ThreatItem]
    mitigations: list[MitigationItem]
    frameworks: dict[int, Framework]
    models: dict[int, ModelWithFramework]
    scales: RiskScales = field(default_factory=RiskScales)

    @property
    def product(self) -> Product:
        return self.snapshot.product

    def diagram(self, diagram_id: int) -> DiagramView | None:
        return next((d for d in self.diagrams if d.id == diagram_id), None)


# ── building ──────────────────────────────────────────────────────────────────────


def extract_elements(diagram: Diagram) -> dict[str, Element]:
    """Read nodes and edges from ``diagram_data``, tolerating partial data."""
    elements: dict[str, Element] = {}
    for node in diagram.nodes:
        if not isinstance(node, dict) or node.get("id") is None:
            continue
        data: dict[str, Any] = node["data"] if isinstance(node.get("data"), dict) else {}
        node_id = str(node["id"])
        node_type = str(data.get("type") or node.get("type") or "unknown")
        elements[node_id] = Element(
            id=node_id,
            kind="node",
            type=node_type,
            label=str(data.get("label") or node_id),
            has_label=bool(str(data.get("label") or "").strip()),
            raw=node,
            parent_id=_opt_str(node.get("parentId") or node.get("parentNode")),
        )
    for edge in diagram.edges:
        if not isinstance(edge, dict) or edge.get("id") is None:
            continue
        data = edge["data"] if isinstance(edge.get("data"), dict) else {}
        edge_id = str(edge["id"])
        label = edge.get("label") or data.get("label")
        elements[edge_id] = Element(
            id=edge_id,
            kind="edge",
            type="flow",
            label=str(label) if label else edge_id,
            has_label=bool(str(label or "").strip()),
            raw=edge,
            source=_opt_str(edge.get("source")),
            target=_opt_str(edge.get("target")),
        )
    return elements


def _opt_str(value: Any) -> str | None:
    return None if value is None else str(value)


def _threat_sort_key(t: ThreatItem) -> tuple[int, int, str, int]:
    return (-t.severity_rank, -(t.risk_score or 0), t.name.lower(), t.id)


def build_view(snapshot: Snapshot, scales: RiskScales | None = None) -> ProductView:
    """Link the snapshot's records. ``scales`` sets custom severity bands per framework."""
    frameworks = {f.id: f for f in snapshot.frameworks}
    models = {m.id: m for m in snapshot.models}

    diagram_views: list[DiagramView] = []
    by_id: dict[int, DiagramView] = {}
    for diagram in sorted(snapshot.diagrams, key=lambda d: (d.name.lower(), d.id)):
        view = DiagramView(
            diagram=diagram,
            elements=extract_elements(diagram),
            models=[m for m in snapshot.models if m.diagram_id == diagram.id],
        )
        diagram_views.append(view)
        by_id[diagram.id] = view

    threats: list[ThreatItem] = []
    threat_by_id: dict[int, ThreatItem] = {}
    for record in snapshot.diagram_threats:
        dview = by_id.get(record.diagram_id)
        if dview is None:
            continue  # belongs to a diagram outside the snapshot
        model = models.get(record.model_id)
        item = ThreatItem(
            record=record,
            diagram=dview,
            element=dview.elements.get(record.element_id),
            model=model,
            framework=frameworks.get(model.framework_id if model else record.threat.framework_id),
        )
        if scales:
            item.scale = scales.for_framework(item.framework_name)
        dview.threats.append(item)
        threats.append(item)
        threat_by_id[record.id] = item

    mitigations: list[MitigationItem] = []
    for mrecord in snapshot.diagram_mitigations:
        dview = by_id.get(mrecord.diagram_id)
        if dview is None:
            continue
        linked = threat_by_id.get(mrecord.threat_id) if mrecord.threat_id is not None else None
        mitem = MitigationItem(
            record=mrecord,
            diagram=dview,
            element=dview.elements.get(mrecord.element_id),
            threat=linked,
        )
        if linked is not None:
            linked.mitigations.append(mitem)
        dview.mitigations.append(mitem)
        mitigations.append(mitem)

    # Stable numbering: diagram order, then most severe first.
    n = 0
    for dview in diagram_views:
        dview.threats.sort(key=_threat_sort_key)
        for t in dview.threats:
            n += 1
            t.ref = f"T{n}"
    m = 0
    for dview in diagram_views:
        dview.mitigations.sort(key=lambda x: (x.name.lower(), x.id))
        for mi in dview.mitigations:
            m += 1
            mi.ref = f"M{m}"

    ordered_threats = [t for d in diagram_views for t in d.threats]
    ordered_mitigations = [mi for d in diagram_views for mi in d.mitigations]
    return ProductView(
        snapshot=snapshot,
        diagrams=diagram_views,
        threats=ordered_threats,
        mitigations=ordered_mitigations,
        frameworks=frameworks,
        models=models,
        scales=scales or RiskScales(),
    )
