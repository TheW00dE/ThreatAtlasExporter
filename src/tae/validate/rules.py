"""Built-in validation rules.

Families: STR (structure), REF (references), CON (consistency), CMP (completeness),
GOV (governance). The three priority checks are on by default as errors:
CMP001 (every threat scored), GOV001–GOV003 (accepted risks fully documented and
approved, review not overdue) and GOV005 (no open high/critical threats).
"""

from __future__ import annotations

from collections.abc import Iterator

from tae.models.api import (
    ACCEPTANCE_REVIEW_STATUSES,
    DIAGRAM_MITIGATION_STATUSES,
    DIAGRAM_THREAT_STATUSES,
    MODEL_STATUSES,
    NODE_TYPES,
    PRODUCT_STATUSES,
    SEVERITIES,
    severity_for_score,
)
from tae.validate.engine import (
    Hit,
    RuleContext,
    ref_diagram,
    ref_element,
    ref_mitigation,
    ref_model,
    ref_product,
    ref_threat,
    rule,
)
from tae.validate.findings import Level

E, W, I = Level.error, Level.warning, Level.info  # noqa: E741


def _bad(value: object, allowed: tuple[str, ...]) -> bool:
    return value is not None and value not in allowed


# ── STR: structure ────────────────────────────────────────────────────────────────


@rule(
    "STR001", "Unknown status or type value", E, "Status and type fields must use ThreatAtlas's vocabularies."
)
def str001(ctx: RuleContext) -> Iterator[Hit]:
    v = ctx.view
    if _bad(v.product.status, PRODUCT_STATUSES):
        yield (
            ref_product(v),
            f"Product status {v.product.status!r} is not one of {', '.join(PRODUCT_STATUSES)}",
        )
    for d in v.diagrams:
        for m in d.models:
            if _bad(m.status, MODEL_STATUSES):
                yield ref_model(m.id, m.name, d), f"Threat model status {m.status!r} is not recognised"
        for e in d.nodes:
            if e.type not in NODE_TYPES:
                yield ref_element(e, d), f"Node type {e.type!r} is not one of {', '.join(NODE_TYPES)}"
    for t in v.threats:
        r = t.record
        if _bad(r.status, DIAGRAM_THREAT_STATUSES):
            yield (
                ref_threat(t),
                f"Threat status {r.status!r} is not one of {', '.join(DIAGRAM_THREAT_STATUSES)}",
            )
        if _bad(r.acceptance_review_status, ACCEPTANCE_REVIEW_STATUSES):
            yield ref_threat(t), f"Acceptance review status {r.acceptance_review_status!r} is not recognised"
        for fname in ("severity", "residual_severity"):
            value = getattr(r, fname)
            if _bad(value, SEVERITIES):
                yield ref_threat(t), f"{fname} {value!r} is not one of {', '.join(SEVERITIES)}"
    for mi in v.mitigations:
        if _bad(mi.status, DIAGRAM_MITIGATION_STATUSES):
            yield (
                ref_mitigation(mi),
                f"Mitigation status {mi.status!r} is not one of {', '.join(DIAGRAM_MITIGATION_STATUSES)}",
            )


@rule("STR002", "Score out of range", E, "Likelihood and impact scores must be between 1 and 5.")
def str002(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        for fname in ("likelihood", "impact", "residual_likelihood", "residual_impact"):
            value = getattr(t.record, fname)
            if value is not None and not 1 <= value <= 5:
                yield ref_threat(t), f"{fname.replace('_', ' ').capitalize()} is {value}; it must be 1–5"


# ── REF: references ───────────────────────────────────────────────────────────────


@rule(
    "REF001",
    "Threat or mitigation on a missing element",
    E,
    "Every threat and mitigation must be attached to a node or edge that exists in the diagram.",
)
def ref001(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.element is None:
            yield ref_threat(t), f"Element {t.record.element_id!r} does not exist in the diagram"
    for mi in ctx.view.mitigations:
        if mi.element is None:
            yield ref_mitigation(mi), f"Element {mi.record.element_id!r} does not exist in the diagram"


@rule(
    "REF002",
    "Threat model mismatch",
    E,
    "A threat or mitigation must belong to a threat model of the same diagram.",
)
def ref002(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.model is None:
            yield ref_threat(t), f"Threat model {t.record.model_id} is not part of the snapshot"
        elif t.model.diagram_id != t.diagram.id:
            yield ref_threat(t), f"Threat model {t.model.name!r} belongs to another diagram"
    for mi in ctx.view.mitigations:
        model = ctx.view.models.get(mi.record.model_id)
        if model is None:
            yield ref_mitigation(mi), f"Threat model {mi.record.model_id} is not part of the snapshot"
        elif model.diagram_id != mi.diagram.id:
            yield ref_mitigation(mi), f"Threat model {model.name!r} belongs to another diagram"


@rule(
    "REF003",
    "Mitigation linked to a missing threat",
    W,
    "A mitigation linked to a threat must point at a threat identified on the same diagram.",
)
def ref003(ctx: RuleContext) -> Iterator[Hit]:
    for mi in ctx.view.mitigations:
        if mi.record.threat_id is not None and mi.threat is None:
            yield ref_mitigation(mi), f"Linked threat {mi.record.threat_id} is not on this diagram"
        elif mi.threat is not None and mi.threat.record.element_id != mi.record.element_id:
            yield (
                ref_mitigation(mi),
                f"Applied to {mi.element_label!r} but its threat {mi.threat.ref} "
                f"is on {mi.threat.element_label!r}",
            )


@rule(
    "REF004", "Element type mismatch", W, "element_type must match whether the element is a node or an edge."
)
def ref004(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.element is not None and t.record.element_type not in (t.element.kind, t.element.type):
            article = "an" if t.element.kind == "edge" else "a"
            yield (
                ref_threat(t),
                f"Element type recorded as {t.record.element_type!r} but {t.element_label!r} "
                f"is {article} {t.element.kind}",
            )


# ── CON: consistency ─────────────────────────────────────────────────────────────


def _score_issue(
    likelihood: int | None, impact: int | None, score: int | None, severity: str | None
) -> str | None:
    if likelihood is None or impact is None:
        return None
    expected = likelihood * impact
    if score is not None and score != expected:
        return f"score is {score} but {likelihood} × {impact} = {expected}"
    expected_sev = severity_for_score(expected)
    if severity is not None and severity != expected_sev:
        return f"severity is {severity!r} but score {expected} is {expected_sev!r}"
    return None


@rule(
    "CON001",
    "Risk score does not match likelihood × impact",
    E,
    "Stored inherent and residual scores and severities must match ThreatAtlas's formula and bands.",
)
def con001(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        r = t.record
        issue = _score_issue(r.likelihood, r.impact, r.risk_score, r.severity)
        if issue:
            yield ref_threat(t), f"Inherent {issue}"
        issue = _score_issue(
            r.residual_likelihood, r.residual_impact, r.residual_risk_score, r.residual_severity
        )
        if issue:
            yield ref_threat(t), f"Residual {issue}"


@rule(
    "CON002",
    "Mitigated threat without an active mitigation",
    W,
    "A threat marked mitigated should have at least one implemented or verified mitigation.",
)
def con002(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.status == "mitigated" and not t.active_mitigations:
            proposed = len(t.mitigations)
            hint = f" ({proposed} proposed)" if proposed else ""
            yield ref_threat(t), f"Marked mitigated but has no implemented or verified mitigation{hint}"


@rule(
    "CON003",
    "Residual risk higher than inherent risk",
    W,
    "Residual risk after mitigation should not exceed the inherent risk.",
)
def con003(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        inherent, residual = t.risk_score, t.residual_score
        if inherent is not None and residual is not None and residual > inherent:
            yield ref_threat(t), f"Residual score {residual} is higher than inherent score {inherent}"


@rule(
    "CON004",
    "Completed threat model with open threats",
    W,
    "A threat model marked completed should have no threats still in status 'identified'.",
)
def con004(ctx: RuleContext) -> Iterator[Hit]:
    for d in ctx.view.diagrams:
        for m in d.models:
            if m.status != "completed":
                continue
            open_threats = [t for t in d.threats if t.record.model_id == m.id and t.is_open]
            if open_threats:
                refs = ", ".join(t.ref for t in open_threats[:10])
                yield (
                    ref_model(m.id, m.name, d),
                    f"Marked completed but {len(open_threats)} threat(s) are open: {refs}",
                )


# ── CMP: completeness ────────────────────────────────────────────────────────────


@rule(
    "CMP001",
    "Threat not scored",
    E,
    "Every threat needs a likelihood and an impact so its risk can be rated.",
)
def cmp001(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        missing = [n for n in ("likelihood", "impact") if getattr(t.record, n) is None]
        if missing:
            yield ref_threat(t), f"Missing {' and '.join(missing)}"


@rule("CMP002", "Diagram without a threat model", W, "Each diagram should have at least one threat model.")
def cmp002(ctx: RuleContext) -> Iterator[Hit]:
    for d in ctx.view.diagrams:
        if not d.models:
            yield ref_diagram(d), "No threat model (framework) has been applied to this diagram"


@rule("CMP003", "Threat model without threats", W, "A threat model should identify at least one threat.")
def cmp003(ctx: RuleContext) -> Iterator[Hit]:
    for d in ctx.view.diagrams:
        for m in d.models:
            if m.status != "archived" and not any(t.record.model_id == m.id for t in d.threats):
                yield ref_model(m.id, m.name, d), "No threats have been identified in this threat model"


@rule(
    "CMP004",
    "Element without threats",
    I,
    "Processes, data stores, external entities and data flows are expected to have threats considered.",
)
def cmp004(ctx: RuleContext) -> Iterator[Hit]:
    wanted = set(ctx.params.uncovered_element_types)
    for d in ctx.view.diagrams:
        if not d.models:
            continue  # CMP002 already covers this diagram
        covered = {t.record.element_id for t in d.threats}
        for e in d.elements.values():
            if e.type in wanted and e.id not in covered:
                yield ref_element(e, d), f"No threats identified on this {e.type}"


@rule(
    "CMP005", "Product information incomplete", W, "Required product fields must be filled in (configurable)."
)
def cmp005(ctx: RuleContext) -> Iterator[Hit]:
    product = ctx.view.product
    missing = [f for f in ctx.params.required_product_fields if not getattr(product, f, None)]
    if missing:
        yield ref_product(ctx.view), f"Missing: {', '.join(missing)}"


@rule("CMP006", "Diagram has no content", E, "Each diagram must contain at least one element to be reported.")
def cmp006(ctx: RuleContext) -> Iterator[Hit]:
    if not ctx.view.diagrams:
        yield ref_product(ctx.view), "The product has no diagrams"
    for d in ctx.view.diagrams:
        if not d.nodes:
            yield ref_diagram(d), "The diagram has no nodes"


# ── GOV: governance ───────────────────────────────────────────────────────────────


@rule(
    "GOV001",
    "Accepted risk not fully documented",
    E,
    "An accepted threat needs a justification, an approver and a review date.",
)
def gov001(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.status != "accepted":
            continue
        r = t.record
        missing = [
            label
            for label, value in (
                ("justification", (r.acceptance_justification or "").strip()),
                ("approver", r.acceptance_approver_id),
                ("review date", r.acceptance_review_date),
            )
            if not value
        ]
        if missing:
            yield ref_threat(t), f"Accepted without {', '.join(missing)}"


@rule("GOV002", "Accepted risk not approved", E, "An accepted threat must be approved by its approver.")
def gov002(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        if t.status == "accepted" and t.record.acceptance_review_status != "approved":
            who = t.record.acceptance_approver_name
            yield ref_threat(t), "Awaiting approval" + (f" by {who}" if who else "")


@rule("GOV003", "Risk review overdue", E, "The review date of an accepted risk has passed.")
def gov003(ctx: RuleContext) -> Iterator[Hit]:
    for t in ctx.view.threats:
        due = t.record.acceptance_review_date
        if t.status == "accepted" and due is not None and due.date() < ctx.as_of:
            days = (ctx.as_of - due.date()).days
            yield ref_threat(t), f"Review was due on {due.date().isoformat()} ({days} days ago)"


@rule("GOV004", "Risk review due soon", W, "The review date of an accepted risk is coming up (configurable).")
def gov004(ctx: RuleContext) -> Iterator[Hit]:
    window = ctx.params.review_warning_days
    for t in ctx.view.threats:
        due = t.record.acceptance_review_date
        if t.status == "accepted" and due is not None:
            days = (due.date() - ctx.as_of).days
            if 0 <= days <= window:
                yield ref_threat(t), f"Review is due on {due.date().isoformat()} (in {days} days)"


@rule(
    "GOV005",
    "Open high or critical threat",
    E,
    "High and critical threats must be mitigated or formally accepted (severities configurable).",
)
def gov005(ctx: RuleContext) -> Iterator[Hit]:
    severities = set(ctx.params.open_risk_severities)
    for t in ctx.view.threats:
        if t.is_open and t.severity in severities:
            yield (
                ref_threat(t),
                f"{(t.severity or '').capitalize()} threat (score {t.risk_score}) is still open",
            )
