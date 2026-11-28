"""Each built-in rule: the clean fixture passes it, and a targeted change trips it."""

from __future__ import annotations

from collections.abc import Callable
from datetime import date
from typing import Any

import pytest

from tae.validate import Level, ValidationConfig, builtin_rules, run
from tests.conftest import make_view, raw_snapshot

AS_OF = date(2026, 11, 25)
Raw = dict[str, Any]


def clean() -> Raw:
    """Fixture data with the known issues fixed, so it passes every rule."""
    raw = raw_snapshot()
    raw["diagrams"] = raw["diagrams"][:1]  # drop the empty "Admin flow" diagram
    raw["diagram_threats"][1]["acceptance_review_status"] = "approved"
    nodes = raw["diagrams"][0]["diagram_data"]["nodes"]
    edges = raw["diagrams"][0]["diagram_data"]["edges"]
    tpl = raw["diagram_threats"][0]
    extra = []
    for i, (element, kind) in enumerate([(nodes[0], "node"), (nodes[1], "node"), (edges[1], "edge")]):
        extra.append(
            {**tpl, "id": 900 + i, "element_id": element["id"], "element_type": kind, "status": "mitigated",
             "likelihood": 1, "impact": 1, "risk_score": 1, "severity": "low",
             "residual_likelihood": None, "residual_impact": None, "residual_risk_score": None,
             "residual_severity": None}
        )  # fmt: skip
    raw["diagram_threats"].extend(extra)
    for t in extra:
        raw["diagram_mitigations"].append(
            {
                **raw["diagram_mitigations"][0],
                "id": t["id"] + 100,
                "threat_id": t["id"],
                "element_id": t["element_id"],
            }
        )
    return raw


def findings(raw: Raw, rule_id: str, config: ValidationConfig | None = None) -> list[str]:
    result = run(make_view(raw), config, as_of=AS_OF)
    return [f.message for f in result.findings if f.rule_id == rule_id]


def test_clean_fixture_has_no_findings() -> None:
    result = run(make_view(clean()), as_of=AS_OF)
    assert [(f.rule_id, f.message) for f in result.findings] == []


def threat(raw: Raw, i: int = 0) -> dict[str, Any]:
    return raw["diagram_threats"][i]


CASES: list[tuple[str, Callable[[Raw], Any], str]] = [
    ("STR001", lambda r: r["product"].update(status="retired"), "Product status 'retired'"),
    ("STR001", lambda r: threat(r).update(status="fixed"), "Threat status 'fixed'"),
    ("STR001", lambda r: r["diagram_mitigations"][0].update(status="done"), "Mitigation status 'done'"),
    ("STR001", lambda r: r["diagrams"][0]["diagram_data"]["nodes"][0]["data"].update(type="cloud"), "Node type 'cloud'"),
    ("STR002", lambda r: threat(r).update(likelihood=7), "Likelihood is 7"),
    ("REF001", lambda r: threat(r).update(element_id="gone"), "Element 'gone' does not exist"),
    ("REF002", lambda r: threat(r).update(model_id=12345), "Threat model 12345 is not part"),
    ("REF003", lambda r: r["diagram_mitigations"][0].update(threat_id=4242), "Linked threat 4242"),
    ("REF003", lambda r: r["diagram_mitigations"][0].update(element_id="n-api"), "but its threat T"),
    ("REF004", lambda r: threat(r).update(element_type="edge"), "recorded as 'edge'"),
    ("CON001", lambda r: threat(r).update(risk_score=19), "Inherent score is 19 but 4 × 5 = 20"),
    ("CON001", lambda r: threat(r).update(severity="high"), "severity is 'high' but score 20 is 'critical'"),
    ("CON001", lambda r: threat(r).update(residual_risk_score=9), "Residual score is 9"),
    ("CON002", lambda r: r["diagram_mitigations"][0].update(status="proposed"), "(1 proposed)"),
    ("CON003", lambda r: threat(r).update(residual_likelihood=5, residual_impact=5, residual_risk_score=25, residual_severity="critical"), "higher than inherent"),
    ("CON004", lambda r: (r["models"][0].update(status="completed"), threat(r).update(status="identified")), "1 threat(s) are open"),
    ("CMP001", lambda r: threat(r).update(likelihood=None, risk_score=None, severity=None), "Missing likelihood"),
    ("CMP002", lambda r: r.update(models=[], diagram_threats=[], diagram_mitigations=[]), "No threat model"),
    ("CMP003", lambda r: r["models"].append({**r["models"][0], "id": 42, "name": "LINDDUN"}), "No threats have been identified"),
    ("CMP004", lambda r: r.update(diagram_threats=r["diagram_threats"][:2]), "No threats identified on this process"),
    ("CMP005", lambda r: r["product"].update(reviewer=None, owner_email=""), "Missing: owner_email, reviewer"),
    ("CMP006", lambda r: r["diagrams"][0].update(diagram_data=None), "The diagram has no nodes"),
    ("CMP006", lambda r: r.update(diagrams=[]), "no diagrams"),
    ("GOV001", lambda r: threat(r, 1).update(acceptance_justification="  ", acceptance_approver_id=None), "Accepted without justification, approver"),
    ("GOV002", lambda r: threat(r, 1).update(acceptance_review_status=None), "Awaiting approval by Rae Viewer"),
    ("GOV003", lambda r: threat(r, 1).update(acceptance_review_date="2026-10-01T00:00:00"), "Review was due on 2026-10-01 (55 days ago)"),
    ("GOV004", lambda r: threat(r, 1).update(acceptance_review_date="2026-12-10T00:00:00"), "Review is due on 2026-12-10 (in 15 days)"),
    ("GOV005", lambda r: threat(r).update(status="identified"), "Critical threat (score 20) is still open"),
]  # fmt: skip


@pytest.mark.parametrize(
    ("rule_id", "mutate", "expected"), CASES, ids=[f"{c[0]}-{i}" for i, c in enumerate(CASES)]
)
def test_rule_trips(rule_id: str, mutate: Callable[[Raw], Any], expected: str) -> None:
    raw = clean()
    mutate(raw)
    messages = findings(raw, rule_id)
    assert any(expected in m for m in messages), messages


def test_every_builtin_rule_has_a_failing_case() -> None:
    assert {r.id for r in builtin_rules()} == {c[0] for c in CASES}


def test_priority_rules_are_errors() -> None:
    levels = {r.id: r.level for r in builtin_rules()}
    for rule_id in ("CMP001", "GOV001", "GOV002", "GOV003", "GOV005"):
        assert levels[rule_id] is Level.error


def test_params_change_behaviour() -> None:
    raw = clean()
    threat(raw, 1).update(acceptance_review_date="2027-02-01T00:00:00")
    assert findings(raw, "GOV004") == []
    config = ValidationConfig.from_data({"params": {"review_warning_days": 90}})
    assert findings(raw, "GOV004", config)
    raw = clean()
    raw["diagram_threats"][1].update(status="identified")
    assert findings(raw, "GOV005") == []  # medium is not in the default list
    config = ValidationConfig.from_data({"params": {"open_risk_severities": ["medium"]}})
    assert findings(raw, "GOV005", config)


def test_disable_and_level_overrides() -> None:
    raw = clean()
    threat(raw).update(status="identified")
    config = ValidationConfig.from_data({"levels": {"GOV005": "warning"}})
    result = run(make_view(raw), config, as_of=AS_OF)
    assert [f.level for f in result.findings if f.rule_id == "GOV005"] == [Level.warning]
    config = ValidationConfig.from_data({"disable": ["GOV005"]})
    assert findings(raw, "GOV005", config) == []
