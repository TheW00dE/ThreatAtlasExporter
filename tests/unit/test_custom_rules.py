from __future__ import annotations

import json
from datetime import date
from pathlib import Path
from xml.etree import ElementTree as ET

import pytest

from tae.validate import FailLevel, ValidationConfig, ValidationConfigError, run
from tae.validate.custom import matches
from tae.validate.output import to_codequality, to_json, to_junit
from tests.conftest import make_view

TODAY = date(2026, 11, 25)


def run_custom(rule: dict[str, object]):  # type: ignore[no-untyped-def]
    config = ValidationConfig.from_data({"rules": [rule]})
    result = run(make_view(), config, as_of=TODAY)
    return [f for f in result.findings if f.rule_id == rule["id"]]


def test_when_and_require() -> None:
    found = run_custom(
        {
            "id": "CUSTOM-001",
            "level": "error",
            "applies_to": "diagram_threat",
            "when": {"severity": ["high", "critical"]},
            "require": {"status": "accepted"},
            "message": "{ref} {name} on {element_label} is {severity} but {status}",
        }
    )
    assert [f.message for f in found] == ["T1 SQL injection on Transactions DB is critical but mitigated"]
    assert found[0].level.value == "error"
    assert found[0].rule_title == "CUSTOM-001"


@pytest.mark.parametrize(
    ("value", "cond", "expected"),
    [
        ("accepted", "ACCEPTED", True),
        ("high", ["low", "high"], True),
        ("high", {"not_in": ["low"]}, True),
        (12, {"gte": 12, "lt": 20}, True),
        (12, {"gt": "12"}, False),
        (None, {"gt": 1}, False),
        (None, {"exists": False}, True),
        ("  ", {"empty": True}, True),
        ("text", {"exists": True}, True),
        ("SQL injection", {"matches": "^SQL"}, True),
        ("SQL injection", {"contains": "inject"}, True),
        ("x", {"ne": "y"}, True),
        (True, True, True),
        (date(2026, 12, 1), {"lt": "today+30"}, True),
        (date(2026, 12, 1), {"lt": "today"}, False),
        (date(2026, 11, 20), {"lt": "today - 1"}, True),
        (date(2026, 12, 1), {"gte": "2026-12-01"}, True),
        (date(2026, 12, 1), {"gte": "not a date"}, False),
    ],
)
def test_condition_operators(value: object, cond: object, expected: bool) -> None:
    assert matches(value, cond, TODAY) is expected


def test_date_fields_in_rules() -> None:
    found = run_custom(
        {
            "id": "REVIEW-SOON",
            "applies_to": "diagram_threat",
            "when": {"status": "accepted"},
            "require": {"acceptance_review_date": {"gte": "today+365"}},
            "message": "Review on {acceptance_review_date} is less than a year away",
        }
    )
    assert [f.message for f in found] == ["Review on 2027-05-01 is less than a year away"]


@pytest.mark.parametrize("applies_to", ["diagram", "model", "element", "product", "diagram_mitigation"])
def test_every_entity_type_can_be_targeted(applies_to: str) -> None:
    found = run_custom(
        {"id": "ALL", "applies_to": applies_to, "require": {"id": {"exists": False}}, "message": "x"}
    )
    assert found  # every entity has an id, so all fail


@pytest.mark.parametrize(
    ("rule", "message"),
    [
        (
            {"id": "X1", "applies_to": "diagram_threat", "require": {"sevrity": "high"}, "message": "m"},
            "unknown field",
        ),
        (
            {"id": "X1", "applies_to": "diagram_threat", "require": {"status": "a"}, "message": "{nope}"},
            "unknown field",
        ),
        (
            {
                "id": "X1",
                "applies_to": "diagram_threat",
                "require": {"status": {"like": "a"}},
                "message": "m",
            },
            "unknown operator",
        ),
        (
            {
                "id": "X1",
                "applies_to": "diagram_threat",
                "require": {"name": {"matches": "("}},
                "message": "m",
            },
            "regular expression",
        ),
        ({"id": "X1", "applies_to": "diagram_threat", "require": {}, "message": "m"}, "at least 1"),
        ({"id": "x1", "applies_to": "diagram_threat", "require": {"status": "a"}, "message": "m"}, "pattern"),
        ({"id": "X1", "applies_to": "widget", "require": {"status": "a"}, "message": "m"}, "applies_to"),
    ],
)
def test_invalid_custom_rules(rule: dict[str, object], message: str) -> None:
    with pytest.raises(ValidationConfigError, match=message):
        ValidationConfig.from_data({"rules": [rule]})


def test_config_errors() -> None:
    rule = {"id": "GOV001", "applies_to": "product", "require": {"name": {"exists": True}}, "message": "m"}
    with pytest.raises(ValidationConfigError, match="clash"):
        run(make_view(), ValidationConfig.from_data({"rules": [rule]}))
    with pytest.raises(ValidationConfigError, match="Duplicate"):
        run(make_view(), ValidationConfig.from_data({"rules": [{**rule, "id": "A1"}, {**rule, "id": "A1"}]}))
    with pytest.raises(ValidationConfigError, match="Unknown rule IDs"):
        run(make_view(), ValidationConfig.from_data({"disable": ["GOV999"]}))
    with pytest.raises(ValidationConfigError, match="extra"):
        ValidationConfig.from_data({"params": {"review_days": 3}})
    with pytest.raises(ValidationConfigError, match="mapping"):
        ValidationConfig.from_data(["not", "a", "mapping"])


def test_load_from_yaml(tmp_path: Path) -> None:
    path = tmp_path / "v.yaml"
    path.write_text("disable: [CMP004]\nlevels:\n  CMP006: warning\nparams:\n  review_warning_days: 7\n")
    config = ValidationConfig.load(path)
    assert config.params.review_warning_days == 7
    path.write_text("disable: [\n")
    with pytest.raises(ValidationConfigError, match="Cannot read"):
        ValidationConfig.load(path)


# ── output formats ─────────────────────────────────────────────────────────────


def result():  # type: ignore[no-untyped-def]
    return run(make_view(), as_of=TODAY)


def test_json_output() -> None:
    data = json.loads(to_json(result(), FailLevel.error))
    assert data["passed"] is False
    assert data["counts"] == {"error": 2, "warning": 1, "info": 3}
    assert {"rule_id", "level", "message", "entity", "fingerprint"} <= set(data["findings"][0])


def test_junit_output() -> None:
    root = ET.fromstring(to_junit(result(), FailLevel.error))  # noqa: S314  (our own output)
    suite = root.find("testsuite")
    assert suite is not None
    assert suite.get("failures") == "2"
    failures = suite.findall("testcase/failure")
    assert {f.get("type") for f in failures} == {"error"}
    # Every rule appears, passing ones included.
    classnames = {c.get("classname", "").split(".")[-1] for c in suite.findall("testcase")}
    assert {"CMP001", "GOV005", "CMP006"} <= classnames
    lenient = ET.fromstring(to_junit(result(), FailLevel.never))  # noqa: S314
    assert lenient.get("failures") == "0"


def test_codequality_output() -> None:
    issues = json.loads(to_codequality(result(), "snapshots/payments.json"))
    assert len(issues) == 6
    assert {i["severity"] for i in issues} == {"major", "minor", "info"}
    assert issues[0]["location"]["path"] == "snapshots/payments.json"
    assert len({i["fingerprint"] for i in issues}) == 6
