"""The shipped examples must stay valid."""

from __future__ import annotations

from pathlib import Path

import pytest
import yaml

from tae.report.definition import ReportDefinition
from tae.report.render import build_report
from tae.validate import ValidationConfig, run
from tests.conftest import make_snapshot, make_view

EXAMPLES = Path(__file__).resolve().parents[2] / "examples"


@pytest.mark.parametrize("path", sorted((EXAMPLES / "reports").glob("*.yaml")), ids=lambda p: p.name)
def test_report_examples_build(path: Path) -> None:
    definition = ReportDefinition.load(path)
    try:
        out = build_report(make_snapshot(), definition)
    except Exception as exc:  # block mode is allowed to refuse the fixture data
        assert definition.validation.on_failure.value == "block", exc
        return
    assert "<html" in out.html


def test_rules_example_loads_and_runs() -> None:
    config = ValidationConfig.load(EXAMPLES / "rules" / "custom-rules.yaml")
    result = run(make_view(), config)
    assert any(f.rule_id.startswith("CUSTOM-") for f in result.findings)


def test_package_example_matches_repository_copy() -> None:
    from tae.cli.report_cmd import EXAMPLE

    assert Path(str(EXAMPLE)).read_text() == (EXAMPLES / "reports" / "full-technical.yaml").read_text()


def test_gitlab_template_is_valid_yaml() -> None:
    data = yaml.safe_load((EXAMPLES / "gitlab" / "threat-model.gitlab-ci.yml").read_text())
    assert {"threat-model:validate", "threat-model:report"} <= set(data)


def test_gitlab_template_only_builds_pdfs_manually() -> None:
    """PDFs are produced on manual runs only: every rule of a job that runs
    `tae report build` must be manual or never."""
    data = yaml.safe_load((EXAMPLES / "gitlab" / "threat-model.gitlab-ci.yml").read_text())
    report_jobs = [
        (name, job)
        for name, job in data.items()
        if isinstance(job, dict) and any("report build" in str(line) for line in job.get("script", []))
    ]
    assert report_jobs
    for name, job in report_jobs:
        whens = [rule.get("when") for rule in job["rules"]]
        assert set(whens) <= {"manual", "never"}, name
        manual = [rule for rule in job["rules"] if rule.get("when") == "manual"]
        assert all(rule.get("allow_failure") is True for rule in manual), name
