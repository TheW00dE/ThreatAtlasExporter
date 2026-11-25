"""CLI tests for pull → validate → report."""

from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx
from typer.testing import CliRunner

from tae.cli.app import app
from tests.conftest import BASE, load
from tests.unit.test_snapshot import mock_product_endpoints

ENV = {"TAE_URL": BASE, "TAE_TOKEN": "ta_x", "COLUMNS": "200"}


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def invoke(runner: CliRunner, *args: str):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), env=ENV)


def test_pull_writes_snapshot(runner: CliRunner, api: respx.MockRouter, tmp_path: Path) -> None:
    api.get("/products").respond(json=load("products"))
    mock_product_endpoints(api)
    out = tmp_path / "snap.json"
    result = invoke(runner, "pull", "--product", "Payments API", "-f", str(out))
    assert result.exit_code == 0, result.output
    data = json.loads(out.read_text())
    assert data["product"]["id"] == 12
    assert len(data["diagram_threats"]) == 2
    assert "2 threat(s)" in result.output


def test_pull_unknown_product(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products").respond(json=load("products"))
    result = invoke(runner, "pull", "--product", "Nope")
    assert result.exit_code == 5
    assert "No product named 'Nope'" in result.output


def test_validate_table_and_exit_code(runner: CliRunner, snapshot_file: Path) -> None:
    result = invoke(runner, "validate", str(snapshot_file), "--as-of", "2026-11-25")
    assert result.exit_code == 10
    assert "GOV002" in result.output
    assert "Validation FAILED" in result.output
    result = invoke(runner, "validate", str(snapshot_file), "--fail-level", "never")
    assert result.exit_code == 0


def test_validate_formats(runner: CliRunner, snapshot_file: Path, tmp_path: Path) -> None:
    result = invoke(runner, "validate", str(snapshot_file), "--format", "json", "--fail-level", "never")
    assert json.loads(result.stdout)["counts"]["error"] == 2
    junit = tmp_path / "report.xml"
    result = invoke(runner, "validate", str(snapshot_file), "--format", "junit", "-f", str(junit))
    assert result.exit_code == 10
    assert junit.read_text().startswith("<?xml")
    cq = tmp_path / "cq.json"
    invoke(
        runner,
        "validate",
        str(snapshot_file),
        "--format",
        "codequality",
        "-f",
        str(cq),
        "--location",
        "x.json",
    )
    assert json.loads(cq.read_text())[0]["location"]["path"] == "x.json"


def test_validate_with_rules_file(runner: CliRunner, snapshot_file: Path, tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text("disable: [CMP006, GOV002]\n")
    assert invoke(runner, "validate", str(snapshot_file), "-r", str(rules)).exit_code == 0
    rules.write_text("disable: [NOPE1]\n")
    result = invoke(runner, "validate", str(snapshot_file), "-r", str(rules))
    assert result.exit_code == 3
    assert "Unknown rule IDs" in result.output


def test_validate_input_errors(runner: CliRunner, snapshot_file: Path, tmp_path: Path) -> None:
    assert invoke(runner, "validate").exit_code == 2
    assert invoke(runner, "validate", str(snapshot_file), "--product", "12").exit_code == 2
    assert invoke(runner, "validate", str(tmp_path / "missing.json")).exit_code == 3
    assert invoke(runner, "validate", str(snapshot_file), "--as-of", "yesterday").exit_code == 2


def test_validate_live_product(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products/12").respond(json=load("products")[0])
    mock_product_endpoints(api)
    result = invoke(runner, "validate", "--product", "12", "--fail-level", "never")
    assert result.exit_code == 0, result.output
    assert "GOV002" in result.output


def test_rules_list(runner: CliRunner, tmp_path: Path) -> None:
    rules = tmp_path / "rules.yaml"
    rules.write_text(
        "disable: [CMP004]\nrules:\n  - id: OWN-1\n    applies_to: product\n"
        "    require: {owner_name: {exists: true}}\n    message: needs an owner\n"
    )
    result = invoke(runner, "rules", "-r", str(rules))
    assert result.exit_code == 0, result.output
    assert "GOV005" in result.output and "OWN-1" in result.output and "disabled" in result.output
    data = json.loads(invoke(runner, "-o", "json", "rules").stdout)
    assert len(data) == 21


def test_report_build(runner: CliRunner, snapshot_file: Path, tmp_path: Path) -> None:
    pdf, html, findings = tmp_path / "r.pdf", tmp_path / "r.html", tmp_path / "f.json"
    result = invoke(
        runner, "report", "build", str(snapshot_file), "-f", str(pdf), "--html", str(html),
        "--findings-file", str(findings), "--as-of", "2026-11-25",
    )  # fmt: skip
    assert result.exit_code == 10, result.output  # annotate mode: PDF written, run marked failed
    assert pdf.read_bytes().startswith(b"%PDF")
    assert "Executive summary" in html.read_text()
    assert json.loads(findings.read_text())["passed"] is False


def test_report_build_block_and_warn(runner: CliRunner, snapshot_file: Path, tmp_path: Path) -> None:
    pdf = tmp_path / "blocked.pdf"
    result = invoke(runner, "report", "build", str(snapshot_file), "-f", str(pdf), "--on-failure", "block")
    assert result.exit_code == 10
    assert not pdf.exists()
    assert "no report was written" in result.output
    result = invoke(runner, "report", "build", str(snapshot_file), "-f", str(pdf), "--on-failure", "warn")
    assert result.exit_code == 0, result.output
    assert pdf.exists()


def test_report_init_check_schema(runner: CliRunner, tmp_path: Path) -> None:
    path = tmp_path / "report.yaml"
    assert invoke(runner, "report", "init", str(path)).exit_code == 0
    assert invoke(runner, "report", "init", str(path)).exit_code == 2  # no overwrite
    result = invoke(runner, "report", "check", str(path))
    assert result.exit_code == 0 and "is valid" in result.output
    path.write_text("sections: [{type: nope}]\n")
    assert invoke(runner, "report", "check", str(path)).exit_code == 3
    schema = json.loads(invoke(runner, "report", "schema").stdout)
    assert schema["title"] == "ThreatAtlasExporter report definition"
