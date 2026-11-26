from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
from typer.testing import CliRunner

from tae.cli.app import app
from tae.report.definition import ReportDefinition
from tae.report.render import build_report
from tae.risk import DEFAULT_BANDS, RiskScale, RiskScaleError, RiskScales, load_risk_scale
from tae.validate import ValidationConfig, run
from tests.conftest import make_snapshot, make_view, raw_snapshot

FRAMEWORK_FILE = Path(__file__).resolve().parents[2] / "examples" / "models" / "payments-framework.yaml"
LEVELS = {n: {"label": f"L{n}"} for n in range(1, 6)}


def scale(**kw: object) -> RiskScale:
    return RiskScale.model_validate({"likelihood": LEVELS, "impact": LEVELS, **kw})


def test_default_bands_match_threatatlas() -> None:
    s = scale()
    assert (s.bands.critical, s.bands.high, s.bands.medium) == (20, 12, 6) == (
        DEFAULT_BANDS.critical, DEFAULT_BANDS.high, DEFAULT_BANDS.medium,
    )  # fmt: skip
    assert [s.severity(x) for x in (None, 5, 6, 12, 20)] == [None, "low", "medium", "high", "critical"]


def test_custom_bands() -> None:
    s = scale(bands={"critical": 16, "high": 10, "medium": 5})
    assert [s.severity(x) for x in (4, 5, 10, 15, 16)] == ["low", "medium", "high", "high", "critical"]


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"likelihood": {1: {"label": "a"}}}, "exactly the levels"),
        ({"bands": {"critical": 10, "high": 10, "medium": 5}}, "critical > high > medium"),
        ({"bands": {"critical": 30, "high": 10, "medium": 5}}, "less than or equal to 25"),
    ],
)
def test_invalid_scales(data: dict[str, object], message: str) -> None:
    with pytest.raises(ValueError, match=message):
        scale(**data)


def test_load_from_framework_file_applies_to_that_framework() -> None:
    s = load_risk_scale(FRAMEWORK_FILE)
    assert s.frameworks == ["Card Payments Threat Model"]
    assert s.applies_to("card payments threat model") and not s.applies_to("STRIDE")


def test_standalone_scale_applies_everywhere(tmp_path: Path) -> None:
    path = tmp_path / "scale.yaml"
    path.write_text(
        "kind: risk-scale\nname: Corp\nlikelihood: {1: {label: a}, 2: {label: b}, 3: {label: c}, 4: {label: d}, 5: {label: e}}\n"
        "impact: {1: {label: a}, 2: {label: b}, 3: {label: c}, 4: {label: d}, 5: {label: e}}\nbands: {critical: 15, high: 9, medium: 4}\n"
    )
    s = load_risk_scale(path)
    assert s.frameworks is None and s.applies_to("STRIDE")
    scales = RiskScales([s, load_risk_scale(FRAMEWORK_FILE)])
    assert scales.for_framework("Card Payments Threat Model") is scales.scales[1]  # explicit wins
    assert scales.for_framework("STRIDE") is s


def test_scale_errors(tmp_path: Path) -> None:
    path = tmp_path / "x.yaml"
    path.write_text("kind: framework\nframework: {name: X}\n")
    with pytest.raises(RiskScaleError, match="no risk_scale"):
        load_risk_scale(path)
    path.write_text("kind: product\n")
    with pytest.raises(RiskScaleError, match="expected 'kind"):
        load_risk_scale(path)


def corp_scale(frameworks: list[str] | None = None) -> RiskScales:
    return RiskScales(
        [scale(name="Corp", bands={"critical": 16, "high": 10, "medium": 5}, frameworks=frameworks)]
    )


def test_scale_changes_severity_only_for_its_frameworks() -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][1].update(likelihood=2, impact=5, risk_score=10, severity="medium")
    plain = {t.name: t.severity for t in make_view(raw).threats}
    from tae.snapshot import build_view

    scaled = {t.name: t.severity for t in build_view(make_snapshot(raw), corp_scale(["STRIDE"])).threats}
    other = {t.name: t.severity for t in build_view(make_snapshot(raw), corp_scale(["LINDDUN"])).threats}
    assert plain["Spoofed client"] == "medium" and scaled["Spoofed client"] == "high"
    assert other == plain


def test_validation_uses_the_scale(tmp_path: Path) -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][1].update(
        status="identified", likelihood=2, impact=5, risk_score=10, severity="medium"
    )
    from tae.snapshot import build_view

    plain = run(make_view(raw), ValidationConfig(), as_of=date(2026, 11, 25))
    assert not any(f.rule_id == "GOV005" for f in plain.findings)
    scaled = run(build_view(make_snapshot(raw), corp_scale()), ValidationConfig(), as_of=date(2026, 11, 25))
    assert any(f.rule_id == "GOV005" and "High threat (score 10)" in f.message for f in scaled.findings)
    # CON001 still checks ThreatAtlas's own stored severity against ThreatAtlas's bands.
    assert not any(f.rule_id == "CON001" for f in scaled.findings)


def test_validate_cli_and_config_take_scales(tmp_path: Path) -> None:
    import json

    raw = raw_snapshot()
    raw["diagram_threats"][1].update(
        status="identified", likelihood=2, impact=5, risk_score=10, severity="medium"
    )
    snap = tmp_path / "snap.json"
    make_snapshot(raw).save(snap)
    scale_file = tmp_path / "corp.yaml"
    scale_file.write_text(
        "kind: risk-scale\nlikelihood: {1: {label: a}, 2: {label: b}, 3: {label: c}, 4: {label: d}, 5: {label: e}}\n"
        "impact: {1: {label: a}, 2: {label: b}, 3: {label: c}, 4: {label: d}, 5: {label: e}}\nbands: {critical: 7, high: 5, medium: 3}\n"
    )
    config = tmp_path / "rules.yaml"
    config.write_text("risk_scales: [corp.yaml]\n")
    runner = CliRunner()
    base = ["validate", str(snap), "--format", "json", "--fail-level", "never"]

    def gov005(args: list[str]) -> list[str]:
        result = runner.invoke(app, base + args, env={"COLUMNS": "200"})
        assert result.exit_code == 0, result.output
        return [f["message"] for f in json.loads(result.stdout)["findings"] if f["rule_id"] == "GOV005"]

    assert gov005([]) == []  # medium for ThreatAtlas: not an open high/critical threat
    assert gov005(["--risk-scale", str(scale_file)]) == ["Critical threat (score 10) is still open"]
    assert gov005(["--rules", str(config)]) == [
        "Critical threat (score 10) is still open"
    ]  # relative to the config


def test_report_uses_scale_for_matrix_and_section() -> None:
    d = ReportDefinition.from_data(
        {
            "risk_scales": [str(FRAMEWORK_FILE)],
            "validation": {"on_failure": "ignore"},
            "sections": [{"type": "risk_matrix"}, {"type": "risk_scale"}],
        }
    )
    out = build_report(make_snapshot(), d, as_of=date(2026, 11, 25))
    # The fixture's threats are STRIDE, so they keep ThreatAtlas bands; the section still explains both.
    assert "Payments risk scale" in out.html and "Almost certain" in out.html
    assert "ThreatAtlas default bands" in out.html


def test_report_matrix_labels_with_a_scale_for_every_threat() -> None:
    d = ReportDefinition.from_data(
        {"validation": {"on_failure": "ignore"}, "sections": [{"type": "risk_matrix"}]}
    )
    from tae.report import render

    original = render.load_risk_scales
    try:
        render.load_risk_scales = lambda paths: corp_scale()  # type: ignore[assignment]
        out = build_report(make_snapshot(), d, as_of=date(2026, 11, 25))
    finally:
        render.load_risk_scales = original  # type: ignore[assignment]
    assert 'class="lvl-name">L5</div>' in out.html
    assert "score ≥ 16 critical, ≥ 10 high, ≥ 5 medium" in out.html
