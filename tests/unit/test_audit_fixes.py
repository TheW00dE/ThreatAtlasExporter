"""Regression tests for the issues found in the code audit (report, validation, config)."""

from __future__ import annotations

import re
import struct
import zlib
from datetime import UTC, date, datetime
from pathlib import Path
from typing import Any

import pytest

from tae.config import ConfigError, load_config_file
from tae.report.definition import ReportDefinition, ReportDefinitionError
from tae.report.diagram_svg import render_svg
from tae.report.render import ReportBlocked, build_report, load_logo, render_user_string
from tae.validate import ValidationConfig, run
from tests.conftest import make_snapshot, make_view, raw_snapshot

AS_OF = date(2026, 11, 25)


def build(
    data: dict[str, Any] | None = None, raw: dict[str, Any] | None = None, base_dir: Path | None = None
):  # type: ignore[no-untyped-def]
    definition = ReportDefinition.from_data(data or {}, base_dir=base_dir)
    return build_report(make_snapshot(raw), definition, as_of=AS_OF)


def badge_count(svg: str) -> int:
    return len(re.findall(r'<circle [^>]*r="9"', svg))


# Finding 4: element_table: false was ignored.
def test_element_table_can_be_switched_off() -> None:
    with_table = build({"sections": [{"type": "diagram"}]})
    without = build({"sections": [{"type": "diagram", "element_table": False}]})
    assert "Elements and threats" in with_table.html
    assert "Elements and threats" not in without.html


# Finding 5: badges counted threats the report had filtered out.
def test_badges_follow_report_filters() -> None:
    diagram = make_view().diagram(31)
    assert diagram is not None
    all_svg = render_svg(diagram)
    critical_only = render_svg(diagram, visible={501})
    assert all_svg is not None and critical_only is not None
    assert badge_count(all_svg) == 2
    assert badge_count(critical_only) == 1

    out = build({"filters": {"min_severity": "high"}, "sections": [{"type": "diagram"}]})
    svg_uri = re.search(r'src="data:image/svg\+xml;base64,([^"]+)" alt="Data flow', out.html)
    assert svg_uri is not None
    import base64

    assert badge_count(base64.b64decode(svg_uri.group(1)).decode()) == 1


# Finding 6: validation ignored the report's scope.
def archived_open_threat() -> dict[str, Any]:
    raw = raw_snapshot()
    raw["diagrams"] = raw["diagrams"][:1]
    raw["diagram_threats"][1]["acceptance_review_status"] = "approved"
    archived = {**raw["models"][0], "id": 42, "name": "Old model", "status": "archived"}
    raw["models"].append(archived)
    raw["diagram_threats"].append(
        {**raw["diagram_threats"][0], "id": 777, "model_id": 42, "status": "identified", "model": archived}
    )
    return raw


def test_validation_follows_scope() -> None:
    raw = archived_open_threat()
    # Validating the whole product finds the open critical threat in the archived model...
    whole = run(make_view(raw), ValidationConfig(), as_of=AS_OF)
    assert any(f.rule_id == "GOV005" for f in whole.findings)
    # ...but a report that leaves archived models out isn't blocked by it.
    out = build({"validation": {"on_failure": "block"}, "sections": [{"type": "threat_table"}]}, raw)
    assert not any(f.rule_id == "GOV005" for f in out.validation.findings)
    # Including archived models in scope brings the finding back.
    with pytest.raises(ReportBlocked):
        build(
            {
                "scope": {"model_status": ["in_progress", "completed", "archived"]},
                "validation": {"on_failure": "block"},
            },
            raw,
        )


def test_scoped_validation_keeps_report_references() -> None:
    raw = archived_open_threat()
    raw["diagram_threats"][0]["status"] = "identified"  # open critical T-ref in scope
    out = build({"sections": [{"type": "threat_table"}]}, raw)
    finding = next(f for f in out.validation.findings if f.rule_id == "GOV005")
    in_report = re.search(
        r'<td class="col-ref ref">(T\d+)</td>\s*<td class="col-threat"><strong>SQL injection', out.html
    )
    assert in_report is not None
    assert finding.entity.ref == in_report.group(1)


# Finding 8: unlabelled data flows could never be detected.
def test_has_label_distinguishes_unlabelled_elements() -> None:
    raw = raw_snapshot()
    del raw["diagrams"][0]["diagram_data"]["edges"][1]["label"]
    d = make_view(raw).diagram(31)
    assert d is not None
    assert d.elements["e-1"].has_label is True
    assert d.elements["e-2"].has_label is False
    assert d.elements["e-2"].label == "e-2"  # still shown by ID
    config = ValidationConfig.from_data(
        {
            "rules": [
                {
                    "id": "FLOWS",
                    "applies_to": "element",
                    "when": {"kind": "edge"},
                    "require": {"has_label": True},
                    "message": "{id} unlabelled",
                }
            ]
        }
    )
    found = [f.message for f in run(make_view(raw), config, as_of=AS_OF).findings if f.rule_id == "FLOWS"]
    assert found == ["e-2 unlabelled"]


def test_example_flow_rule_fires() -> None:
    raw = raw_snapshot()
    del raw["diagrams"][0]["diagram_data"]["edges"][1]["label"]
    examples = Path(__file__).resolve().parents[2] / "examples" / "rules" / "custom-rules.yaml"
    result = run(make_view(raw), ValidationConfig.load(examples), as_of=AS_OF)
    assert [f.entity.id for f in result.findings if f.rule_id == "CUSTOM-FLOWS-NAMED"] == ["e-2"]


# Finding 9: verify_tls = "false" (a string) kept verification on.
@pytest.mark.parametrize(
    ("value", "expected"), [("false", False), ('"false"', False), ('"no"', False), ("true", True)]
)
def test_verify_tls_strings(tmp_path: Path, value: str, expected: bool) -> None:
    path = tmp_path / "c.toml"
    path.write_text(f'[profiles.p]\nurl = "https://a.test"\nverify_tls = {value}\n')
    assert load_config_file(path).profiles["p"].verify_tls is expected


@pytest.mark.parametrize("value", ['"maybe"', "1"])
def test_verify_tls_rejects_nonsense(tmp_path: Path, value: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(f'[profiles.p]\nurl = "https://a.test"\nverify_tls = {value}\n')
    with pytest.raises(ConfigError, match="verify_tls must be true or false"):
        load_config_file(path)


# Finding 10: placeholders printed "None" and raw datetimes.
def test_placeholders_print_cleanly() -> None:
    product = make_snapshot().product.model_copy(update={"owner_name": None})
    assert render_user_string("owner {{ product.owner_name }}", product=product) == "owner "
    assert render_user_string("{{ product.owner_name or 'unassigned' }}", product=product) == "unassigned"
    when = datetime(2026, 11, 26, 10, 41, 7, 123456, tzinfo=UTC)
    assert render_user_string("{{ t }}", t=when) == "2026-11-26 10:41 UTC"
    assert render_user_string("{{ t|date }}", t=when) == "2026-11-26"


def test_audit_example_subtitle_without_owner() -> None:
    examples = Path(__file__).resolve().parents[2] / "examples" / "reports"
    raw = raw_snapshot()
    raw["product"]["owner_name"] = None
    definition = ReportDefinition.load(examples / "audit-acceptance.yaml")
    out = build_report(
        make_snapshot(raw),
        definition.model_copy(
            update={"validation": definition.validation.model_copy(update={"on_failure": "warn"})}
        ),
        as_of=AS_OF,
    )
    assert "owner unassigned" in out.html
    assert "None" not in re.sub(r"<[^>]+>", " ", out.html.split("<body>", 1)[1])
    assert not re.search(r"\d{2}:\d{2}:\d{2}\.\d{6}", out.html)


# L2: custom templates could reach Python internals.
def test_custom_templates_are_sandboxed(tmp_path: Path) -> None:
    (tmp_path / "tpl" / "sections").mkdir(parents=True)
    (tmp_path / "tpl" / "sections" / "text.html.j2").write_text(
        "{{ ''.__class__.__mro__[1].__subclasses__() }}"
    )
    with pytest.raises(ReportDefinitionError, match="sandbox"):
        build({"template": "tpl", "sections": [{"type": "text", "body": "x"}]}, base_dir=tmp_path)


# L3: any file with an image extension could be embedded as the "logo".
def png_bytes() -> bytes:
    def chunk(kind: bytes, data: bytes) -> bytes:
        return struct.pack(">I", len(data)) + kind + data + struct.pack(">I", zlib.crc32(kind + data))

    ihdr = struct.pack(">IIBBBBB", 1, 1, 8, 2, 0, 0, 0)
    return (
        b"\x89PNG\r\n\x1a\n"
        + chunk(b"IHDR", ihdr)
        + chunk(b"IDAT", zlib.compress(b"\x00\x00\x00\x00"))
        + chunk(b"IEND", b"")
    )


def test_logo_must_really_be_an_image(tmp_path: Path) -> None:
    (tmp_path / "logo.png").write_bytes(png_bytes())
    assert load_logo(tmp_path / "logo.png")[1] == "image/png"
    (tmp_path / "logo.svg").write_text('<?xml version="1.0"?><svg xmlns="http://www.w3.org/2000/svg"/>')
    assert load_logo(tmp_path / "logo.svg")[1] == "image/svg+xml"
    (tmp_path / "id_rsa.png").write_text("-----BEGIN OPENSSH PRIVATE KEY-----\n")
    with pytest.raises(ReportDefinitionError, match="must be a PNG"):
        load_logo(tmp_path / "id_rsa.png")
    (tmp_path / "secrets.svg").write_text("password=hunter2")
    with pytest.raises(ReportDefinitionError, match="must be a PNG"):
        load_logo(tmp_path / "secrets.svg")
    (tmp_path / "huge.png").write_bytes(png_bytes() + b"\x00" * (3 * 1024 * 1024))
    with pytest.raises(ReportDefinitionError, match="larger than"):
        load_logo(tmp_path / "huge.png")
