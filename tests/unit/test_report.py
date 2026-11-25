from __future__ import annotations

import re
from datetime import date
from pathlib import Path

import pytest
from pypdf import PdfReader

from tae.report.definition import (
    Filters,
    OnFailure,
    ReportDefinition,
    ReportDefinitionError,
    Scope,
    json_schema,
)
from tae.report.diagram_svg import layout, legend_svg, render_svg
from tae.report.query import apply_scope, filter_threats, group_threats, sort_threats
from tae.report.render import (
    ReportBlocked,
    build_report,
    css_string,
    make_url_fetcher,
    render_user_string,
)
from tests.conftest import make_snapshot, make_view, raw_snapshot

AS_OF = date(2026, 11, 25)


# ── definition ─────────────────────────────────────────────────────────────────


def test_defaults_are_complete() -> None:
    d = ReportDefinition()
    assert [s.type for s in d.sections][:3] == ["cover", "toc", "executive_summary"]
    assert d.validation.on_failure is OnFailure.annotate


def test_load_with_top_level_report_key(tmp_path: Path) -> None:
    path = tmp_path / "r.yaml"
    path.write_text("report:\n  title: X\n  sections:\n    - type: threat_table\n      group_by: severity\n")
    d = ReportDefinition.load(path)
    assert d.title == "X"
    assert d.base_dir == tmp_path.resolve()
    assert d.sections[0].type == "threat_table"


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"branding": {"primary_color": "navy"}}, "hex colour"),
        ({"sections": [{"type": "threat_table", "sort": ["-likelihood"]}]}, "unknown sort key"),
        ({"sections": [{"type": "threat_table", "columns": ["ref", "owner"]}]}, "columns"),
        ({"sections": [{"type": "cover"}, {"type": "cover"}]}, "only one cover"),
        ({"sections": [{"type": "pie_chart"}]}, "pie_chart"),
        ({"sections": []}, "at least 1"),
        ({"scope": {"model_status": ["done"]}}, "unknown model status"),
        ({"filters": {"min_severity": "severe"}}, "min_severity"),
        ({"titel": "typo"}, "titel"),
        ("just a string", "mapping"),
    ],
)
def test_definition_errors(data: object, message: str) -> None:
    with pytest.raises(ReportDefinitionError, match=message):
        ReportDefinition.from_data(data)


def test_example_definition_is_valid() -> None:
    from tae.cli.report_cmd import EXAMPLE

    path = Path(str(EXAMPLE))
    d = ReportDefinition.load(path)
    assert len(d.sections) >= 10


def test_json_schema_lists_section_types() -> None:
    text = str(json_schema())
    for t in ("executive_summary", "risk_matrix", "accepted_risks"):
        assert t in text


# ── query ────────────────────────────────────────────────────────────────────


def test_scope_by_diagram_and_framework() -> None:
    view = make_view()
    assert len(apply_scope(view, Scope(diagrams=["payment flow"])).diagrams) == 1
    assert len(apply_scope(view, Scope(diagrams=[32])).threats) == 0
    assert len(apply_scope(view, Scope(frameworks=["LINDDUN"])).threats) == 0
    assert len(apply_scope(view, Scope(frameworks=["stride"])).threats) == 2
    assert len(apply_scope(view, Scope(model_status=["completed"])).threats) == 0


def test_filters() -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][1].update(likelihood=None, risk_score=None, severity=None)
    threats = make_view(raw).threats
    assert [t.name for t in filter_threats(threats, Filters(min_severity="high"))] == [
        "SQL injection",
        "Spoofed client",
    ]
    assert [
        t.name for t in filter_threats(threats, Filters(min_severity="high", include_unscored=False))
    ] == ["SQL injection"]
    assert [t.name for t in filter_threats(threats, Filters(statuses=["accepted"]))] == ["Spoofed client"]
    assert [t.name for t in filter_threats(threats, Filters(categories=["tampering"]))] == ["SQL injection"]


def test_sort_and_group() -> None:
    threats = make_view().threats
    assert [t.ref for t in sort_threats(threats, ["name"])] == ["T2", "T1"]  # Spoofed < SQL
    assert [t.ref for t in sort_threats(threats, ["-name"])] == ["T1", "T2"]
    assert [t.ref for t in sort_threats(threats, ["severity"])] == ["T2", "T1"]
    groups = group_threats(threats, "severity")
    assert [g.title for g in groups] == ["critical", "medium"]
    assert [g.title for g in group_threats(threats, "status")] == ["accepted", "mitigated"]
    assert group_threats([], "none") == []


# ── diagram SVG ──────────────────────────────────────────────────────────────


def test_svg_has_shapes_labels_and_badges() -> None:
    diagram = make_view().diagram(31)
    assert diagram is not None
    svg = render_svg(diagram)
    assert svg is not None
    assert svg.count("<circle") >= 1 + 2  # process + two badges
    assert "Transactions DB" in svg
    assert "HTTPS card data" in svg
    assert 'stroke-dasharray="7 4"' in svg  # trust boundary
    plain = render_svg(diagram, annotate_threats=False)
    assert plain is not None and plain.count("#b91c1c") == 0  # no critical badge


def test_svg_escapes_labels() -> None:
    raw = raw_snapshot()
    raw["diagrams"][0]["diagram_data"]["nodes"][0]["data"]["label"] = '<script>alert("x")</script>'
    svg = render_svg(make_view(raw).diagram(31))  # type: ignore[arg-type]
    assert svg is not None
    assert "<script>" not in svg
    assert "&lt;script&gt;" in svg


def test_layout_resolves_parents_and_grows_boundaries() -> None:
    raw = raw_snapshot()
    raw["diagrams"][0]["diagram_data"] = {
        "nodes": [
            {"id": "b", "position": {"x": 100, "y": 100}, "style": {"width": "50px", "height": 50},
             "data": {"type": "boundary", "label": "Zone"}},
            {"id": "p", "parentId": "b", "position": {"x": 20, "y": 30}, "data": {"type": "process", "label": "P"}},
            {"id": "loop", "parentId": "loop", "position": {"x": 5, "y": 5}, "data": {"type": "external", "label": "L"}},
        ],
        "edges": [],
    }  # fmt: skip
    boxes = layout(make_view(raw).diagram(31))  # type: ignore[arg-type]
    assert (boxes["p"].x, boxes["p"].y) == (120, 130)
    assert boxes["b"].w >= 20 + 96 and boxes["b"].h >= 30 + 96  # grown to fit the child
    assert (boxes["loop"].x, boxes["loop"].y) == (5, 5)  # self-parent cycle is ignored


def test_empty_diagram_renders_nothing() -> None:
    assert render_svg(make_view().diagram(32)) is None  # type: ignore[arg-type]
    assert legend_svg().startswith("<svg")


# ── rendering ────────────────────────────────────────────────────────────────


def build(data: dict[str, object] | None = None, raw: dict[str, object] | None = None, **kw: object):  # type: ignore[no-untyped-def]
    return build_report(make_snapshot(raw), ReportDefinition.from_data(data or {}), as_of=AS_OF, **kw)  # type: ignore[arg-type]


def test_html_contains_every_default_section() -> None:
    out = build()
    for heading in ("Contents", "Executive summary", "Risk matrix", "Data flow diagrams", "Threats",
                    "Mitigations", "Accepted risks", "Validation findings", "Appendix"):  # fmt: skip
        assert heading in out.html
    assert "T1" in out.html and "M1" in out.html
    assert "data:image/svg+xml;base64," in out.html


def test_annotate_mode_adds_banner_and_fails() -> None:
    out = build()
    assert out.validation_failed and out.exit_with_failure
    assert "validation-banner" in out.html
    assert 'content: "VALIDATION FAILED"' in out.html


def test_warn_mode_keeps_findings_without_banner() -> None:
    out = build({"validation": {"on_failure": "warn"}, "sections": [{"type": "threat_table"}]})
    assert not out.exit_with_failure
    assert "validation-banner" not in out.html
    assert "Validation findings" in out.html  # appended because validation failed


def test_ignore_mode_drops_findings() -> None:
    out = build({"validation": {"on_failure": "ignore"}})
    assert not out.exit_with_failure
    assert "Validation findings" not in out.html


def test_block_mode_raises() -> None:
    with pytest.raises(ReportBlocked) as info:
        build({"validation": {"on_failure": "block"}})
    assert info.value.result.counts()["error"] == 2


def test_cli_override_and_lenient_fail_level() -> None:
    assert not build(on_failure=OnFailure.ignore).exit_with_failure
    out = build({"validation": {"fail_level": "never"}})
    assert not out.validation_failed


def test_rules_file_from_definition(tmp_path: Path) -> None:
    (tmp_path / "v.yaml").write_text("disable: [CMP006, GOV002]\n")
    d = ReportDefinition.from_data({"validation": {"rules": "v.yaml"}}, base_dir=tmp_path)
    out = build_report(make_snapshot(), d, as_of=AS_OF)
    assert not out.validation_failed


def test_server_text_is_escaped() -> None:
    raw = raw_snapshot()
    raw["product"]["name"] = "<img src=x onerror=alert(1)>"
    raw["diagram_threats"][0]["threat"]["name"] = "<b>bold</b>"
    out = build(raw=raw)
    assert "<img src=x" not in out.html
    assert "&lt;b&gt;bold&lt;/b&gt;" in out.html


def test_classification_cannot_break_out_of_css() -> None:
    out = build({"branding": {"classification": 'SECRET"; } </style><script>x</script>'}})
    assert "</style><script>" not in out.html
    assert css_string('a"b\\c<d') == '"a\\"b\\\\c\\3C d"'


def test_user_strings_are_sandboxed() -> None:
    assert render_user_string("{{ product.name }}!", product=make_snapshot().product) == "Payments API!"
    with pytest.raises(ReportDefinitionError):
        render_user_string("{{ product.__class__.__mro__ }}", product=make_snapshot().product)
    with pytest.raises(ReportDefinitionError):
        render_user_string("{{ nope.x }}")


def test_title_and_text_placeholders() -> None:
    out = build(
        {
            "title": "TM for {{ product.name }}",
            "sections": [{"type": "text", "title": "Intro", "body": "A\n\nOwner: {{ product.owner_name }}"}],
        }
    )
    assert "TM for Payments API" in out.html
    assert "<p>Owner: Pat Owner</p>" in out.html


def test_logo_is_embedded(tmp_path: Path) -> None:
    (tmp_path / "logo.svg").write_text('<svg xmlns="http://www.w3.org/2000/svg" width="10" height="10"/>')
    d = ReportDefinition.from_data({"branding": {"logo": "logo.svg"}}, base_dir=tmp_path)
    out = build_report(make_snapshot(), d, as_of=AS_OF)
    assert re.search(r'class="cover-logo" src="data:image/svg\+xml;base64,', out.html)
    d = ReportDefinition.from_data({"branding": {"logo": "missing.png"}}, base_dir=tmp_path)
    with pytest.raises(ReportDefinitionError, match="Logo not found"):
        build_report(make_snapshot(), d, as_of=AS_OF)


def test_custom_template_directory_overrides(tmp_path: Path) -> None:
    (tmp_path / "tpl" / "sections").mkdir(parents=True)
    (tmp_path / "tpl" / "sections" / "accepted_risks.html.j2").write_text("<p>CUSTOM ACCEPTED</p>")
    d = ReportDefinition.from_data({"template": "tpl"}, base_dir=tmp_path)
    out = build_report(make_snapshot(), d, as_of=AS_OF)
    assert "CUSTOM ACCEPTED" in out.html
    assert "Executive summary" in out.html  # other sections still come from the built-in templates
    with pytest.raises(ReportDefinitionError, match="Template directory not found"):
        build_report(make_snapshot(), ReportDefinition.from_data({"template": "nope"}, base_dir=tmp_path))


def test_url_fetcher_blocks_remote_and_stray_files(tmp_path: Path) -> None:
    allowed = tmp_path / "templates"
    allowed.mkdir()
    (allowed / "ok.css").write_text("p{}")
    fetch = make_url_fetcher([allowed])
    assert fetch.fetch((allowed / "ok.css").as_uri()).read() == b"p{}"
    assert fetch.fetch("data:text/plain;base64,aGk=").read() == b"hi"
    for url in ("https://example.com/x.png", (tmp_path / "secret.txt").as_uri(), "ftp://example.com/x"):
        with pytest.raises(ValueError, match="Blocked"):
            fetch.fetch(url)


def test_pdf_is_written(tmp_path: Path) -> None:
    out = build({"branding": {"classification": "CONFIDENTIAL", "organisation": "Example Corp"}})
    path = tmp_path / "report.pdf"
    out.write_pdf(path)
    reader = PdfReader(path)
    assert len(reader.pages) >= 8
    text = "\n".join(page.extract_text() for page in reader.pages)
    for expected in (
        "Threat Model Report",
        "Executive summary",
        "SQL injection",
        "CONFIDENTIAL",
        "Page 2 of",
    ):
        assert expected in text
    # The PDF has an outline (bookmarks) built from the section headings.
    assert any(
        "Executive summary" in str(item.title) for item in reader.outline if not isinstance(item, list)
    )


def test_missing_pdf_libraries_are_explained(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    import builtins

    from tae.errors import EnvironmentProblem

    real_import = builtins.__import__

    def fake_import(name: str, *args: object, **kwargs: object) -> object:
        if name == "weasyprint":
            raise OSError("cannot load library 'libgobject-2.0-0'\nmore detail")
        return real_import(name, *args, **kwargs)  # type: ignore[arg-type]

    monkeypatch.setattr(builtins, "__import__", fake_import)
    with pytest.raises(EnvironmentProblem, match=r"libgobject-2\.0-0'\)\. Use the Docker image"):
        build().write_pdf(tmp_path / "x.pdf")
