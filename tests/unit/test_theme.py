"""Report themes: loading, validation, CSS safety and their effect on the report."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import pytest
import yaml
from typer.testing import CliRunner

from tae.cli.app import app
from tae.report.definition import ReportDefinition, ReportDefinitionError
from tae.report.render import build_report, effective_branding, load_theme
from tae.report.theme import DEFAULT_LABELS, Theme, ThemeError, css_content, font_faces, theme_css
from tests.conftest import make_snapshot

AS_OF = date(2026, 11, 28)
EXAMPLES = Path(__file__).resolve().parents[2] / "examples"
PNG = b"\x89PNG\r\n\x1a\n" + b"\x00" * 32
TTF = b"\x00\x01\x00\x00" + b"\x00" * 64


def build(data: dict[str, object], base: Path | None = None, **kw: object) -> str:
    d = ReportDefinition.from_data(data)
    if base is not None:
        d._base_dir = base  # type: ignore[attr-defined]
    return build_report(make_snapshot(), d, as_of=AS_OF, **kw).html  # type: ignore[arg-type]


# ── model ──────────────────────────────────────────────────────────────────────


def test_example_theme_loads_and_matches_package_copy() -> None:
    from tae.cli.report_cmd import EXAMPLE_THEME

    theme = Theme.load(EXAMPLES / "themes" / "example-corp.yaml")
    assert theme.name == "Example Corp"
    assert Path(str(EXAMPLE_THEME)).read_text() == (EXAMPLES / "themes" / "example-corp.yaml").read_text()


@pytest.mark.parametrize(
    ("data", "message"),
    [
        ({"colors": {"primary": "red; } body { display: none"}}, "primary"),
        ({"colors": {"primary": "url(http://evil.test/x)"}}, "primary"),
        ({"page": {"margins": {"top": "20mm; } @import url(x)"}}}, "top"),
        ({"page": {"size": "A4; background: red"}}, "size"),
        ({"fonts": {"body": {"family": 'Arial"; } * { color: red'}}}, "family"),
        ({"labels": {"no.such.key": "x"}}, "unknown label"),
        ({"colours": {}}, "colours"),
        ({"watermark": {"text": "x", "opacity": 5}}, "opacity"),
    ],
)
def test_invalid_theme_values_are_refused(data: dict[str, object], message: str) -> None:
    with pytest.raises(ThemeError, match=message):
        Theme.from_data(data, Path.cwd())


def test_custom_page_size_and_margins() -> None:
    theme = Theme.from_data({"page": {"size": ["8.5in", "11in"], "margins": {"left": "1in"}}}, Path.cwd())
    assert theme.page.css_size() == "215.9mm 279.4mm"
    assert theme.page.css_margins() == "20mm 16mm 18mm 1in"
    assert theme.page.css_size(landscape=True) == "279.4mm 215.9mm"


def test_labels_override_defaults_and_allow_extra_status_words() -> None:
    theme = Theme.from_data(
        {"labels": {"column.threat": "Bedrohung", "status.in_review": "In Prüfung"}}, Path.cwd()
    )
    assert theme.label("column.threat") == "Bedrohung"
    assert theme.label("status.in_review") == "In Prüfung"
    assert theme.label("column.ref") == DEFAULT_LABELS["column.ref"]
    assert theme.label("status.something_new") == "something new"


# ── CSS safety ───────────────────────────────────────────────────────────────


def test_css_content_quotes_text_and_turns_page_placeholders_into_counters() -> None:
    assert css_content("Page {page} of {pages}") == '"Page " counter(page) " of " counter(pages)'
    assert css_content("") == "none"
    hostile = css_content('x"; } body { display: none } </style><script>')
    assert "</style>" not in hostile and "<script>" not in hostile
    assert hostile.startswith('"x\\"; }')


def test_theme_css_escapes_slot_text() -> None:
    css = theme_css(Theme(), "#000000", "#ffffff", {"top-left": '"; } </style>'}, banner=False)
    assert "</style>" not in css
    assert '"\\"; } \\3C /style\\3E "' in css


def test_header_text_from_definition_cannot_break_out_of_style() -> None:
    html = build({"theme": {"header": {"left": "</style><script>alert(1)</script>"}}})
    style = html.split("<style>", 1)[1].split("</style>", 1)[0]
    assert "<script>" not in style
    assert "<script>" not in html


def test_extra_css_cannot_close_the_style_element() -> None:
    html = build({"theme": {"extra_css": "h1 { color: red } </style><script>alert(1)</script>"}})
    assert "<script>alert(1)</script>" not in html
    assert "h1 { color: red }" in html


# ── assets ──────────────────────────────────────────────────────────────────────


def test_fonts_are_embedded_after_a_content_check(tmp_path: Path) -> None:
    (tmp_path / "f.ttf").write_bytes(TTF)
    theme = Theme.from_data(
        {"fonts": {"body": {"family": "House Sans", "files": {"regular": "f.ttf"}}}}, tmp_path
    )
    faces = font_faces(theme)
    assert len(faces) == 1 and 'font-family: "House Sans"' in faces[0] and "data:font/ttf;base64," in faces[0]

    (tmp_path / "evil.ttf").write_text("-----BEGIN PRIVATE KEY-----")
    bad = Theme.from_data({"fonts": {"body": {"family": "X", "files": {"regular": "evil.ttf"}}}}, tmp_path)
    with pytest.raises(ThemeError, match="Not a TTF"):
        font_faces(bad)
    missing = Theme.from_data(
        {"fonts": {"body": {"family": "X", "files": {"regular": "nope.ttf"}}}}, tmp_path
    )
    with pytest.raises(ThemeError, match="not found"):
        font_faces(missing)


def test_cover_image_layout(tmp_path: Path) -> None:
    (tmp_path / "cover.png").write_bytes(PNG)
    (tmp_path / "theme.yaml").write_text(
        yaml.safe_dump({"cover": {"layout": "image", "background_image": "cover.png"}})
    )
    html = build({"theme": "theme.yaml"}, base=tmp_path)
    assert "cover-layout-image" in html and "data:image/png;base64," in html

    (tmp_path / "secret.png").write_text("not an image")
    (tmp_path / "theme.yaml").write_text(
        yaml.safe_dump({"cover": {"layout": "image", "background_image": "secret.png"}})
    )
    with pytest.raises(ReportDefinitionError, match="must be a PNG"):
        build({"theme": "theme.yaml"}, base=tmp_path)


def test_missing_theme_file(tmp_path: Path) -> None:
    with pytest.raises(ThemeError, match="Theme not found"):
        build({"theme": "nope.yaml"}, base=tmp_path)


# ── effect on the report ───────────────────────────────────────────────────────


def test_theme_colours_labels_header_and_numbering_reach_the_report() -> None:
    html = build(
        {
            "theme": {
                "colors": {"primary": "#123456", "severity": {"high": "#00ff00"}},
                "labels": {"section.threat_table": "Threat register", "column.ref": "ID"},
                "header": {"right": "{{ document.id }}"},
                "footer": {"right": "S. {page}/{pages}"},
                "numbering": False,
                "watermark": {"text": "DRAFT"},
            },
            "document": {"id": "TM-{{ product.name }}"},
            "validation": {"on_failure": "warn"},
        }
    )
    assert "--primary: #123456" in html and "--sev-high: #00ff00" in html
    assert "Threat register" in html and ">ID</th>" in html
    assert '"TM-Payments API"' in html
    assert '"S. " counter(page) "/" counter(pages)' in html
    assert '<span class="num">' not in html
    assert '<div class="watermark">DRAFT</div>' in html


def test_definition_branding_overrides_theme_only_where_set(tmp_path: Path) -> None:
    d = ReportDefinition.from_data(
        {
            "theme": {
                "branding": {"organisation": "Theme Org", "footer": "T"},
                "colors": {"primary": "#111111"},
            },
            "branding": {"organisation": "Def Org"},
        }
    )
    b = effective_branding(d, load_theme(d))
    assert (b.organisation, b.footer, b.primary_color) == ("Def Org", "T", "#111111")


def test_definition_page_size_overrides_theme() -> None:
    d = ReportDefinition.from_data({"theme": {"page": {"size": "A3"}}, "page_size": "Letter"})
    assert load_theme(d).page.size == "Letter"
    d = ReportDefinition.from_data({"theme": {"page": {"size": "A3"}}})
    assert load_theme(d).page.size == "A3"


def test_document_control_section_fills_placeholders() -> None:
    html = build(
        {
            "document": {
                "id": "TM-1",
                "revisions": [{"version": "1.0", "author": "{{ product.owner_name }}"}],
                "approvals": [{"role": "Owner", "name": "{{ product.owner_name }}"}],
            },
            "sections": [{"type": "document_control"}],
            "validation": {"on_failure": "ignore"},
        }
    )
    assert "Document control" in html and "TM-1" in html and "Revision history" in html
    assert "{{" not in html and html.count("Pat Owner") >= 2


def test_cli_theme_commands(tmp_path: Path) -> None:
    runner = CliRunner()
    out = tmp_path / "theme.yaml"
    assert runner.invoke(app, ["report", "init", "--theme", str(out)]).exit_code == 0
    Theme.load(out)
    result = runner.invoke(app, ["report", "schema", "--theme"])
    assert result.exit_code == 0 and '"labels"' in result.stdout
    result = runner.invoke(app, ["report", "labels", "--theme", str(out)])
    assert (
        result.exit_code == 0
        and "* section.threat_table" in result.stdout
        and "Threat register" in result.stdout
    )
