from __future__ import annotations

import os
from datetime import date
from pathlib import Path

import pytest
from pypdf import PdfReader

from tae.errors import EnvironmentProblem
from tae.report import pdf
from tae.report.definition import ReportDefinition
from tae.report.pdf import PdfEngine
from tae.report.render import build_report
from tests.conftest import make_snapshot

CHROMIUM = os.environ.get("TAE_TEST_BROWSER", "/opt/pw-browsers/chromium")


def output():  # type: ignore[no-untyped-def]
    return build_report(make_snapshot(), ReportDefinition(), as_of=date(2026, 11, 25))


def test_auto_prefers_weasyprint(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf, "weasyprint_available", lambda: True)
    assert pdf.resolve_engine(PdfEngine.auto) is PdfEngine.weasyprint


def test_auto_falls_back_to_browser(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "msedge.exe"
    fake.write_text("")
    monkeypatch.setattr(pdf, "weasyprint_available", lambda: False)
    monkeypatch.setenv("TAE_BROWSER", str(fake))
    assert pdf.resolve_engine(PdfEngine.auto) is PdfEngine.browser


def test_no_engine_is_explained(monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(pdf, "weasyprint_available", lambda: False)
    monkeypatch.setattr(pdf, "find_browser", lambda: None)
    with pytest.raises(EnvironmentProblem, match="No PDF engine available"):
        pdf.resolve_engine(PdfEngine.auto)
    with pytest.raises(EnvironmentProblem, match="No Edge, Chrome or Chromium"):
        pdf.resolve_engine(PdfEngine.browser)


def test_browser_override_must_exist(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAE_BROWSER", str(tmp_path / "missing.exe"))
    with pytest.raises(EnvironmentProblem, match="TAE_BROWSER"):
        pdf.find_browser()


def test_windows_finds_edge(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    edge = tmp_path / "x86" / "Microsoft" / "Edge" / "Application" / "msedge.exe"
    edge.parent.mkdir(parents=True)
    edge.write_text("")
    monkeypatch.delenv("TAE_BROWSER", raising=False)
    monkeypatch.setattr(pdf.sys, "platform", "win32")
    monkeypatch.setenv("PROGRAMFILES(X86)", str(tmp_path / "x86"))
    monkeypatch.setenv("PROGRAMFILES", str(tmp_path / "pf"))
    monkeypatch.delenv("LOCALAPPDATA", raising=False)
    assert pdf.find_browser() == edge


def test_inline_stylesheets_and_policy() -> None:
    out = output()
    html = pdf.inline_stylesheets(out.html, out.base_url, out.allowed_dirs)
    assert '<link rel="stylesheet"' not in html
    assert "@page" in html
    assert "Content-Security-Policy" in html and "default-src 'none'" in html
    assert html.index("Content-Security-Policy") < html.index("<style>")


@pytest.mark.parametrize(
    "href", ["https://evil.example/x.css", "file:///etc/passwd", "../../../../etc/passwd"]
)
def test_inline_stylesheets_refuses_outside_files(href: str) -> None:
    out = output()
    html = out.html.replace('href="styles/default.css"', f'href="{href}"')
    with pytest.raises(EnvironmentProblem):
        pdf.inline_stylesheets(html, out.base_url, out.allowed_dirs)


def test_browser_command(tmp_path: Path) -> None:
    cmd = pdf.browser_command(Path("/x/msedge"), tmp_path / "r.html", tmp_path / "r.pdf", tmp_path / "p")
    assert cmd[0] == "/x/msedge"
    assert "--headless=new" in cmd and f"--print-to-pdf={tmp_path / 'r.pdf'}" in cmd
    assert f"--user-data-dir={tmp_path / 'p'}" in cmd  # never touches the user's own browser profile
    assert cmd[-1].startswith("file://")


@pytest.mark.skipif(not Path(CHROMIUM).is_file(), reason="no Chromium available")
def test_browser_engine_renders(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    monkeypatch.setenv("TAE_BROWSER", CHROMIUM)
    path = tmp_path / "report.pdf"
    used = pdf.write_pdf(output(), path, PdfEngine.browser)
    assert used is PdfEngine.browser
    reader = PdfReader(path)
    text = "\n".join(p.extract_text() for p in reader.pages)
    for expected in ("Threat Model Report", "Executive summary", "SQL injection", "Page 2 of"):
        assert expected in text
    assert "Payments API — Threat Model Report" in text  # running header


def test_browser_failure_is_explained(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    fake = tmp_path / "fake-browser"
    fake.write_text("#!/bin/sh\necho 'cannot render' >&2\nexit 3\n")
    fake.chmod(0o755)
    with pytest.raises(EnvironmentProblem, match=r"did not produce a PDF \(exit code 3\)\. cannot render"):
        pdf.write_pdf_with_browser(output(), tmp_path / "x.pdf", fake)


def test_weasyprint_has_running_header_and_no_blank_first_page(tmp_path: Path) -> None:
    path = tmp_path / "w.pdf"
    output().write_pdf(path)
    reader = PdfReader(path)
    assert "Threat Model Report" in reader.pages[0].extract_text()  # page 1 is the cover
    assert "Payments API — Threat Model Report" in reader.pages[1].extract_text()
