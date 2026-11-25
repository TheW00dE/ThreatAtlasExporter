"""PDF engines: WeasyPrint, or a Chromium-based browser (Edge/Chrome) in headless mode.

WeasyPrint gives the best paged-media support (table of contents page numbers,
PDF bookmarks) but needs the Pango/HarfBuzz system libraries, which are awkward
on Windows. Every Windows machine has Microsoft Edge, which can print HTML to PDF
headlessly, so ``auto`` falls back to it when WeasyPrint can't load.
"""

from __future__ import annotations

import logging
import os
import re
import shutil
import subprocess
import sys
import tempfile
from enum import StrEnum
from pathlib import Path
from typing import TYPE_CHECKING
from urllib.parse import unquote, urlparse

from tae.errors import EnvironmentProblem

if TYPE_CHECKING:
    from tae.report.render import ReportOutput

log = logging.getLogger(__name__)

BROWSER_TIMEOUT = 180  # seconds


class PdfEngine(StrEnum):
    auto = "auto"
    weasyprint = "weasyprint"
    browser = "browser"


def weasyprint_available() -> bool:
    from tae.report.render import _weasyprint_html

    try:
        _weasyprint_html()
    except EnvironmentProblem:
        return False
    return True


# ── browser discovery ────────────────────────────────────────────────────────────


def _windows_candidates() -> list[Path]:
    roots = [os.environ.get(v) for v in ("PROGRAMFILES(X86)", "PROGRAMFILES", "LOCALAPPDATA")]
    rel = [
        Path("Microsoft/Edge/Application/msedge.exe"),
        Path("Google/Chrome/Application/chrome.exe"),
        Path("Chromium/Application/chrome.exe"),
    ]
    return [Path(root) / r for root in roots if root for r in rel]


_UNIX_NAMES = (
    "microsoft-edge",
    "microsoft-edge-stable",
    "google-chrome",
    "google-chrome-stable",
    "chromium",
    "chromium-browser",
)
_MAC_APPS = (
    Path("/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge"),
    Path("/Applications/Google Chrome.app/Contents/MacOS/Google Chrome"),
    Path("/Applications/Chromium.app/Contents/MacOS/Chromium"),
)


def find_browser() -> Path | None:
    """Locate Edge, Chrome or Chromium. ``TAE_BROWSER`` overrides the search."""
    override = os.environ.get("TAE_BROWSER")
    if override:
        path = Path(override)
        if not path.is_file():
            raise EnvironmentProblem(f"TAE_BROWSER points to {path}, which does not exist")
        return path
    # Read the platform at call time (tests switch it); a plain string avoids mypy
    # treating the other platforms' branches as unreachable.
    platform: str = sys.platform
    candidates: list[Path] = []
    if platform == "win32":
        candidates = _windows_candidates()
    elif platform == "darwin":
        candidates = list(_MAC_APPS)
    for c in candidates:
        if c.is_file():
            return c
    for name in _UNIX_NAMES:
        found = shutil.which(name)
        if found:
            return Path(found)
    return None


def resolve_engine(engine: PdfEngine) -> PdfEngine:
    """Turn ``auto`` into a concrete engine, or explain why none is usable."""
    if engine is PdfEngine.weasyprint:
        return engine
    if engine is PdfEngine.browser:
        if find_browser() is None:
            raise EnvironmentProblem(
                "No Edge, Chrome or Chromium found for PDF rendering. Install one, or set TAE_BROWSER "
                "to the browser executable."
            )
        return engine
    if weasyprint_available():
        return PdfEngine.weasyprint
    if find_browser() is not None:
        return PdfEngine.browser
    raise EnvironmentProblem(
        "No PDF engine available: WeasyPrint's libraries (Pango, HarfBuzz) are missing and no Edge, "
        "Chrome or Chromium was found. Install either, or set TAE_BROWSER to a browser executable."
    )


# ── rendering ─────────────────────────────────────────────────────────────────────

_STYLESHEET_LINK = re.compile(r'<link rel="stylesheet" href="([^"]+)">')

# The page handed to the browser is self-contained (inline CSS, data: images). This
# policy stops it running scripts or fetching anything. (Chromium's own flags for
# disabling scripts or DNS also stop it printing, so the policy is set in the page.)
BROWSER_CSP = (
    '<meta http-equiv="Content-Security-Policy" '
    "content=\"default-src 'none'; img-src data:; style-src 'unsafe-inline'; font-src data:\">"
)


def inline_stylesheets(html: str, base_url: str, allowed_dirs: list[Path]) -> str:
    """Replace stylesheet links with inline <style> so the page is self-contained.

    Only files inside the template directories are read, as with the WeasyPrint fetcher.
    """
    base = Path(unquote(urlparse(base_url).path))
    roots = [d.resolve() for d in allowed_dirs]

    def replace(m: re.Match[str]) -> str:
        href = m.group(1)
        if re.match(r"^[a-z][a-z0-9+.-]*:", href, re.IGNORECASE):
            raise EnvironmentProblem(f"Refusing to load stylesheet {href!r}: only template files are allowed")
        for root in [base, *roots]:
            path = (root / href).resolve()
            if path.is_file() and any(path.is_relative_to(r) for r in roots):
                css = path.read_text(encoding="utf-8").replace("</", "<\\/")
                return f"<style>\n{css}\n</style>"
        raise EnvironmentProblem(f"Stylesheet {href!r} not found in the report templates")

    html = _STYLESHEET_LINK.sub(replace, html)
    if '<meta charset="utf-8">' not in html:
        raise EnvironmentProblem("Report HTML has no charset meta tag; cannot apply the content policy")
    return html.replace('<meta charset="utf-8">', '<meta charset="utf-8">\n' + BROWSER_CSP, 1)


def browser_command(browser: Path, html_file: Path, pdf_file: Path, profile_dir: Path) -> list[str]:
    args = [
        str(browser),
        "--headless=new",
        "--disable-gpu",
        "--no-first-run",
        "--no-default-browser-check",
        "--disable-extensions",
        "--disable-sync",
        "--disable-background-networking",
        "--disable-component-update",
        f"--user-data-dir={profile_dir}",
        "--no-pdf-header-footer",
        "--generate-pdf-document-outline",
        f"--print-to-pdf={pdf_file}",
        html_file.as_uri(),
    ]
    if hasattr(os, "geteuid") and os.geteuid() == 0:
        args.insert(1, "--no-sandbox")  # Chromium refuses to run sandboxed as root (containers)
    return args


def write_pdf_with_browser(output: ReportOutput, path: Path, browser: Path | None = None) -> None:
    browser = browser or find_browser()
    if browser is None:
        raise EnvironmentProblem("No Edge, Chrome or Chromium found for PDF rendering.")
    html = inline_stylesheets(output.html, output.base_url, output.allowed_dirs)
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="tae-pdf-") as tmp:
        tmp_dir = Path(tmp)
        html_file = tmp_dir / "report.html"
        html_file.write_text(html, encoding="utf-8")
        pdf_tmp = tmp_dir / "report.pdf"
        cmd = browser_command(browser, html_file, pdf_tmp, tmp_dir / "profile")
        log.debug("Running %s", cmd)
        try:
            proc = subprocess.run(  # noqa: S603  (fixed argument list, no shell)
                cmd, capture_output=True, text=True, timeout=BROWSER_TIMEOUT, check=False
            )
        except subprocess.TimeoutExpired as exc:
            raise EnvironmentProblem(
                f"{browser.name} did not finish rendering within {BROWSER_TIMEOUT}s"
            ) from exc
        except OSError as exc:
            raise EnvironmentProblem(f"Could not start {browser}: {exc}") from exc
        if not pdf_tmp.is_file() or pdf_tmp.stat().st_size == 0:
            detail = (proc.stderr or proc.stdout or "").strip().splitlines()[-3:]
            raise EnvironmentProblem(
                f"{browser.name} did not produce a PDF (exit code {proc.returncode}). " + " ".join(detail)
            )
        shutil.move(str(pdf_tmp), path)


def write_pdf(output: ReportOutput, path: Path, engine: PdfEngine = PdfEngine.auto) -> PdfEngine:
    """Render ``output`` to ``path``; returns the engine actually used."""
    chosen = resolve_engine(engine)
    if chosen is PdfEngine.weasyprint:
        output.write_pdf(path)
    else:
        write_pdf_with_browser(output, path)
    return chosen
