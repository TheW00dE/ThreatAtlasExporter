"""``tae desktop``: the desktop proof of concept (a local web page in the user's browser)."""

from __future__ import annotations

import os
import ssl
from pathlib import Path

import truststore
import typer

from tae.cli.common import console, err_console, get_state
from tae.client import errors as api_errors
from tae.config import resolve
from tae.desktop.runs import ReportStore, RunManager, load_presets
from tae.desktop.server import DesktopApp, engine_label, launch_url, make_server, open_browser
from tae.errors import EnvironmentProblem
from tae.report.pdf import PdfEngine, resolve_engine


def default_reports_dir() -> Path:
    """``Documents/ThreatAtlas Reports`` when a Documents folder exists, else the home folder."""
    home = Path.home()
    documents = home / "Documents"
    return (documents if documents.is_dir() else home) / "ThreatAtlas Reports"


def desktop(
    ctx: typer.Context,
    port: int = typer.Option(0, "--port", help="Local port. [default: a free one]"),
    reports_dir: Path | None = typer.Option(
        None, "--reports-dir", help="Where reports are saved. [default: Documents/ThreatAtlas Reports]"
    ),
    pdf_engine: PdfEngine = typer.Option(PdfEngine.auto, "--pdf-engine", help="weasyprint, browser or auto."),
    no_browser: bool = typer.Option(
        False, "--no-browser", help="Don't open the browser; just print the link."
    ),
) -> None:
    """Start the desktop app: a local page in your browser to generate and download reports.

    It only listens on this computer (127.0.0.1), uses your own ThreatAtlas API token,
    and saves every report, with the data it was built from, in a local folder.
    Report types: the built-in ones plus any *.yaml report definitions in
    <reports folder>/definitions/.
    """
    state = get_state(ctx)
    settings = resolve(state.overrides, require_url=False)
    env_dir = os.environ.get("TAE_REPORTS_DIR")
    root = (reports_dir or (Path(env_dir) if env_dir else default_reports_dir())).expanduser()
    root.mkdir(parents=True, exist_ok=True)

    try:
        engine = resolve_engine(pdf_engine)
        label = engine_label(engine)
    except EnvironmentProblem as exc:
        err_console.print(f"[yellow]Warning:[/yellow] {exc}", highlight=False)
        engine, label = pdf_engine, "not available"

    client_options = settings.client_options()
    if client_options.get("verify") is True:
        # Trust the operating system's certificate store (Windows, macOS, Linux), so an
        # internal CA the desktop already trusts works without configuring a CA bundle.
        client_options["verify"] = truststore.SSLContext(ssl.PROTOCOL_TLS_CLIENT)

    store = ReportStore(root)
    interrupted = store.mark_interrupted()
    app = DesktopApp(
        store=store,
        runs=RunManager(store, engine),
        presets=load_presets(root / "definitions"),
        engine_label=label,
        client_options=client_options,
    )
    app.connection.url = settings.url or None
    if settings.url and settings.token:
        try:
            user = app.sign_in(settings.url, settings.token)
            console.print(
                f"Signed in to {settings.url} as {user.username} (token from {settings.token_source}).",
                markup=False,
                highlight=False,
            )
        except (api_errors.ThreatAtlasError, ValueError) as exc:
            err_console.print(f"Could not sign in automatically: {exc}", markup=False, highlight=False)

    server = make_server(app, port)
    link = launch_url(app)
    console.print("ThreatAtlas Reports (desktop proof of concept)", style="bold")
    console.print(f"Reports folder: {root}", markup=False, highlight=False)
    console.print(f"PDF engine:     {label}", markup=False, highlight=False)
    if interrupted:
        console.print(f"Marked {interrupted} unfinished report(s) from a previous session as interrupted.")
    console.print("\nOpen this link in your browser (it only works on this computer):", highlight=False)
    console.print(link, markup=False, highlight=False, soft_wrap=True)
    console.print("\nKeep this window open while you use the app. Press Ctrl+C to stop.\n")
    if not no_browser and not open_browser(link):
        err_console.print("Could not open a browser automatically; copy the link above.", markup=False)
    # Make sure the link is visible even when output is piped or captured (it's buffered then).
    console.file.flush()
    err_console.file.flush()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        console.print("Stopping.")
    finally:
        server.server_close()
