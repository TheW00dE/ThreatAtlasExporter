"""Root ``tae`` command."""

from __future__ import annotations

import logging
from pathlib import Path

import typer

from tae import __version__
from tae.cli import auth, config_cmd, import_cmd, pull, report_cmd, validate_cmd
from tae.cli.common import ErrorHandlingGroup, console, get_state
from tae.cli.resources import diagrams, frameworks, mitigations, models, products, risks, threats
from tae.output import OutputFormat

app = typer.Typer(
    name="tae",
    cls=ErrorHandlingGroup,
    help="Pull, validate and report on OWASP ThreatAtlas threat models.",
    no_args_is_help=True,
    rich_markup_mode="rich",
    context_settings={"help_option_names": ["-h", "--help"]},
    pretty_exceptions_enable=False,
)

app.add_typer(auth.app, name="auth")
app.add_typer(config_cmd.app, name="config")
app.add_typer(products.app, name="products")
app.add_typer(frameworks.app, name="frameworks")
app.add_typer(diagrams.app, name="diagrams")
app.add_typer(models.app, name="models")
app.add_typer(threats.app, name="threats")
app.add_typer(mitigations.app, name="mitigations")
app.add_typer(risks.app, name="risks")
app.command("pull")(pull.pull)
app.command("validate")(validate_cmd.validate)
app.command("rules")(validate_cmd.rules_list)
app.add_typer(report_cmd.app, name="report")
app.command("import")(import_cmd.import_file)


def _version(value: bool) -> None:
    if value:
        console.print(f"tae {__version__}")
        raise typer.Exit()


@app.callback()
def root(
    ctx: typer.Context,
    profile: str | None = typer.Option(
        None, "--profile", "-p", help="Config profile to use. [env: TAE_PROFILE]", show_default=False
    ),
    url: str | None = typer.Option(
        None, "--url", help="ThreatAtlas base URL, e.g. https://threatatlas.example.com [env: TAE_URL]"
    ),
    token: str | None = typer.Option(
        None,
        "--token",
        help="API token. Prefer TAE_TOKEN / TAE_TOKEN_FILE so it doesn't land in shell history.",
    ),
    config: Path | None = typer.Option(
        None, "--config", help="Config file. [env: TAE_CONFIG] [default: ~/.config/tae/config.toml]"
    ),
    ca_bundle: str | None = typer.Option(
        None, "--ca-bundle", help="CA bundle for internal certificates. [env: TAE_CA_BUNDLE]"
    ),
    verify_tls: bool | None = typer.Option(
        None,
        "--verify-tls/--no-verify-tls",
        help="Verify TLS certificates. Only disable for local testing. [env: TAE_VERIFY_TLS]",
        show_default=False,
    ),
    timeout: float | None = typer.Option(
        None, "--timeout", help="HTTP timeout in seconds. [env: TAE_TIMEOUT]"
    ),
    output: OutputFormat = typer.Option(
        OutputFormat.table, "--output", "-o", help="Output format for list/get commands."
    ),
    verbose: int = typer.Option(0, "--verbose", "-v", count=True, help="More logging (-v info, -vv debug)."),
    version: bool = typer.Option(
        False, "--version", callback=_version, is_eager=True, help="Show the version and exit."
    ),
) -> None:
    state = get_state(ctx)
    o = state.overrides
    o.profile, o.url, o.token, o.config = profile, url, token, config
    o.ca_bundle, o.verify_tls, o.timeout = ca_bundle, verify_tls, timeout
    state.output = output
    state.verbose = verbose
    level = logging.DEBUG if verbose >= 2 else logging.INFO if verbose == 1 else logging.WARNING
    logging.basicConfig(level=level, format="%(levelname)s %(name)s: %(message)s")
    if verbose < 2:
        # httpx logs every request at INFO; only show that in debug mode.
        logging.getLogger("httpx").setLevel(logging.WARNING)


def main() -> None:
    app()
