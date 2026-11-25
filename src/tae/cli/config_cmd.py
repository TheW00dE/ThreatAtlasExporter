"""``tae config``: inspect the resolved configuration."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.config import default_config_path, keyring_available

app = typer.Typer(help="Inspect configuration.", no_args_is_help=True)


@app.command("show")
def show(ctx: typer.Context) -> None:
    """Show the effective settings after applying the config file, env vars and flags."""
    s = get_state(ctx).settings
    verify = (
        "disabled" if s.verify is False else ("system CAs" if s.verify is True else f"CA bundle {s.verify}")
    )
    rows = [
        ("Config file", str(s.config_path) if s.config_path else f"none ({default_config_path()} not found)"),
        ("Profile", s.profile or "—"),
        ("URL", s.url),
        ("TLS", verify),
        ("Timeout", f"{s.timeout:g}s"),
        ("Retries", str(s.retries)),
        ("Token", f"set (from {s.token_source})" if s.token else "not set"),
        ("Keyring", "available" if keyring_available() else "not installed"),
    ]
    width = max(len(k) for k, _ in rows)
    for key, value in rows:
        console.print(f"{key.ljust(width)}  {value}", markup=False, highlight=False)


@app.command("path")
def path() -> None:
    """Print the default config file location."""
    console.print(str(default_config_path()), markup=False, highlight=False)
