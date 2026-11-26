"""``tae auth``: store, check and remove the API token."""

from __future__ import annotations

import sys

import typer
from rich.markup import escape

from tae.cli.common import ExitCode, State, console, err_console, fail, get_state
from tae.client import ThreatAtlasClient
from tae.config import ConfigError, keyring_delete, keyring_set, resolve
from tae.output import safe_text

app = typer.Typer(help="Manage the ThreatAtlas API token.", no_args_is_help=True)


@app.command("login")
def login(
    ctx: typer.Context,
    token_stdin: bool = typer.Option(False, "--token-stdin", help="Read the token from standard input."),
) -> None:
    """Check a personal API token against the server and store it in the OS keyring.

    Create the token in ThreatAtlas under Settings → Integrations → API Tokens.
    In containers and CI, set TAE_TOKEN or TAE_TOKEN_FILE instead.
    """
    state = get_state(ctx)
    # Resolve everything except the token: a broken token setup (say, a token file that
    # was deleted) must not stop the command that replaces the token.
    settings = resolve(state.overrides, with_token=False)
    if token_stdin:
        token = sys.stdin.readline().strip()
    else:
        token = typer.prompt(f"API token for {settings.url}", hide_input=True).strip()
    if not token:
        fail("No token given.", ExitCode.USAGE)
    if not token.startswith("ta_"):
        err_console.print("[yellow]Note: personal API tokens normally start with 'ta_'.[/yellow]")

    with ThreatAtlasClient(settings.url, token, **settings.client_options()) as client:
        user = client.users.me()
    keyring_set(settings.url, token)
    console.print(
        f"Logged in to {escape(safe_text(settings.url))} as [bold]{escape(safe_text(user.username))}[/bold] "
        f"({escape(safe_text(user.role))}). Token saved in the OS keyring."
    )
    _warn_if_overridden(state)


def _warn_if_overridden(state: State) -> None:
    """The keyring is the last place tae looks; say so if something else wins."""
    try:
        effective = resolve(state.overrides)
    except ConfigError as exc:
        err_console.print(
            f"Warning: your configuration has another token source that is broken and takes "
            f"precedence over the keyring: {safe_text(exc)}",
            markup=False,
            highlight=False,
        )
        return
    if effective.token_source and effective.token_source != "keyring":  # noqa: S105  (a source name)
        err_console.print(
            f"Warning: the token from {effective.token_source} takes precedence over the keyring, "
            "so tae will keep using that one. Remove it to use the token you just saved.",
            markup=False,
            highlight=False,
        )


@app.command("status")
def status(ctx: typer.Context) -> None:
    """Show which server and user the current token resolves to."""
    state = get_state(ctx)
    s = state.settings
    console.print(f"URL:      {s.url}", markup=False, highlight=False)
    console.print(f"Profile:  {s.profile or '—'}", markup=False, highlight=False)
    console.print(
        f"Token:    {'from ' + s.token_source if s.token_source else 'none'}", markup=False, highlight=False
    )
    user = state.client().users.me()
    role = user.effective_role or user.role
    console.print(
        f"User:     {safe_text(user.username)} <{safe_text(user.email)}> (role: {safe_text(role)})",
        markup=False,
        highlight=False,
    )


@app.command("logout")
def logout(ctx: typer.Context) -> None:
    """Remove the stored token for the current URL from the OS keyring."""
    url = get_state(ctx).settings.url
    if keyring_delete(url):
        console.print(f"Removed the stored token for {url}.", markup=False, highlight=False)
    else:
        console.print(f"No stored token for {url}.", markup=False, highlight=False)
