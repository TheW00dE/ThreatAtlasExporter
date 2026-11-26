"""Shared CLI state, consoles, exit codes and error handling."""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import IntEnum
from typing import Any, NoReturn

import typer
from rich.console import Console
from rich.markup import escape
from typer.core import TyperGroup

from tae.client import ThreatAtlasClient
from tae.client import errors as e
from tae.config import ConfigError, Overrides, Settings, resolve
from tae.errors import EnvironmentProblem, InputError
from tae.output import OutputFormat, safe_text
from tae.snapshot.collector import ProductNotFound

console = Console(soft_wrap=True)
err_console = Console(stderr=True, soft_wrap=True)


class ExitCode(IntEnum):
    OK = 0
    ERROR = 1
    USAGE = 2  # click's own code for bad arguments
    CONFIG = 3
    AUTH = 4
    NOT_FOUND = 5
    CONNECTION = 6
    API = 7
    CHECKS_FAILED = 10  # validation failed, or a report was blocked by validation


@dataclass
class State:
    overrides: Overrides = field(default_factory=Overrides)
    output: OutputFormat = OutputFormat.table
    verbose: int = 0
    _settings: Settings | None = None
    _client: ThreatAtlasClient | None = None

    @property
    def settings(self) -> Settings:
        if self._settings is None:
            self._settings = resolve(self.overrides)
            if self._settings.verify is False:
                err_console.print("[yellow]Warning: TLS certificate verification is disabled.[/yellow]")
        return self._settings

    def client(self, *, require_token: bool = True) -> ThreatAtlasClient:
        if self._client is None:
            s = self.settings
            if require_token and not s.token:
                raise ConfigError(
                    "No API token found. Set TAE_TOKEN or TAE_TOKEN_FILE, pass --token, "
                    "or run `tae auth login`. "
                    "Create a token in ThreatAtlas under Settings → Integrations → API Tokens."
                )
            self._client = ThreatAtlasClient(s.url, s.token, **s.client_options())
        return self._client

    def close(self) -> None:
        if self._client is not None:
            self._client.close()
            self._client = None


def get_state(ctx: typer.Context) -> State:
    obj = ctx.find_root().obj
    if not isinstance(obj, State):
        obj = State()
        ctx.find_root().obj = obj
    return obj


def fail(message: str, code: ExitCode = ExitCode.ERROR) -> NoReturn:
    err_console.print(f"[red]Error:[/red] {escape(safe_text(message))}", highlight=False)
    raise typer.Exit(int(code))


def _exit_code_for(exc: Exception) -> ExitCode:
    if isinstance(exc, ConfigError | InputError | EnvironmentProblem):
        return ExitCode.CONFIG
    if isinstance(exc, ProductNotFound):
        return ExitCode.NOT_FOUND
    if isinstance(exc, e.AuthenticationError | e.PermissionDenied):
        return ExitCode.AUTH
    if isinstance(exc, e.NotFound):
        return ExitCode.NOT_FOUND
    if isinstance(exc, e.ConnectionFailed):
        return ExitCode.CONNECTION
    if isinstance(exc, e.ThreatAtlasError):
        return ExitCode.API
    return ExitCode.ERROR


def _hint_for(exc: Exception) -> str | None:
    if isinstance(exc, e.AuthenticationError):
        return "The token was rejected or has expired. Create a new one and run `tae auth login`."
    if isinstance(exc, e.PermissionDenied):
        return "Your ThreatAtlas user doesn't have permission for this (role or product sharing)."
    if isinstance(exc, e.ConnectionFailed) and "CERTIFICATE_VERIFY_FAILED" in str(exc):
        return "If the instance uses an internal CA, set TAE_CA_BUNDLE or ca_bundle in the profile."
    return None


class ErrorHandlingGroup(TyperGroup):
    """Root command group: turns known exceptions into a message and an exit code."""

    def invoke(self, ctx: Any) -> Any:
        try:
            return super().invoke(ctx)
        except (ConfigError, InputError, EnvironmentProblem, e.ThreatAtlasError) as exc:
            if logging.getLogger().isEnabledFor(logging.DEBUG):
                err_console.print_exception()
            # Error text can contain server-supplied detail: no markup, no escape sequences.
            err_console.print(f"[red]Error:[/red] {escape(safe_text(exc))}", highlight=False)
            hint = _hint_for(exc)
            if hint:
                err_console.print(f"[dim]{escape(hint)}[/dim]", highlight=False)
            raise typer.Exit(int(_exit_code_for(exc))) from None
        finally:
            obj = ctx.obj
            if isinstance(obj, State):
                obj.close()
