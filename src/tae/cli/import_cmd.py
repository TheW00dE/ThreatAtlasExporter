"""``tae import``: sync a framework or threat-model YAML file into ThreatAtlas."""

from __future__ import annotations

import json
import sys
from pathlib import Path

import typer
from rich.table import Table
from rich.text import Text

from tae.cli.common import ExitCode, console, err_console, fail, get_state
from tae.client.errors import ThreatAtlasError
from tae.importer import FrameworkDocument, Sync, load_document, sync_framework, sync_threat_model
from tae.importer.schema import Document, json_schema
from tae.output import safe_text

ACTION_STYLE = {"create": "green", "update": "yellow", "delete": "bold red", "note": "dim"}


def _run(s: Sync, doc: Document) -> None:
    if isinstance(doc, FrameworkDocument):
        sync_framework(s, doc)
    else:
        sync_threat_model(s, doc)


def _print_plan(s: Sync) -> None:
    changes = [c for c in s.changes if c.action != "note"]
    notes = [c for c in s.changes if c.action == "note"]
    if changes:
        table = Table(header_style="bold", title="Planned changes", title_justify="left")
        for name in ("Action", "What", "Name", "Details"):
            table.add_column(name, overflow="fold")
        for c in changes:
            table.add_row(
                Text(c.action, style=ACTION_STYLE[c.action]),
                Text(c.kind),
                Text(safe_text(c.name)),
                Text(safe_text(c.detail)),
            )
        console.print(table)
    for n in notes:
        console.print(Text(f"Note: {n.kind} {safe_text(n.name)}: {safe_text(n.detail)}", style="dim"))
    counts = {a: sum(c.action == a for c in changes) for a in ("create", "update", "delete")}
    summary = ", ".join(f"{n} to {a}" for a, n in counts.items() if n) or "nothing to change"
    console.print(f"Plan: {summary}.", markup=False)


def import_file(
    ctx: typer.Context,
    file: Path | None = typer.Argument(None, help="Framework or threat-model YAML file.", show_default=False),
    dry_run: bool = typer.Option(False, "--dry-run", "-n", help="Only show what would change."),
    prune: bool = typer.Option(
        False, "--prune", help="Also delete things in ThreatAtlas that the file no longer contains."
    ),
    yes: bool = typer.Option(
        False, "--yes", "-y", help="Don't ask before deleting (needed for --prune in CI)."
    ),
    schema: str | None = typer.Option(
        None, "--schema", help="Print the JSON Schema for 'framework' or 'threat-model' files and exit."
    ),
) -> None:
    """Create or update a custom framework, or a product's threat model, from a YAML file.

    Re-importing an edited file updates ThreatAtlas to match: entries are matched by
    name, new ones are created and changed ones updated. Nothing is deleted unless
    --prune is given. The plan is always shown first; --dry-run stops there.

    Note: ThreatAtlas shows custom frameworks only to the user who created them, so
    import frameworks and the threat models using them with the same account.
    """
    if schema is not None:
        if schema not in ("framework", "threat-model"):
            fail("--schema must be 'framework' or 'threat-model'", ExitCode.USAGE)
        console.file.write(json.dumps(json_schema(schema), indent=2) + "\n")
        return
    if file is None:
        fail("Give the YAML file to import (or --schema KIND).", ExitCode.USAGE)

    doc = load_document(file)
    state = get_state(ctx)
    client = state.client()

    plan = Sync(client, dry_run=True, prune=prune, source=file.name)
    _run(plan, doc)
    _print_plan(plan)
    if dry_run or not any(c.action != "note" for c in plan.changes):
        _after_notes(doc, file)
        return

    if plan.deletes and not yes:
        if not sys.stdin.isatty():
            fail(f"The plan deletes {len(plan.deletes)} item(s). Add --yes to confirm.", ExitCode.USAGE)
        if not typer.confirm(f"Delete {len(plan.deletes)} item(s) from ThreatAtlas?", default=False):
            fail("Nothing was changed.", ExitCode.USAGE)

    real = Sync(client, dry_run=False, prune=prune, source=file.name)
    try:
        _run(real, doc)
    except ThreatAtlasError:
        done = max(0, sum(c.action != "note" for c in real.changes) - 1)
        err_console.print(
            f"The import stopped after {done} change(s). Fix the problem and run it again: "
            "it picks up where it left off.",
            markup=False,
        )
        raise
    applied = sum(c.action != "note" for c in real.changes)
    console.print(f"Applied {applied} change(s) to {client.base_url}.", markup=False)
    _after_notes(doc, file)


def _after_notes(doc: Document, file: Path) -> None:
    if isinstance(doc, FrameworkDocument):
        if doc.risk_scale is not None:
            console.print(
                f"The risk scale is in the framework description. To use it in tae, add "
                f"'risk_scales: [{file}]' to a report definition or validation config, "
                f"or run tae validate --risk-scale {file}.",
                markup=False,
                style="dim",
            )
        console.print(
            "ThreatAtlas shows custom frameworks only to the account that created them.",
            markup=False,
            style="dim",
        )
