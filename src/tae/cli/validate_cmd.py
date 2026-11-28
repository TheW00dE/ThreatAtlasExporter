"""``tae validate`` and ``tae rules``."""

from __future__ import annotations

from datetime import date
from pathlib import Path

import typer
from rich.table import Table
from rich.text import Text

from tae.cli.common import ExitCode, console, err_console, get_state
from tae.cli.inputs import obtain_snapshot
from tae.output import OutputFormat, print_structured
from tae.risk import load_risk_scales
from tae.snapshot import build_view
from tae.validate import FailLevel, ValidationConfig, builtin_rules, run
from tae.validate.engine import active_rules
from tae.validate.output import (
    FindingsFormat,
    render_table,
    summary_line,
    to_codequality,
    to_json,
    to_junit,
)


def validate(
    ctx: typer.Context,
    snapshot: Path | None = typer.Argument(None, help="Snapshot file from `tae pull`.", show_default=False),
    product: str | None = typer.Option(None, "--product", "-P", help="Pull this product live instead."),
    rules: Path | None = typer.Option(
        None, "--rules", "-r", help="Validation config (YAML): custom rules, levels."
    ),
    fail_level: FailLevel = typer.Option(
        FailLevel.error, "--fail-level", help="Exit with code 10 if findings at this level or worse exist."
    ),
    fmt: FindingsFormat = typer.Option(FindingsFormat.table, "--format", help="Output format."),
    output_file: Path | None = typer.Option(None, "--output-file", "-f", help="Write the output here."),
    as_of: str | None = typer.Option(
        None, "--as-of", help="Date for review-date checks (YYYY-MM-DD). [default: today]"
    ),
    risk_scale: list[Path] = typer.Option(
        [],
        "--risk-scale",
        help="Framework or risk-scale file with a custom risk scale (repeatable).",
        show_default=False,
    ),
    location: str | None = typer.Option(
        None, "--location", help="File path reported in Code Quality output. [default: the snapshot path]"
    ),
) -> None:
    """Check a product's threat model against the built-in and custom rules.

    Exit codes: 0 passed, 10 findings at or above --fail-level, 3 bad input.
    """
    state = get_state(ctx)
    config = ValidationConfig.load(rules) if rules else ValidationConfig()
    snap = obtain_snapshot(state, snapshot, product)
    day = _parse_date(as_of)
    scales = load_risk_scales([*risk_scale, *config.scale_paths()])
    result = run(build_view(snap, scales), config, as_of=day)

    if fmt is FindingsFormat.table and output_file is None:
        render_table(console, result, fail_level)
    else:
        if fmt is FindingsFormat.table or fmt is FindingsFormat.json:
            text = to_json(result, fail_level)
        elif fmt is FindingsFormat.junit:
            text = to_junit(result, fail_level)
        else:
            text = to_codequality(
                result, location or (str(snapshot) if snapshot else f"threatatlas/{snap.product.id}")
            )
        if output_file:
            output_file.write_text(text + "\n", encoding="utf-8")
            err_console.print(summary_line(result, fail_level), markup=False, highlight=False)
        else:
            console.file.write(text + "\n")

    if result.fails(fail_level):
        raise typer.Exit(int(ExitCode.CHECKS_FAILED))


def _parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not a date in YYYY-MM-DD form", param_hint="--as-of"
        ) from None


def rules_list(
    ctx: typer.Context,
    rules: Path | None = typer.Option(
        None, "--rules", "-r", help="Include custom rules and overrides from this config."
    ),
) -> None:
    """List the validation rules, their levels and what they check."""
    state = get_state(ctx)
    config = ValidationConfig.load(rules) if rules else ValidationConfig()
    active = {r.id: r for r in active_rules(config)}
    all_rules = builtin_rules() + [r.to_rule() for r in config.rules]

    if state.output is not OutputFormat.table:
        data = [
            {
                "id": r.id,
                "family": r.family,
                "level": active[r.id].level.value if r.id in active else None,
                "enabled": r.id in active,
                "title": r.title,
                "description": r.description,
            }
            for r in all_rules
        ]
        print_structured(console, data, state.output)
        return

    table = Table(header_style="bold")
    for name in ("Rule", "Family", "Level", "Title", "Checks"):
        table.add_column(name, overflow="fold")
    for r in all_rules:
        level = active[r.id].level.value if r.id in active else "disabled"
        table.add_row(Text(r.id), Text(r.family), Text(level), Text(r.title), Text(r.description))
    console.print(table)
