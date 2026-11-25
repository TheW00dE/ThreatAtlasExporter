"""``tae frameworks``."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.output import col, render_item, render_list

app = typer.Typer(help="Threat-modeling frameworks (STRIDE, LINDDUN, custom).", no_args_is_help=True)

COLUMNS = [
    col("ID", "id"),
    col("Name", "name", 30),
    col("Custom", "is_custom"),
    col("Description", "description", 70),
]


@app.command("list")
def list_(ctx: typer.Context) -> None:
    """List frameworks."""
    state = get_state(ctx)
    render_list(console, state.client().frameworks.list(), COLUMNS, state.output, title="Frameworks")


@app.command("get")
def get(ctx: typer.Context, framework_id: int = typer.Argument(..., help="Framework ID.")) -> None:
    """Show one framework."""
    state = get_state(ctx)
    render_item(console, state.client().frameworks.get(framework_id), state.output)
