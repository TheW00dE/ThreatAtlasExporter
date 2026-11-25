"""``tae models``: threat models (a framework bound to a diagram)."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.output import col, render_item, render_list

app = typer.Typer(help="Threat models: a framework applied to a diagram.", no_args_is_help=True)

COLUMNS = [
    col("ID", "id"),
    col("Name", "name", 35),
    col("Diagram", "diagram_id"),
    col("Framework", "framework_name"),
    col("Status", "status"),
    col("Threats", "threat_count"),
    col("Mitigations", "mitigation_count"),
    col("Completed", "completed_at"),
]


@app.command("list")
def list_(
    ctx: typer.Context,
    diagram: int | None = typer.Option(None, "--diagram", "-d", help="Only models on this diagram."),
) -> None:
    """List threat models."""
    state = get_state(ctx)
    render_list(console, state.client().models.list(diagram), COLUMNS, state.output, title="Threat models")


@app.command("get")
def get(ctx: typer.Context, model_id: int = typer.Argument(..., help="Model ID.")) -> None:
    """Show one threat model."""
    state = get_state(ctx)
    render_item(console, state.client().models.get(model_id), state.output)
