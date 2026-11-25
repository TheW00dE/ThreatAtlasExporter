"""``tae products``."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.output import col, render_item, render_list

app = typer.Typer(
    help="Products: the top-level container for diagrams and threat models.", no_args_is_help=True
)

COLUMNS = [
    col("ID", "id"),
    col("Name", "name", 40),
    col("Status", "status"),
    col("Owner", "owner_name", 25),
    col("Business area", "business_area", 25),
    col("Public", "is_public"),
    col("Editable", "can_edit"),
    col("Updated", "updated_at"),
]


@app.command("list")
def list_(ctx: typer.Context) -> None:
    """List products visible to you."""
    state = get_state(ctx)
    render_list(console, state.client().products.list(), COLUMNS, state.output, title="Products")


@app.command("get")
def get(ctx: typer.Context, product_id: int = typer.Argument(..., help="Product ID.")) -> None:
    """Show one product."""
    state = get_state(ctx)
    render_item(console, state.client().products.get(product_id), state.output)


@app.command("security-status")
def security_status(ctx: typer.Context, product_id: int = typer.Argument(..., help="Product ID.")) -> None:
    """Show ThreatAtlas's own security status summary for a product."""
    state = get_state(ctx)
    render_item(console, state.client().products.security_status(product_id), state.output)
