"""``tae risks``: risk acceptance and approval (read-only in this version)."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.output import col, render_list

app = typer.Typer(help="Risk acceptance and approval.", no_args_is_help=True)

COLUMNS = [
    col("ID", "diagram_threat_id"),
    col("Threat", "threat_name", 35),
    col("Product", "product_name", 25),
    col("Diagram", "diagram_name", 25),
    col("Accepted by", "accepted_by_name"),
    col("Accepted", "accepted_at"),
    col("Review by", "acceptance_review_date"),
    col("Review", "acceptance_review_status"),
]


@app.command("pending")
def pending(
    ctx: typer.Context,
    all_: bool = typer.Option(False, "--all", help="Include risks you have already reviewed."),
) -> None:
    """List accepted risks assigned to you for approval."""
    state = get_state(ctx)
    items = state.client().approvals.mine()
    if not all_:
        items = [i for i in items if i.acceptance_review_status is None]
    render_list(console, items, COLUMNS, state.output, title="Risk acceptances awaiting your review")
