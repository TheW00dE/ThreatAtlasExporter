"""``tae products``."""

from __future__ import annotations

import typer

from tae.cli.common import ExitCode, console, err_console, get_state
from tae.output import OutputFormat, col, render_item, render_list

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
def security_status(
    ctx: typer.Context,
    product_id: int = typer.Argument(..., help="Product ID."),
    fail_on_critical: bool = typer.Option(
        False, "--fail-on-critical", help="Fail if any critical threat exists."
    ),
    fail_on_unmitigated_high: bool = typer.Option(
        False,
        "--fail-on-unmitigated-high",
        help="Fail if a high or critical threat has no active mitigation.",
    ),
    min_mitigation_ratio: float | None = typer.Option(
        None,
        "--min-mitigation-ratio",
        min=0.0,
        max=1.0,
        help="Fail below this share of mitigated threats (0-1).",
    ),
) -> None:
    """ThreatAtlas's own security check for a product, with optional pass/fail thresholds.

    Without thresholds ThreatAtlas only reports counts and always passes. Exits with
    code 10 when a threshold is not met, so it can gate a CI pipeline.
    """
    state = get_state(ctx)
    status = state.client().products.security_status(
        product_id,
        fail_on_critical=fail_on_critical,
        fail_on_unmitigated_high=fail_on_unmitigated_high,
        min_mitigation_ratio=min_mitigation_ratio,
    )
    render_item(console, status, state.output)
    thresholds = fail_on_critical or fail_on_unmitigated_high or min_mitigation_ratio is not None
    if state.output is OutputFormat.table and not thresholds:
        err_console.print(
            "No thresholds given, so this always passes. Add --fail-on-critical, "
            "--fail-on-unmitigated-high or --min-mitigation-ratio to check against them.",
            markup=False,
            style="dim",
        )
    if status.get("pass") is False:
        raise typer.Exit(int(ExitCode.CHECKS_FAILED))
