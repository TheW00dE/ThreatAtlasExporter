"""``tae diagrams``."""

from __future__ import annotations

import typer

from tae.cli.common import console, get_state
from tae.output import Column, OutputFormat, col, render_item, render_list

app = typer.Typer(help="Data flow diagrams.", no_args_is_help=True)
versions_app = typer.Typer(help="Diagram version history.", no_args_is_help=True)
app.add_typer(versions_app, name="versions")

COLUMNS = [
    col("ID", "id"),
    col("Name", "name", 40),
    col("Product", "product_id"),
    Column("Nodes", lambda d: len(d.nodes)),
    Column("Edges", lambda d: len(d.edges)),
    col("Version", "current_version"),
    col("Updated", "updated_at"),
]

VERSION_COLUMNS = [
    col("Version", "version_number"),
    col("Name", "name", 30),
    col("Comment", "comment", 40),
    col("Nodes", "node_count"),
    col("Edges", "edge_count"),
    col("Threats", "threat_count"),
    col("Mitigations", "mitigation_count"),
    col("Created", "created_at"),
]


@app.command("list")
def list_(
    ctx: typer.Context,
    product: int | None = typer.Option(None, "--product", "-P", help="Only diagrams in this product."),
) -> None:
    """List diagrams."""
    state = get_state(ctx)
    render_list(console, state.client().diagrams.list(product), COLUMNS, state.output, title="Diagrams")


@app.command("get")
def get(ctx: typer.Context, diagram_id: int = typer.Argument(..., help="Diagram ID.")) -> None:
    """Show one diagram. Use -o json to include the full node/edge data."""
    state = get_state(ctx)
    diagram = state.client().diagrams.get(diagram_id)
    if state.output is OutputFormat.table:
        render_item(console, diagram, state.output, exclude={"diagram_data"})
        console.print(
            f"[dim]{len(diagram.nodes)} nodes, {len(diagram.edges)} edges (use -o json for data)[/dim]"
        )
    else:
        render_item(console, diagram, state.output)


@versions_app.command("list")
def versions_list(ctx: typer.Context, diagram_id: int = typer.Argument(..., help="Diagram ID.")) -> None:
    """List saved versions of a diagram."""
    state = get_state(ctx)
    items = state.client().diagram_versions.list(diagram_id)
    render_list(console, items, VERSION_COLUMNS, state.output, title="Versions")


@versions_app.command("show")
def versions_show(
    ctx: typer.Context,
    diagram_id: int = typer.Argument(..., help="Diagram ID."),
    version: int = typer.Argument(..., help="Version number."),
) -> None:
    """Show one saved version, including its threat and mitigation snapshot (-o json)."""
    state = get_state(ctx)
    render_item(console, state.client().diagram_versions.get(diagram_id, version), state.output)
