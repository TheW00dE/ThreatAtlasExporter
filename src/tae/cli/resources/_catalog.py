"""Command builder shared by ``tae threats`` and ``tae mitigations``.

Both have the same two levels: catalog entries (the knowledge base), and instances
of those entries attached to diagram elements.
"""

from __future__ import annotations

from collections.abc import Callable, Sequence
from typing import Any

import typer

from tae.cli.common import console, get_state
from tae.client import ThreatAtlasClient
from tae.output import Column, col, render_item, render_list

CATALOG_COLUMNS = [
    col("ID", "id"),
    col("Name", "name", 45),
    col("Category", "category", 25),
    col("Framework", "framework_id"),
    col("Custom", "is_custom"),
    col("Modified", "is_modified"),
]


def build(
    *,
    noun: str,
    catalog: Callable[[ThreatAtlasClient], Any],
    instances: Callable[[ThreatAtlasClient], Any],
    instance_columns: Sequence[Column],
) -> typer.Typer:
    plural = f"{noun}s"
    app = typer.Typer(
        help=f"{plural.capitalize()}: the catalog, and {plural} on diagrams.", no_args_is_help=True
    )
    catalog_app = typer.Typer(help=f"The {noun} knowledge base.", no_args_is_help=True)
    app.add_typer(catalog_app, name="catalog")

    @catalog_app.command("list")
    def catalog_list(
        ctx: typer.Context,
        framework: int | None = typer.Option(None, "--framework", "-f", help="Only this framework ID."),
        custom: bool | None = typer.Option(
            None, "--custom/--builtin", help="Only custom or only built-in entries.", show_default=False
        ),
    ) -> None:
        state = get_state(ctx)
        items = catalog(state.client()).list(framework, custom)
        render_list(console, items, CATALOG_COLUMNS, state.output, title=f"{noun.capitalize()} catalog")

    catalog_list.__doc__ = f"List catalog {plural}."

    @catalog_app.command("get")
    def catalog_get(ctx: typer.Context, item_id: int = typer.Argument(..., help="Catalog ID.")) -> None:
        state = get_state(ctx)
        render_item(console, catalog(state.client()).get(item_id), state.output)

    catalog_get.__doc__ = f"Show one catalog {noun}."

    @app.command("list")
    def instance_list(
        ctx: typer.Context,
        diagram: int | None = typer.Option(None, "--diagram", "-d", help="Diagram ID."),
        model: int | None = typer.Option(None, "--model", "-m", help="Threat model ID."),
        element: str | None = typer.Option(None, "--element", "-e", help="Diagram element (node/edge) ID."),
    ) -> None:
        state = get_state(ctx)
        items = instances(state.client()).list(diagram, model, element)
        render_list(console, items, instance_columns, state.output, title=f"Diagram {plural}")

    instance_list.__doc__ = f"List {plural} identified on diagrams."

    @app.command("get")
    def instance_get(
        ctx: typer.Context, item_id: int = typer.Argument(..., help=f"Diagram {noun} ID.")
    ) -> None:
        state = get_state(ctx)
        render_item(console, instances(state.client()).get(item_id), state.output)

    instance_get.__doc__ = f"Show one {noun} on a diagram, with its catalog entry."

    return app
