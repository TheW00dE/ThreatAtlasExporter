"""``tae pull``: save one product's data as a snapshot file."""

from __future__ import annotations

import re
from pathlib import Path

import typer

from tae.cli.common import console, err_console, get_state
from tae.cli.inputs import pull as pull_snapshot


def slugify(name: str) -> str:
    slug = re.sub(r"[^a-z0-9]+", "-", name.lower()).strip("-")
    return slug or "product"


def pull(
    ctx: typer.Context,
    product: str = typer.Option(..., "--product", "-P", help="Product ID or exact name."),
    output: Path | None = typer.Option(
        None, "--output-file", "-f", help="Snapshot file to write. [default: <product-slug>.snapshot.json]"
    ),
    stdout: bool = typer.Option(
        False, "--stdout", help="Write the snapshot JSON to standard output instead."
    ),
    quiet: bool = typer.Option(False, "--quiet", "-q", help="No progress messages."),
) -> None:
    """Pull a product's diagrams, threat models, threats and mitigations into a snapshot file.

    The snapshot is the input for `tae validate` and `tae report build`, and can be
    kept as evidence of exactly what a report was built from.
    """
    state = get_state(ctx)
    snapshot = pull_snapshot(state, product, quiet=quiet or stdout)
    if stdout:
        console.file.write(snapshot.to_json() + "\n")
        return
    path = output or Path(f"{slugify(snapshot.product.name)}.snapshot.json")
    snapshot.save(path)
    err_console.print(
        f"Saved {path}: {len(snapshot.diagrams)} diagram(s), {len(snapshot.models)} threat model(s), "
        f"{len(snapshot.diagram_threats)} threat(s), {len(snapshot.diagram_mitigations)} mitigation(s).",
        markup=False,
        highlight=False,
    )
