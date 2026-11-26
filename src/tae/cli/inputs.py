"""Helpers for commands that take either a snapshot file or a live product."""

from __future__ import annotations

from pathlib import Path

from rich.text import Text

from tae.cli.common import ExitCode, State, err_console, fail
from tae.output import safe_text
from tae.snapshot import Snapshot
from tae.snapshot.collector import collect, resolve_product


def obtain_snapshot(state: State, snapshot: Path | None, product: str | None) -> Snapshot:
    """Load ``snapshot`` from disk, or pull ``product`` from the server."""
    if snapshot is not None and product is not None:
        fail("Give either a snapshot file or --product, not both.", ExitCode.USAGE)
    if snapshot is not None:
        return Snapshot.load(snapshot)
    if product is None:
        fail("Give a snapshot file (from `tae pull`) or --product ID|NAME to pull live.", ExitCode.USAGE)
    return pull(state, product)


def pull(state: State, product_ref: str, *, quiet: bool = False) -> Snapshot:
    client = state.client()
    product = resolve_product(client, product_ref)

    def progress(message: str) -> None:
        if not quiet:
            # Progress messages include diagram names from the server.
            err_console.print(Text(f"{safe_text(message)}…", style="dim"), highlight=False)

    return collect(client, product, progress)
