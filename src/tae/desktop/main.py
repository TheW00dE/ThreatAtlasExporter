"""Entry point for the ``tae-desktop`` launcher: the same as ``tae desktop``."""

from __future__ import annotations

import sys


def main() -> None:
    from tae.cli.app import app

    app(args=["desktop", *sys.argv[1:]], prog_name="tae-desktop")
