"""Render API objects as a table, JSON or YAML."""

from __future__ import annotations

import json
from collections.abc import Callable, Sequence
from dataclasses import dataclass
from datetime import datetime
from enum import StrEnum
from typing import Any

import yaml
from pydantic import BaseModel
from rich.console import Console
from rich.table import Table
from rich.text import Text


class OutputFormat(StrEnum):
    table = "table"
    json = "json"
    yaml = "yaml"


@dataclass(frozen=True)
class Column:
    header: str
    get: Callable[[Any], Any]
    max_width: int | None = None


def col(header: str, attr: str, max_width: int | None = None) -> Column:
    return Column(header, lambda o: getattr(o, attr, None), max_width)


def to_data(obj: Any) -> Any:
    if isinstance(obj, BaseModel):
        return obj.model_dump(mode="json")
    if isinstance(obj, list | tuple):
        return [to_data(o) for o in obj]
    return obj


def dumps(obj: Any, fmt: OutputFormat) -> str:
    data = to_data(obj)
    if fmt is OutputFormat.yaml:
        return yaml.safe_dump(data, sort_keys=False, allow_unicode=True).rstrip()
    return json.dumps(data, indent=2, ensure_ascii=False, default=str)


def print_structured(console: Console, obj: Any, fmt: OutputFormat) -> None:
    """Write JSON/YAML to stdout without Rich markup or wrapping, so it can be piped."""
    console.file.write(dumps(obj, fmt) + "\n")


def _cell(value: Any) -> Text:
    """Format a value as plain text; server data is never interpreted as Rich markup."""
    if value is None:
        return Text("—", style="dim")
    if isinstance(value, bool):
        return Text("yes" if value else "no")
    if isinstance(value, datetime):
        return Text(value.strftime("%Y-%m-%d %H:%M"))
    return Text(str(value))


def render_list(
    console: Console,
    items: Sequence[Any],
    columns: Sequence[Column],
    fmt: OutputFormat,
    *,
    title: str | None = None,
) -> None:
    if fmt is not OutputFormat.table:
        print_structured(console, items, fmt)
        return
    if not items:
        console.print(f"[dim]No {title.lower() if title else 'results'} found.[/dim]")
        return
    table = Table(title=title, title_justify="left", header_style="bold")
    for c in columns:
        table.add_column(c.header, max_width=c.max_width, overflow="fold")
    for item in items:
        table.add_row(*(_cell(c.get(item)) for c in columns))
    console.print(table)


def render_item(console: Console, item: Any, fmt: OutputFormat, *, exclude: set[str] | None = None) -> None:
    if fmt is not OutputFormat.table:
        print_structured(console, item, fmt)
        return
    data = to_data(item)
    table = Table(show_header=False, box=None, pad_edge=False)
    table.add_column(style="bold")
    table.add_column(overflow="fold")
    for key, value in data.items():
        if exclude and key in exclude:
            continue
        if isinstance(value, dict | list):
            text = json.dumps(value, ensure_ascii=False)
            value = text if len(text) <= 120 else f"<{type(value).__name__}: use -o json to see it>"
        table.add_row(Text(key), _cell(value))
    console.print(table)
