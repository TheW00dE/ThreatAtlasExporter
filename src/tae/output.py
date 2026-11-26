"""Render API objects as a table, JSON or YAML."""

from __future__ import annotations

import json
import re
from collections.abc import Callable, Iterator, Sequence
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


# Characters that can drive a terminal rather than display: C0 controls (except tab and
# newline), DEL, C1 controls, and bidirectional overrides that reorder visible text.
_UNSAFE = re.compile("[\x00-\x08\x0b-\x1f\x7f-\x9f\u202a-\u202e\u2066-\u2069]")


def safe_text(value: object) -> str:
    """Make server-supplied text safe to print to a terminal.

    Rich's markup escaping doesn't stop raw escape sequences, which could clear the
    screen, rewrite earlier lines, plant hyperlinks or write to the clipboard (OSC 52).
    They are shown as visible ``\\x1b``-style codes instead.
    """

    def show(m: re.Match[str]) -> str:
        code = ord(m.group())
        return f"\\x{code:02x}" if code < 0x100 else f"\\u{code:04x}"

    return _UNSAFE.sub(show, str(value))


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
    text = json.dumps(data, indent=2, ensure_ascii=False, default=str)
    # json escapes C0 controls but not C1 (8-bit CSI etc.) or bidi overrides; these can
    # only occur inside strings, where a \\uXXXX escape means the same thing.
    return _UNSAFE.sub(lambda m: f"\\u{ord(m.group()):04x}", text)


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
    return Text(safe_text(value))


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
    for key, value in _flatten(data, exclude or set()):
        table.add_row(Text(safe_text(key)), _cell(value))
    console.print(table)


def _flatten(data: dict[str, Any], exclude: set[str], prefix: str = "") -> Iterator[tuple[str, Any]]:
    """Rows for a key/value table: nested objects become ``parent.child`` rows."""
    for key, value in data.items():
        if not prefix and key in exclude:
            continue
        name = f"{prefix}{key}"
        if isinstance(value, dict) and value:
            yield from _flatten(value, exclude, f"{name}.")
        elif isinstance(value, list):
            if all(not isinstance(v, dict | list) for v in value):
                yield name, "; ".join(str(v) for v in value) if value else "—"
            else:
                yield name, f"{len(value)} item(s): use -o json to see them"
        else:
            yield name, value
