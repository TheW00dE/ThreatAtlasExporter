"""Render a ThreatAtlas data flow diagram (ReactFlow nodes/edges) as print-friendly SVG.

Shapes follow ThreatAtlas's own export: processes are circles, data stores are
open-ended parallel lines, external entities are rectangles, and trust boundaries
are dashed rectangles drawn behind everything. Optional badges show how many
threats sit on each element, coloured by the most severe one.
"""

from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any
from xml.sax.saxutils import escape

from tae.snapshot.view import DiagramView, Element

PADDING = 40.0
FONT = "DejaVu Sans, Liberation Sans, Arial, sans-serif"

NODE_SIZES: dict[str, tuple[float, float]] = {
    "process": (96.0, 96.0),
    "datastore": (140.0, 40.0),
    "external": (120.0, 44.0),
    "boundary": (200.0, 150.0),
}
DEFAULT_SIZE = NODE_SIZES["external"]

COLORS = {
    "process": "#2563eb",
    "datastore": "#059669",
    "external": "#d97706",
    "boundary": "#6b7280",
    "unknown": "#6b7280",
}
SEVERITY_COLORS = {
    "critical": "#b91c1c",
    "high": "#ea580c",
    "medium": "#ca8a04",
    "low": "#16a34a",
    None: "#6b7280",
}
EDGE_COLOR = "#4b5563"
TEXT_COLOR = "#111827"


@dataclass
class Box:
    x: float
    y: float
    w: float
    h: float

    @property
    def cx(self) -> float:
        return self.x + self.w / 2

    @property
    def cy(self) -> float:
        return self.y + self.h / 2


def _num(value: Any) -> float | None:
    if isinstance(value, bool):
        return None
    if isinstance(value, int | float):
        return float(value)
    if isinstance(value, str):
        v = value.strip().removesuffix("px")
        try:
            return float(v)
        except ValueError:
            return None
    return None


def node_size(e: Element) -> tuple[float, float]:
    raw = e.raw
    default = NODE_SIZES.get(e.type, DEFAULT_SIZE)
    candidates = [
        (raw.get("width"), raw.get("height")),
        ((raw.get("measured") or {}).get("width"), (raw.get("measured") or {}).get("height")),
        ((raw.get("style") or {}).get("width"), (raw.get("style") or {}).get("height")),
    ]
    w = next((n for c in candidates if (n := _num(c[0])) is not None and n > 0), default[0])
    h = next((n for c in candidates if (n := _num(c[1])) is not None and n > 0), default[1])
    return w, h


def _position(e: Element) -> tuple[float, float]:
    pos = e.raw.get("position") or {}
    return _num(pos.get("x")) or 0.0, _num(pos.get("y")) or 0.0


def layout(view: DiagramView) -> dict[str, Box]:
    """Absolute boxes for every node, resolving parentId chains and growing boundaries."""
    nodes = {e.id: e for e in view.nodes}
    sizes = {nid: node_size(e) for nid, e in nodes.items()}

    # Grow boundaries to contain their children (relative coordinates).
    for nid, e in nodes.items():
        if not e.is_boundary:
            continue
        w, h = sizes[nid]
        for child in nodes.values():
            if child.parent_id == nid:
                cx, cy = _position(child)
                cw, ch = sizes[child.id]
                w = max(w, cx + cw + PADDING)
                h = max(h, cy + ch + PADDING)
        sizes[nid] = (w, h)

    absolute: dict[str, tuple[float, float]] = {}

    def resolve(nid: str, seen: frozenset[str] = frozenset()) -> tuple[float, float]:
        if nid in absolute:
            return absolute[nid]
        e = nodes[nid]
        x, y = _position(e)
        parent = e.parent_id
        if parent and parent != nid and parent in nodes and parent not in seen:
            px, py = resolve(parent, seen | {nid})
            x, y = x + px, y + py
        absolute[nid] = (x, y)
        return absolute[nid]

    boxes: dict[str, Box] = {}
    for nid in nodes:
        x, y = resolve(nid)
        w, h = sizes[nid]
        boxes[nid] = Box(x, y, w, h)
    return boxes


def _boundary_point(box: Box, shape: str, tx: float, ty: float) -> tuple[float, float]:
    dx, dy = tx - box.cx, ty - box.cy
    length = math.hypot(dx, dy) or 1.0
    if shape == "process":
        r = min(box.w, box.h) / 2
        return box.cx + dx / length * r, box.cy + dy / length * r
    hw, hh = box.w / 2, box.h / 2
    scale = hw / (abs(dx) or 1.0) if abs(dx) * hh > abs(dy) * hw else hh / (abs(dy) or 1.0)
    return box.cx + dx * scale, box.cy + dy * scale


def _wrap(text: str, max_width: float, font_size: float, max_lines: int = 3) -> list[str]:
    char_w = font_size * 0.58
    words = text.split()
    lines: list[str] = []
    current = ""
    for word in words:
        candidate = f"{current} {word}".strip()
        if len(candidate) * char_w > max_width and current:
            lines.append(current)
            current = word
        else:
            current = candidate
    if current:
        lines.append(current)
    if len(lines) > max_lines:
        lines = lines[:max_lines]
        lines[-1] = lines[-1][: max(1, int(max_width / char_w) - 1)] + "…"
    return lines or [""]


def _text_block(lines: list[str], cx: float, cy: float, size: float, color: str = TEXT_COLOR) -> str:
    line_h = size * 1.2
    top = cy - (len(lines) - 1) * line_h / 2
    out = []
    for i, line in enumerate(lines):
        out.append(
            f'<text x="{cx:.1f}" y="{top + i * line_h:.1f}" dy="0.35em" font-size="{size}" '
            f'font-family="{FONT}" fill="{color}" text-anchor="middle">{escape(line)}</text>'
        )
    return "".join(out)


def _badge(x: float, y: float, count: int, severity: str | None) -> str:
    color = SEVERITY_COLORS.get(severity, SEVERITY_COLORS[None])
    return (
        f'<circle cx="{x:.1f}" cy="{y:.1f}" r="9" fill="{color}" stroke="#ffffff" stroke-width="1.5"/>'
        f'<text x="{x:.1f}" y="{y:.1f}" dy="0.35em" font-size="9" font-weight="bold" font-family="{FONT}" '
        f'fill="#ffffff" text-anchor="middle">{count}</text>'
    )


def _worst(view: DiagramView, element_id: str) -> tuple[int, str | None]:
    threats = view.threats_on(element_id)
    if not threats:
        return 0, None
    worst = max(threats, key=lambda t: t.severity_rank)
    return len(threats), worst.severity


def render_svg(view: DiagramView, *, annotate_threats: bool = True) -> str | None:
    """Return SVG markup, or ``None`` if the diagram has no nodes."""
    boxes = layout(view)
    if not boxes:
        return None
    nodes = {e.id: e for e in view.nodes}
    edges = [e for e in view.edges if e.source in boxes and e.target in boxes]

    # Edge geometry first, so labels count towards the bounding box.
    pair_groups: dict[tuple[str, str], list[Element]] = {}
    for edge in edges:
        key = tuple(sorted((edge.source or "", edge.target or "")))
        pair_groups.setdefault(key, []).append(edge)  # type: ignore[arg-type]

    edge_geo: list[tuple[Element, tuple[float, float], tuple[float, float], tuple[float, float], bool]] = []
    for group in pair_groups.values():
        mid = (len(group) - 1) / 2
        for i, edge in enumerate(group):
            src, tgt = boxes[edge.source or ""], boxes[edge.target or ""]
            if edge.source == edge.target:
                continue  # self-loops are not drawn
            start = _boundary_point(src, nodes[edge.source or ""].type, tgt.cx, tgt.cy)
            end = _boundary_point(tgt, nodes[edge.target or ""].type, src.cx, src.cy)
            dx, dy = end[0] - start[0], end[1] - start[1]
            length = math.hypot(dx, dy) or 1.0
            offset = (i - mid) * 40
            ctrl = (
                (start[0] + end[0]) / 2 - dy / length * offset,
                (start[1] + end[1]) / 2 + dx / length * offset,
            )
            edge_geo.append((edge, start, end, ctrl, len(group) > 1))

    min_x = min(b.x for b in boxes.values())
    min_y = min(b.y for b in boxes.values())
    max_x = max(b.x + b.w for b in boxes.values())
    max_y = max(b.y + b.h for b in boxes.values())
    for _edge, _s, _e, ctrl, _curved in edge_geo:
        min_x, max_x = min(min_x, ctrl[0] - 70), max(max_x, ctrl[0] + 70)
        min_y, max_y = min(min_y, ctrl[1] - 16), max(max_y, ctrl[1] + 16)

    ox, oy = PADDING - min_x, PADDING - min_y
    width, height = max_x - min_x + 2 * PADDING, max_y - min_y + 2 * PADDING

    def sx(v: float) -> float:
        return v + ox

    def sy(v: float) -> float:
        return v + oy

    parts: list[str] = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width:.0f}" height="{height:.0f}" '
        f'viewBox="0 0 {width:.0f} {height:.0f}">',
        "<defs>"
        '<marker id="arrow" markerWidth="10" markerHeight="7" refX="9" refY="3.5" orient="auto">'
        f'<polygon points="0 0, 10 3.5, 0 7" fill="{EDGE_COLOR}"/></marker>'
        "</defs>",
        f'<rect x="0" y="0" width="{width:.0f}" height="{height:.0f}" fill="#ffffff"/>',
    ]

    # Trust boundaries (outermost first so nested ones draw on top).
    boundaries = sorted(
        (e for e in nodes.values() if e.is_boundary), key=lambda e: -boxes[e.id].w * boxes[e.id].h
    )
    for e in boundaries:
        b = boxes[e.id]
        color = COLORS["boundary"]
        parts.append(
            f'<rect x="{sx(b.x):.1f}" y="{sy(b.y):.1f}" width="{b.w:.1f}" height="{b.h:.1f}" rx="6" '
            f'fill="#f9fafb" fill-opacity="0.6" stroke="{color}" stroke-width="1.5" stroke-dasharray="7 4"/>'
            f'<text x="{sx(b.x) + 8:.1f}" y="{sy(b.y) + 15:.1f}" font-size="10" font-style="italic" '
            f'font-family="{FONT}" fill="{color}">{escape(e.label)}</text>'
        )

    # Data flows.
    for edge, start, end, ctrl, curved in edge_geo:
        x1, y1, x2, y2 = sx(start[0]), sy(start[1]), sx(end[0]), sy(end[1])
        cx, cy = sx(ctrl[0]), sy(ctrl[1])
        if curved:
            parts.append(
                f'<path d="M {x1:.1f},{y1:.1f} Q {cx:.1f},{cy:.1f} {x2:.1f},{y2:.1f}" fill="none" '
                f'stroke="{EDGE_COLOR}" stroke-width="1.2" marker-end="url(#arrow)"/>'
            )
            lx, ly = (x1 + 2 * cx + x2) / 4, (y1 + 2 * cy + y2) / 4  # point on the curve at t=0.5
        else:
            parts.append(
                f'<line x1="{x1:.1f}" y1="{y1:.1f}" x2="{x2:.1f}" y2="{y2:.1f}" stroke="{EDGE_COLOR}" '
                f'stroke-width="1.2" marker-end="url(#arrow)"/>'
            )
            lx, ly = (x1 + x2) / 2, (y1 + y2) / 2
        label = edge.label if edge.label != edge.id else ""
        if label:
            text = label if len(label) <= 28 else label[:26] + "…"
            tw = len(text) * 5.4 + 8
            parts.append(
                f'<rect x="{lx - tw / 2:.1f}" y="{ly - 8:.1f}" width="{tw:.1f}" height="16" rx="3" '
                f'fill="#ffffff" fill-opacity="0.9"/>'
            )
            parts.append(_text_block([text], lx, ly, 9, "#374151"))
        if annotate_threats:
            count, sev = _worst(view, edge.id)
            if count:
                bx = lx + (len(label[:28]) * 2.7 + 14 if label else 12)
                parts.append(_badge(bx, ly - 8, count, sev))

    # Nodes.
    for e in nodes.values():
        if e.is_boundary:
            continue
        b = boxes[e.id]
        x, y = sx(b.x), sy(b.y)
        color = COLORS.get(e.type, COLORS["unknown"])
        if e.type == "process":
            r = min(b.w, b.h) / 2
            cx, cy = x + b.w / 2, y + b.h / 2
            parts.append(
                f'<circle cx="{cx:.1f}" cy="{cy:.1f}" r="{r:.1f}" fill="#eff6ff" '
                f'stroke="{color}" stroke-width="2"/>'
            )
            parts.append(_text_block(_wrap(e.label, r * 1.5, 10), cx, cy, 10))
            badge_at = (cx + r * 0.72, cy - r * 0.72)
        elif e.type == "datastore":
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{b.w:.1f}" height="{b.h:.1f}" '
                f'fill="#ecfdf5" stroke="none"/>'
                f'<line x1="{x:.1f}" y1="{y:.1f}" x2="{x + b.w:.1f}" y2="{y:.1f}" '
                f'stroke="{color}" stroke-width="2"/>'
                f'<line x1="{x:.1f}" y1="{y + b.h:.1f}" x2="{x + b.w:.1f}" y2="{y + b.h:.1f}" '
                f'stroke="{color}" stroke-width="2"/>'
            )
            parts.append(_text_block(_wrap(e.label, b.w - 10, 10, 2), x + b.w / 2, y + b.h / 2, 10))
            badge_at = (x + b.w, y)
        else:
            dash = ' stroke-dasharray="3 3"' if e.type not in COLORS else ""
            parts.append(
                f'<rect x="{x:.1f}" y="{y:.1f}" width="{b.w:.1f}" height="{b.h:.1f}" rx="3" fill="#fffbeb" '
                f'stroke="{color}" stroke-width="2"{dash}/>'
            )
            parts.append(_text_block(_wrap(e.label, b.w - 10, 10, 2), x + b.w / 2, y + b.h / 2, 10))
            badge_at = (x + b.w, y)
        if annotate_threats:
            count, sev = _worst(view, e.id)
            if count:
                parts.append(_badge(badge_at[0], badge_at[1], count, sev))

    parts.append("</svg>")
    return "".join(parts)


def legend_svg() -> str:
    """A small key explaining the shapes and badge colours."""
    items = [
        f'<circle cx="14" cy="14" r="9" fill="#eff6ff" stroke="{COLORS["process"]}" stroke-width="2"/>'
        f'<text x="30" y="14" dy="0.35em" font-size="9" font-family="{FONT}">Process</text>',
        f'<line x1="90" y1="8" x2="118" y2="8" stroke="{COLORS["datastore"]}" stroke-width="2"/>'
        f'<line x1="90" y1="20" x2="118" y2="20" stroke="{COLORS["datastore"]}" stroke-width="2"/>'
        f'<text x="124" y="14" dy="0.35em" font-size="9" font-family="{FONT}">Data store</text>',
        f'<rect x="190" y="6" width="26" height="16" rx="2" fill="#fffbeb" stroke="{COLORS["external"]}" '
        f'stroke-width="2"/><text x="222" y="14" dy="0.35em" font-size="9" font-family="{FONT}">'
        "External entity</text>",
        f'<rect x="310" y="5" width="26" height="18" rx="3" fill="none" stroke="{COLORS["boundary"]}" '
        f'stroke-dasharray="5 3"/><text x="342" y="14" dy="0.35em" font-size="9" font-family="{FONT}">'
        "Trust boundary</text>",
    ]
    x = 430.0
    for sev in ("critical", "high", "medium", "low"):
        items.append(_badge(x, 14, 1, sev).replace(">1<", "><"))
        items.append(f'<text x="{x + 13}" y="14" dy="0.35em" font-size="9" font-family="{FONT}">{sev}</text>')
        x += 13 + len(sev) * 5.5 + 14
    return (
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{x:.0f}" height="28" viewBox="0 0 {x:.0f} 28">'
        + "".join(items)
        + "</svg>"
    )
