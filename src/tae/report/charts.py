"""Small SVG charts for the executive summary."""

from __future__ import annotations

from xml.sax.saxutils import escape

from tae.report.diagram_svg import FONT, SEVERITY_COLORS


def severity_bars(counts: dict[str, tuple[int, int]], width: int = 460) -> str:
    """Horizontal bars per severity: total threats, with the open share darker.

    ``counts`` maps severity → (open, total).
    """
    rows = [s for s in ("critical", "high", "medium", "low", "unscored") if s in counts]
    label_w, row_h, gap = 70, 18, 8
    bar_max = width - label_w - 70
    biggest = max((total for _o, total in counts.values()), default=0) or 1
    height = len(rows) * (row_h + gap) + gap
    parts = [
        f'<svg xmlns="http://www.w3.org/2000/svg" width="{width}" height="{height}" '
        f'viewBox="0 0 {width} {height}">'
    ]
    for i, sev in enumerate(rows):
        open_n, total = counts[sev]
        y = gap + i * (row_h + gap)
        color = SEVERITY_COLORS.get(None if sev == "unscored" else sev, SEVERITY_COLORS[None])
        total_w = bar_max * total / biggest
        open_w = bar_max * open_n / biggest
        parts.append(
            f'<text x="{label_w - 8}" y="{y + row_h / 2}" dy="0.35em" font-size="10" font-family="{FONT}" '
            f'text-anchor="end" fill="#111827">{escape(sev.capitalize())}</text>'
        )
        parts.append(
            f'<rect x="{label_w}" y="{y}" width="{max(total_w, 1):.1f}" height="{row_h}" rx="2" '
            f'fill="{color}" fill-opacity="0.3"/>'
        )
        if open_n:
            parts.append(
                f'<rect x="{label_w}" y="{y}" width="{open_w:.1f}" height="{row_h}" rx="2" fill="{color}"/>'
            )
        parts.append(
            f'<text x="{label_w + total_w + 6:.1f}" y="{y + row_h / 2}" dy="0.35em" font-size="10" '
            f'font-family="{FONT}" fill="#374151">{total} ({open_n} open)</text>'
        )
    parts.append("</svg>")
    return "".join(parts)
