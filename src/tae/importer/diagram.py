"""Turn a YAML diagram (elements and flows) into ThreatAtlas's React Flow diagram data.

The output matches what ThreatAtlas's own editor and templates produce:

- nodes are ``type: custom`` with ``data.label`` and ``data.type`` (process, datastore,
  external, boundary); boundaries carry ``width``/``height`` and sit behind (zIndex -1);
- edges are ``type: custom``, animated, with explicit ``sourceHandle``/``targetHandle``
  chosen from the nodes' relative positions, and the label in ``data.label``.

Positions come from the YAML if given, otherwise from the existing diagram (so a
layout tidied up in the ThreatAtlas editor survives a re-import), otherwise from a
simple left-to-right layout that follows the data flows.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any

from tae.importer.schema import DiagramEntry, Element

NODE_SIZES = {"process": (96.0, 96.0), "datastore": (140.0, 40.0), "external": (120.0, 44.0)}
COLUMN_GAP = 240.0
ROW_GAP = 150.0
ORIGIN = (80.0, 80.0)
BOUNDARY_PAD = 40.0
BOUNDARY_LABEL = 30.0
DEFAULT_BOUNDARY = (200.0, 150.0)


@dataclass
class BuildResult:
    data: dict[str, Any]
    kept: list[str]  # IDs of nodes/edges kept from the existing diagram that the YAML doesn't define
    removed: list[str]  # IDs removed because they're not in the YAML (only with prune)


def _existing(
    diagram_data: dict[str, Any] | None,
) -> tuple[dict[str, dict[str, Any]], dict[str, dict[str, Any]]]:
    data = diagram_data or {}
    nodes = {str(n["id"]): n for n in data.get("nodes") or [] if isinstance(n, dict) and "id" in n}
    edges = {str(e["id"]): e for e in data.get("edges") or [] if isinstance(e, dict) and "id" in e}
    return nodes, edges


def _pos(node: dict[str, Any]) -> tuple[float, float] | None:
    p = node.get("position")
    if isinstance(p, dict) and isinstance(p.get("x"), int | float) and isinstance(p.get("y"), int | float):
        return float(p["x"]), float(p["y"])
    return None


def _layers(diagram: DiagramEntry, ids: list[str]) -> dict[str, int]:
    """Longest-path layering along the flows (cycles are cut by visiting order)."""
    succ: dict[str, list[str]] = {i: [] for i in ids}
    indeg = dict.fromkeys(ids, 0)
    for f in diagram.flows:
        if f.from_ in succ and f.to in succ and f.from_ != f.to:
            succ[f.from_].append(f.to)
            indeg[f.to] += 1
    layer = dict.fromkeys(ids, 0)
    queue = [i for i in ids if indeg[i] == 0]
    seen: set[str] = set()
    while queue or len(seen) < len(ids):
        if not queue:  # a cycle: start from the first unvisited element
            queue = [next(i for i in ids if i not in seen)]
        node = queue.pop(0)
        if node in seen:
            continue
        seen.add(node)
        for nxt in succ[node]:
            if nxt not in seen:
                layer[nxt] = max(layer[nxt], layer[node] + 1)
                indeg[nxt] -= 1
                if indeg[nxt] <= 0:
                    queue.append(nxt)
    return layer


def _boundary_path(e: Element, elements: dict[str, Element]) -> tuple[str, ...]:
    path: list[str] = []
    current = e.boundary
    while current is not None:
        path.insert(0, current)
        current = elements[current].boundary
    return tuple(path)


def _auto_positions(
    diagram: DiagramEntry, todo: list[Element], top: float = ORIGIN[1]
) -> dict[str, tuple[float, float]]:
    """Columns follow the data flows; each trust-boundary group gets its own band of rows,
    so a boundary box only ever encloses its own members."""
    if not todo:
        return {}
    elements = {e.id: e for e in diagram.elements}
    layer = _layers(diagram, [e.id for e in todo])
    order = {e.id: i for i, e in enumerate(diagram.elements)}
    groups: dict[tuple[str, ...], list[Element]] = {}
    for e in todo:
        groups.setdefault(_boundary_path(e, elements), []).append(e)
    positions: dict[str, tuple[float, float]] = {}
    y = top + BOUNDARY_LABEL
    # Elements outside boundaries first, then boundary groups with nested ones together.
    for path in sorted(groups, key=lambda p: (len(p) > 0, [order[b] for b in p])):
        columns: dict[int, list[Element]] = {}
        for e in groups[path]:
            columns.setdefault(layer[e.id], []).append(e)
        rows = 0
        for col, members in columns.items():
            members.sort(key=lambda e: order[e.id])
            for row, e in enumerate(members):
                positions[e.id] = (ORIGIN[0] + col * COLUMN_GAP, y + row * ROW_GAP)
            rows = max(rows, len(members))
        y += rows * ROW_GAP + 2 * BOUNDARY_PAD + BOUNDARY_LABEL
    return positions


def _handles(
    src: tuple[float, float, float, float], dst: tuple[float, float, float, float]
) -> tuple[str, str]:
    """Pick facing sides, as ThreatAtlas asks for (right/left, bottom/top, ...)."""
    sx, sy = src[0] + src[2] / 2, src[1] + src[3] / 2
    dx, dy = dst[0] + dst[2] / 2, dst[1] + dst[3] / 2
    if abs(dx - sx) >= abs(dy - sy):
        return ("source-right", "target-left") if dx >= sx else ("source-left", "target-right")
    return ("source-bottom", "target-top") if dy >= sy else ("source-top", "target-bottom")


def build_diagram_data(
    diagram: DiagramEntry, existing: dict[str, Any] | None = None, *, prune: bool = False
) -> BuildResult:
    old_nodes, old_edges = _existing(existing)
    elements = {e.id: e for e in diagram.elements}

    # 1. Positions of ordinary elements: YAML, else existing, else automatic.
    positions: dict[str, tuple[float, float]] = {}
    todo: list[Element] = []
    for e in diagram.elements:
        if e.type == "boundary":
            continue
        if e.position is not None:
            positions[e.id] = e.position
        elif e.id in old_nodes and _pos(old_nodes[e.id]) is not None:
            positions[e.id] = _pos(old_nodes[e.id])  # type: ignore[assignment]
        else:
            todo.append(e)
    # New elements go below anything already placed, so they never land on top of it.
    placed_bottom = max(
        (y + NODE_SIZES[elements[eid].type][1] for eid, (_, y) in positions.items()), default=None
    )
    top = ORIGIN[1] if placed_bottom is None else placed_bottom + ROW_GAP
    positions.update(_auto_positions(diagram, todo, top))

    boxes: dict[str, tuple[float, float, float, float]] = {}
    for eid, (x, y) in positions.items():
        w, h = NODE_SIZES[elements[eid].type]
        boxes[eid] = (x, y, w, h)

    # 2. Boundaries, innermost first, fitted around their members unless sized in YAML.
    def depth(e: Element) -> int:
        d, cur = 0, e.boundary
        while cur is not None:
            d += 1
            cur = elements[cur].boundary
        return d

    boundaries = sorted((e for e in diagram.elements if e.type == "boundary"), key=depth, reverse=True)
    for b in boundaries:
        members = [boxes[m.id] for m in diagram.elements if m.boundary == b.id and m.id in boxes]
        old = old_nodes.get(b.id, {})
        if b.size is not None:
            x, y = b.position or _pos(old) or ORIGIN
            boxes[b.id] = (x, y, b.size[0], b.size[1])
        elif members:
            left = min(m[0] for m in members) - BOUNDARY_PAD
            top = min(m[1] for m in members) - BOUNDARY_PAD - BOUNDARY_LABEL / 2
            right = max(m[0] + m[2] for m in members) + BOUNDARY_PAD
            bottom = max(m[1] + m[3] for m in members) + BOUNDARY_PAD
            if b.position is not None:
                left, top = b.position
            boxes[b.id] = (left, top, right - left, bottom - top)
        else:
            x, y = b.position or _pos(old) or ORIGIN
            boxes[b.id] = (x, y, *DEFAULT_BOUNDARY)

    # 3. Nodes: boundaries first (drawn behind), keeping unknown fields of existing nodes.
    nodes: list[dict[str, Any]] = []
    for e in [*boundaries[::-1], *(e for e in diagram.elements if e.type != "boundary")]:
        x, y, w, h = boxes[e.id]
        node = copy.deepcopy(old_nodes.get(e.id, {}))
        node.pop("parentId", None)  # positions here are absolute
        node.pop("parentNode", None)
        data = dict(node.get("data") or {})
        data.update(label=e.label, type=e.type)
        node.update(id=e.id, type="custom", position={"x": round(x, 1), "y": round(y, 1)}, data=data)
        if e.type == "boundary":
            node.update(width=round(w, 1), height=round(h, 1), zIndex=-1)
        nodes.append(node)

    # 4. Edges, keeping unknown fields (e.g. a label dragged aside in the editor).
    edges: list[dict[str, Any]] = []
    for f in diagram.flows:
        edge = copy.deepcopy(old_edges.get(f.id, {}))
        source_handle, target_handle = _handles(boxes[f.from_], boxes[f.to])
        data = dict(edge.get("data") or {})
        if f.label:
            data["label"] = f.label
        else:
            data.pop("label", None)
        edge.pop("label", None)
        edge.update(
            id=f.id,
            source=f.from_,
            target=f.to,
            type="custom",
            animated=True,
            sourceHandle=source_handle,
            targetHandle=target_handle,
            data=data,
        )
        edges.append(edge)

    # 5. Things drawn in ThreatAtlas but not in the YAML: kept, unless pruning.
    known = set(elements) | {f.id for f in diagram.flows}
    extra_nodes = [n for nid, n in old_nodes.items() if nid not in known]
    extra_edges = [e for eid, e in old_edges.items() if eid not in known]
    extra_ids = [str(x["id"]) for x in [*extra_nodes, *extra_edges]]
    if prune:
        return BuildResult({"nodes": nodes, "edges": edges}, kept=[], removed=extra_ids)
    node_ids = {n["id"] for n in nodes} | {str(n["id"]) for n in extra_nodes}
    kept_edges = [
        e for e in extra_edges if str(e.get("source")) in node_ids and str(e.get("target")) in node_ids
    ]
    return BuildResult(
        {"nodes": [*nodes, *extra_nodes], "edges": [*edges, *kept_edges]}, kept=extra_ids, removed=[]
    )


def canonical(data: dict[str, Any] | None) -> Any:
    """Order-independent form of diagram data, to tell whether an update is needed."""
    data = data or {}

    def norm(items: Any) -> list[Any]:
        return sorted((i for i in items or [] if isinstance(i, dict)), key=lambda i: str(i.get("id")))

    return {"nodes": norm(data.get("nodes")), "edges": norm(data.get("edges"))}
