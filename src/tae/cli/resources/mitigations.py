"""``tae mitigations``."""

from __future__ import annotations

from tae.cli.resources._catalog import build
from tae.output import Column, col

INSTANCE_COLUMNS = [
    col("ID", "id"),
    Column("Mitigation", lambda m: m.mitigation.name, 40),
    col("Diagram", "diagram_id"),
    col("Element", "element_id", 20),
    col("Threat", "threat_id"),
    col("Status", "status"),
]

app = build(
    noun="mitigation",
    catalog=lambda c: c.mitigations,
    instances=lambda c: c.diagram_mitigations,
    instance_columns=INSTANCE_COLUMNS,
)
