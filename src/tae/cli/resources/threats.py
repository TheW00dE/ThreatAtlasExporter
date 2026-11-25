"""``tae threats``."""

from __future__ import annotations

from tae.cli.resources._catalog import build
from tae.output import Column, col

INSTANCE_COLUMNS = [
    col("ID", "id"),
    Column("Threat", lambda t: t.threat.name, 40),
    col("Diagram", "diagram_id"),
    col("Element", "element_id", 20),
    col("Status", "status"),
    col("L", "likelihood"),
    col("I", "impact"),
    col("Score", "risk_score"),
    col("Severity", "severity"),
    col("Residual", "residual_severity"),
]

app = build(
    noun="threat",
    catalog=lambda c: c.threats,
    instances=lambda c: c.diagram_threats,
    instance_columns=INSTANCE_COLUMNS,
)
