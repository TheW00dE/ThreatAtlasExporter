"""The snapshot file: everything pulled for one product, as returned by the API.

A snapshot is the hand-off between ``tae pull``, ``tae validate`` and
``tae report``. It stores API records unchanged (no derived data), so it can be
re-validated or re-rendered later with newer rules and templates, and kept as
audit evidence of what the report was built from.
"""

from __future__ import annotations

import hashlib
import json
from datetime import UTC, datetime
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field, ValidationError

from tae import __version__
from tae.errors import InputError
from tae.models.api import (
    Diagram,
    DiagramMitigationWithDetails,
    DiagramThreatWithDetails,
    Framework,
    ModelWithFramework,
    Product,
)

SNAPSHOT_FORMAT = 1


class SnapshotError(InputError):
    """A snapshot file is missing, unreadable or malformed."""


class SnapshotMeta(BaseModel):
    model_config = ConfigDict(extra="allow")

    format: int = SNAPSHOT_FORMAT
    tool_version: str = __version__
    source_url: str | None = None
    pulled_at: datetime = Field(default_factory=lambda: datetime.now(UTC))
    pulled_by: str | None = None


class Snapshot(BaseModel):
    model_config = ConfigDict(extra="forbid")

    meta: SnapshotMeta = Field(default_factory=SnapshotMeta)
    product: Product
    frameworks: list[Framework] = Field(default_factory=list)
    diagrams: list[Diagram] = Field(default_factory=list)
    models: list[ModelWithFramework] = Field(default_factory=list)
    diagram_threats: list[DiagramThreatWithDetails] = Field(default_factory=list)
    diagram_mitigations: list[DiagramMitigationWithDetails] = Field(default_factory=list)

    def content_hash(self) -> str:
        """SHA-256 of the data (excluding metadata), for spotting unchanged pulls."""
        data = self.model_dump(mode="json", exclude={"meta"})
        canonical = json.dumps(data, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        return hashlib.sha256(canonical.encode()).hexdigest()

    def to_json(self) -> str:
        return self.model_dump_json(indent=2)

    def save(self, path: Path) -> None:
        path.parent.mkdir(parents=True, exist_ok=True)
        tmp = path.with_suffix(path.suffix + ".tmp")
        tmp.write_text(self.to_json() + "\n", encoding="utf-8")
        tmp.replace(path)

    @classmethod
    def load(cls, path: Path) -> Snapshot:
        try:
            text = path.read_text(encoding="utf-8")
        except OSError as exc:
            raise SnapshotError(f"Cannot read snapshot {path}: {exc}") from exc
        try:
            raw = json.loads(text)
        except ValueError as exc:
            raise SnapshotError(f"{path} is not valid JSON: {exc}") from exc
        fmt = raw.get("meta", {}).get("format") if isinstance(raw, dict) else None
        if fmt is not None and fmt > SNAPSHOT_FORMAT:
            raise SnapshotError(
                f"{path} uses snapshot format {fmt}, but this version of tae reads up to "
                f"{SNAPSHOT_FORMAT}. Upgrade tae."
            )
        try:
            return cls.model_validate(raw)
        except ValidationError as exc:
            raise SnapshotError(f"{path} is not a valid snapshot: {exc}") from exc
