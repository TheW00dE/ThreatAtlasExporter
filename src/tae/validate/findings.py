"""Validation findings and levels."""

from __future__ import annotations

import hashlib
from dataclasses import dataclass, field
from enum import StrEnum
from typing import Any


class Level(StrEnum):
    info = "info"
    warning = "warning"
    error = "error"

    @property
    def rank(self) -> int:
        return {"info": 1, "warning": 2, "error": 3}[self.value]

    def at_least(self, other: Level) -> bool:
        return self.rank >= other.rank


class FailLevel(StrEnum):
    """Threshold for failing a run; ``never`` disables failing."""

    info = "info"
    warning = "warning"
    error = "error"
    never = "never"

    def fails(self, level: Level) -> bool:
        return self is not FailLevel.never and level.at_least(Level(self.value))


@dataclass(frozen=True)
class EntityRef:
    """What a finding is about, with enough context to locate it in ThreatAtlas."""

    kind: str  # product | diagram | element | model | diagram_threat | diagram_mitigation | asset
    id: str
    label: str
    diagram_id: int | None = None
    diagram_name: str | None = None
    ref: str | None = None  # report reference such as T3

    def describe(self) -> str:
        where = f" on diagram {self.diagram_name!r}" if self.diagram_name and self.kind != "diagram" else ""
        prefix = f"{self.ref} " if self.ref else ""
        return f"{self.kind.replace('_', ' ')} {prefix}{self.label!r}{where}"


@dataclass(frozen=True)
class Finding:
    rule_id: str
    level: Level
    message: str
    entity: EntityRef
    rule_title: str = ""
    details: dict[str, Any] = field(default_factory=dict, compare=False, hash=False)

    @property
    def fingerprint(self) -> str:
        key = f"{self.rule_id}|{self.entity.kind}|{self.entity.id}|{self.message}"
        return hashlib.sha256(key.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        e = self.entity
        return {
            "rule_id": self.rule_id,
            "rule_title": self.rule_title,
            "level": self.level.value,
            "message": self.message,
            "entity": {
                "kind": e.kind,
                "id": e.id,
                "label": e.label,
                "ref": e.ref,
                "diagram_id": e.diagram_id,
                "diagram_name": e.diagram_name,
            },
            "fingerprint": self.fingerprint,
            **({"details": self.details} if self.details else {}),
        }
