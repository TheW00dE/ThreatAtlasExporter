from __future__ import annotations

import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import respx

BASE = "https://ta.test"
API = f"{BASE}/api"
FIXTURES = Path(__file__).parent / "fixtures" / "api"


def load(name: str) -> Any:
    return json.loads((FIXTURES / f"{name}.json").read_text())


@pytest.fixture(autouse=True)
def isolated_env(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    """Keep the developer's real config, env vars and keyring out of tests."""
    import os

    for key in list(os.environ):
        if key.startswith("TAE_"):
            monkeypatch.delenv(key)
    monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg"))
    monkeypatch.setattr("tae.config._keyring", lambda: None)


@pytest.fixture
def api() -> Iterator[respx.MockRouter]:
    with respx.mock(base_url=API, assert_all_called=False) as router:
        yield router


@pytest.fixture
def no_sleep() -> list[float]:
    """Collects retry delays instead of sleeping."""
    return []


def raw_snapshot() -> dict[str, Any]:
    """Fresh, mutable snapshot data built from the API fixtures."""
    return {
        "meta": {"source_url": BASE, "pulled_at": "2026-11-20T09:00:00Z", "pulled_by": "analyst"},
        "product": load("products")[0],
        "frameworks": load("frameworks"),
        "diagrams": load("diagrams"),
        "models": load("models"),
        "diagram_threats": load("diagram_threats"),
        "diagram_mitigations": load("diagram_mitigations"),
    }


def make_snapshot(raw: dict[str, Any] | None = None):  # type: ignore[no-untyped-def]
    from tae.snapshot import Snapshot

    return Snapshot.model_validate(raw if raw is not None else raw_snapshot())


def make_view(raw: dict[str, Any] | None = None):  # type: ignore[no-untyped-def]
    from tae.snapshot import build_view

    return build_view(make_snapshot(raw))


@pytest.fixture
def snapshot_file(tmp_path: Path) -> Path:
    path = tmp_path / "payments.snapshot.json"
    make_snapshot().save(path)
    return path
