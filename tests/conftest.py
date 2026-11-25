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
