from __future__ import annotations

import json
from pathlib import Path

import pytest
import respx

from tae.client import ThreatAtlasClient
from tae.snapshot import Snapshot, SnapshotError, build_view
from tae.snapshot.collector import ProductNotFound, collect, resolve_product
from tae.snapshot.model import SNAPSHOT_FORMAT
from tests.conftest import BASE, load, make_snapshot, make_view, raw_snapshot


def test_view_links_everything() -> None:
    view = make_view()
    payment = view.diagram(31)
    assert payment is not None
    assert [t.ref for t in view.threats] == ["T1", "T2"]
    sqli, spoof = view.threats
    assert sqli.name == "SQL injection"
    assert sqli.element is not None and sqli.element.label == "Transactions DB"
    assert sqli.element.type == "datastore"
    assert spoof.element is not None and spoof.element.kind == "edge"
    assert spoof.element_label == "HTTPS card data"
    assert sqli.framework_name == "STRIDE"
    # Mitigation.threat_id is the *diagram threat* ID (501), not the catalog threat (101).
    assert [m.ref for m in sqli.mitigations] == ["M1"]
    assert sqli.active_mitigations == sqli.mitigations
    assert view.mitigations[0].threat is sqli


def test_threats_numbered_most_severe_first_per_diagram() -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][0]["risk_score"] = 4
    raw["diagram_threats"][0]["severity"] = "low"
    view = make_view(raw)
    assert [(t.ref, t.name) for t in view.threats] == [("T1", "Spoofed client"), ("T2", "SQL injection")]


def test_derived_scores_when_server_omits_them() -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][0].update(
        risk_score=None, severity=None, residual_risk_score=None, residual_severity=None
    )
    t = make_view(raw).threats[0]
    assert (t.risk_score, t.severity) == (20, "critical")
    assert (t.residual_score, t.residual_severity) == (5, "low")


def test_elements_tolerate_messy_diagram_data() -> None:
    raw = raw_snapshot()
    raw["diagrams"][0]["diagram_data"] = {
        "nodes": [
            {"id": 1, "data": {"label": "Numeric id", "type": "process"}},
            {"id": "child", "parentId": "b", "data": {"label": "Inside", "type": "process"}},
            {"id": "no-data"},
            "garbage",
            {"data": {"label": "no id"}},
        ],
        "edges": [{"id": "e", "source": 1, "target": "child", "data": {"label": "via data"}}, {"id": "bare"}],
    }
    d = make_view(raw).diagram(31)
    assert d is not None
    assert set(d.elements) == {"1", "child", "no-data", "e", "bare"}
    assert d.elements["child"].parent_id == "b"
    assert d.elements["no-data"].type == "unknown"
    assert d.elements["no-data"].label == "no-data"
    assert d.elements["e"].label == "via data"
    assert d.elements["e"].source == "1"


def test_threats_on_other_diagrams_are_ignored() -> None:
    raw = raw_snapshot()
    raw["diagram_threats"][0]["diagram_id"] = 999
    assert len(make_view(raw).threats) == 1


def test_save_and_load_round_trip(tmp_path: Path) -> None:
    snap = make_snapshot()
    path = tmp_path / "s.json"
    snap.save(path)
    loaded = Snapshot.load(path)
    assert loaded.content_hash() == snap.content_hash()
    assert loaded.meta.pulled_by == "analyst"


def test_content_hash_ignores_metadata() -> None:
    a = raw_snapshot()
    b = raw_snapshot()
    b["meta"]["pulled_at"] = "2030-01-01T00:00:00Z"
    assert make_snapshot(a).content_hash() == make_snapshot(b).content_hash()
    b["product"]["name"] = "Renamed"
    assert make_snapshot(a).content_hash() != make_snapshot(b).content_hash()


@pytest.mark.parametrize(
    ("content", "message"),
    [
        ("{not json", "not valid JSON"),
        (json.dumps({"meta": {"format": SNAPSHOT_FORMAT + 1}}), "Upgrade tae"),
        (json.dumps({"product": {"id": 1}}), "not a valid snapshot"),
    ],
)
def test_load_errors(tmp_path: Path, content: str, message: str) -> None:
    path = tmp_path / "bad.json"
    path.write_text(content)
    with pytest.raises(SnapshotError, match=message):
        Snapshot.load(path)


def test_load_missing_file(tmp_path: Path) -> None:
    with pytest.raises(SnapshotError, match="Cannot read"):
        Snapshot.load(tmp_path / "nope.json")


# ── collector ──────────────────────────────────────────────────────────────────


@pytest.fixture
def client() -> ThreatAtlasClient:
    return ThreatAtlasClient(BASE, "ta_x", retries=0)


def mock_product_endpoints(api: respx.MockRouter) -> None:
    diagrams = load("diagrams")
    api.get("/frameworks").respond(json=load("frameworks"))
    api.get("/diagrams").respond(json=[diagrams[0], {**diagrams[1], "diagram_data": None}])
    api.get("/diagrams/32").respond(json={**diagrams[1], "diagram_data": {"nodes": [], "edges": []}})
    api.get("/models/diagram/31").respond(json=load("models"))
    api.get("/models/diagram/32").respond(json=[])
    api.get("/diagram-threats", params={"diagram_id": "31"}).respond(json=load("diagram_threats"))
    api.get("/diagram-threats", params={"diagram_id": "32"}).respond(json=[])
    api.get("/diagram-mitigations", params={"diagram_id": "31"}).respond(json=load("diagram_mitigations"))
    api.get("/diagram-mitigations", params={"diagram_id": "32"}).respond(json=[])
    api.get("/auth/me").respond(json=load("me"))


def test_collect(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    mock_product_endpoints(api)
    messages: list[str] = []
    product = make_snapshot().product
    snap = collect(client, product, messages.append)
    assert len(snap.diagrams) == 2
    assert snap.diagrams[1].diagram_data == {"nodes": [], "edges": []}  # fetched individually
    assert len(snap.diagram_threats) == 2
    assert snap.meta.source_url == BASE
    assert snap.meta.pulled_by == "analyst"
    assert any("Payment flow" in m for m in messages)
    assert len(build_view(snap).threats) == 2


def test_resolve_product_by_id_and_name(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/products/12").respond(json=load("products")[0])
    api.get("/products").respond(json=load("products"))
    assert resolve_product(client, "12").id == 12
    assert resolve_product(client, "customer portal").id == 14


def test_resolve_product_errors(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/products/99").respond(404, json={"detail": "Product not found"})
    products = load("products")
    api.get("/products").respond(json=[*products, {**products[0], "id": 99}])
    with pytest.raises(ProductNotFound, match="No product with ID 99"):
        resolve_product(client, "99")
    with pytest.raises(ProductNotFound, match="No product named"):
        resolve_product(client, "Nope")
    with pytest.raises(ProductNotFound, match="IDs 12, 99"):
        resolve_product(client, "Payments API")
