from __future__ import annotations

import json

import pytest
import respx

from tae.client import ThreatAtlasClient
from tae.client.errors import ResponseFormatError
from tae.models import api as m
from tests.conftest import BASE, load


@pytest.fixture
def client() -> ThreatAtlasClient:
    return ThreatAtlasClient(BASE, "ta_secret", retries=0)


def test_me(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/auth/me").respond(json=load("me"))
    me = client.users.me()
    assert me.username == "analyst"
    assert me.effective_role == "standard"


def test_products_list_keeps_unknown_fields(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/products").respond(json=load("products"))
    products = client.products.list()
    assert [p.name for p in products] == ["Payments API", "Customer Portal"]
    assert products[1].model_extra == {"future_field": "kept"}


def test_products_duplicate(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    route = api.post("/products/12/duplicate").respond(201, json=load("products")[0])
    client.products.duplicate(12, "Copy")
    assert json.loads(route.calls.last.request.content) == {"name": "Copy"}


def test_diagrams_list_filters_by_product(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    route = api.get("/diagrams").respond(json=load("diagrams"))
    diagrams = client.diagrams.list(product_id=12)
    assert route.calls.last.request.url.params["product_id"] == "12"
    assert len(diagrams[0].nodes) == 4
    assert len(diagrams[0].edges) == 2
    assert diagrams[1].nodes == []


def test_models_list_all_is_not_paginated(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    route = api.get("/models").respond(json=load("models"))
    models = client.models.list()
    assert "skip" not in route.calls.last.request.url.params
    assert models[0].framework_name == "STRIDE"


def test_models_list_by_diagram(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/models/diagram/31").respond(json=load("models"))
    assert client.models.list(diagram_id=31)[0].diagram_id == 31


def test_catalog_bool_param_is_lowercase(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    route = api.get("/threats").respond(json=load("threats"))
    client.threats.list(framework_id=1, is_custom=False)
    params = route.calls.last.request.url.params
    assert params["is_custom"] == "false"
    assert params["framework_id"] == "1"


def test_catalog_revert(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.post("/mitigations/201/revert").respond(json=load("mitigations")[0])
    assert isinstance(client.mitigations.revert(201), m.Mitigation)


def test_diagram_threats_list_has_details(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/diagram-threats").respond(json=load("diagram_threats"))
    items = client.diagram_threats.list(diagram_id=31)
    assert items[0].threat.name == "SQL injection"
    assert items[0].severity == "critical"
    assert items[1].acceptance_approver_name == "Rae Viewer"


def test_diagram_threat_create_returns_bare_record(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    created = {k: v for k, v in load("diagram_threats")[0].items() if k not in ("threat", "model")}
    route = api.post("/diagram-threats").respond(201, json=created)
    body = m.DiagramThreatCreate(
        diagram_id=31,
        model_id=41,
        threat_id=101,
        element_id="n-db",
        element_type="node",
        likelihood=4,
        impact=5,
    )
    result = client.diagram_threats.create(body)
    assert type(result) is m.DiagramThreat
    sent = json.loads(route.calls.last.request.content)
    assert sent["likelihood"] == 4
    assert "comments" not in sent  # unset fields are not sent


def test_update_sends_only_given_fields(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    route = api.put("/diagram-mitigations/601").respond(json=load("diagram_mitigations")[0])
    client.diagram_mitigations.update(601, m.DiagramMitigationUpdate(status="verified"))
    assert json.loads(route.calls.last.request.content) == {"status": "verified"}


def test_request_models_validate_scores() -> None:
    with pytest.raises(ValueError, match="less than or equal to 5"):
        m.DiagramThreatUpdate(likelihood=6)


def test_request_models_reject_unknown_fields() -> None:
    with pytest.raises(ValueError, match="Extra inputs"):
        m.ProductUpdate(nmae="typo")  # type: ignore[call-arg]


def test_versions(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/diagram-versions/31/versions").respond(json=load("versions"))
    route = api.get("/diagram-versions/31/versions/compare").respond(
        json={"from_version": 1, "to_version": 3}
    )
    assert client.diagram_versions.list(31)[0].total_risk_score == 26
    client.diagram_versions.compare(31, 1, 3)
    assert dict(route.calls.last.request.url.params) == {"from_version": "1", "to_version": "3"}


def test_approvals(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/approvals/my").respond(json=load("approvals"))
    api.get("/approvals/my/count").respond(json={"count": 1})
    assert [a.threat_name for a in client.approvals.mine()] == ["Spoofed client", "Log tampering"]
    assert client.approvals.pending_count() == 1


def test_unexpected_shape_raises(api: respx.MockRouter, client: ThreatAtlasClient) -> None:
    api.get("/products/12").respond(json={"id": "not-a-number"})
    with pytest.raises(ResponseFormatError, match="GET /products/12"):
        client.products.get(12)


@pytest.mark.parametrize(
    ("score", "severity"),
    [
        (None, None),
        (1, "low"),
        (5, "low"),
        (6, "medium"),
        (11, "medium"),
        (12, "high"),
        (19, "high"),
        (20, "critical"),
        (25, "critical"),
    ],
)
def test_severity_bands_match_upstream(score: int | None, severity: str | None) -> None:
    assert m.severity_for_score(score) == severity
