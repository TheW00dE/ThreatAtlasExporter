"""tae import: frameworks and threat models as YAML, synced into a fake ThreatAtlas."""

from __future__ import annotations

import copy
import json
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
import yaml
from typer.testing import CliRunner

from tae.cli.app import app
from tae.client import ThreatAtlasClient
from tae.importer import Sync, sync_framework, sync_threat_model
from tae.importer.diagram import NODE_SIZES, build_diagram_data, canonical
from tae.importer.schema import ImportFileError, parse_document
from tae.importer.sync import SUGGESTED
from tests.fake_api import FakeThreatAtlasAPI

EXAMPLES = Path(__file__).resolve().parents[2] / "examples" / "models"


def example(name: str) -> dict[str, Any]:
    return yaml.safe_load((EXAMPLES / name).read_text())


FRAMEWORK = "payments-framework.yaml"
MODEL = "payments-threat-model.yaml"


@pytest.fixture
def fake() -> FakeThreatAtlasAPI:
    return FakeThreatAtlasAPI()


@pytest.fixture
def client(fake: FakeThreatAtlasAPI) -> Iterator[ThreatAtlasClient]:
    with ThreatAtlasClient("https://ta.test", "ta_x", transport=fake.transport, retries=0) as c:
        yield c


def sync(
    client: ThreatAtlasClient, raw: dict[str, Any], *, dry_run: bool = False, prune: bool = False
) -> Sync:
    doc = parse_document(raw, "test.yaml")
    s = Sync(client, dry_run=dry_run, prune=prune, source="test.yaml")
    (sync_framework if raw["kind"] == "framework" else sync_threat_model)(s, doc)  # type: ignore[operator]
    return s


def actions(s: Sync) -> list[tuple[str, str, str]]:
    return [(c.action, c.kind, c.name) for c in s.changes if c.action != "note"]


def custom_framework(fake: FakeThreatAtlasAPI) -> dict[str, Any]:
    return next(f for f in fake.frameworks.values() if f["is_custom"])


# ── frameworks ─────────────────────────────────────────────────────────────────


def test_framework_import_creates_everything(fake: FakeThreatAtlasAPI, client: ThreatAtlasClient) -> None:
    s = sync(client, example(FRAMEWORK))
    fw = custom_framework(fake)
    assert fw["name"] == "Card Payments Threat Model" and fw["user_id"] == fake.user_id
    assert "Risk scale: Payments risk scale" in fw["description"]
    assert "Likelihood: 1 Rare; 2 Unlikely" in fw["description"]
    assert "critical from 16, high from 10, medium from 5" in fw["description"]
    threats = {t["name"]: t for t in fake.threats.values() if t["framework_id"] == fw["id"]}
    assert len(threats) == 5 and threats["Card testing attack"]["category"] == "Fraud"
    assert threats["Card testing attack"]["description"].endswith(
        f"{SUGGESTED}Velocity limits; Bot detection"
    )
    assert len([m for m in fake.mitigations.values() if m["framework_id"] == fw["id"]]) == 7
    assert len(actions(s)) == 13


def test_framework_dry_run_writes_nothing(fake: FakeThreatAtlasAPI, client: ThreatAtlasClient) -> None:
    s = sync(client, example(FRAMEWORK), dry_run=True)
    assert fake.writes == []
    assert len(actions(s)) == 13


def test_framework_reimport_is_a_no_op(fake: FakeThreatAtlasAPI, client: ThreatAtlasClient) -> None:
    sync(client, example(FRAMEWORK))
    writes = len(fake.writes)
    assert actions(sync(client, example(FRAMEWORK))) == []
    assert len(fake.writes) == writes


def test_framework_edits_update_and_removals_need_prune(
    fake: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    sync(client, example(FRAMEWORK))
    raw = example(FRAMEWORK)
    raw["framework"]["description"] = "New wording."
    raw["threats"][0]["category"] = "Compliance"
    raw["threats"] = [t for t in raw["threats"] if t["name"] != "Acquirer outage"]
    raw["threats"].append({"name": "Refund fraud", "category": "Fraud"})
    s = sync(client, raw)
    assert ("update", "framework", "Card Payments Threat Model") in actions(s)
    assert ("update", "threat", "Card-not-present fraud") in actions(s)
    assert ("create", "threat", "Refund fraud") in actions(s)
    assert any(c.action == "note" and c.name == "Acquirer outage" for c in s.changes)
    assert any(t["name"] == "Acquirer outage" for t in fake.threats.values())  # kept without --prune
    s = sync(client, raw, prune=True)
    assert actions(s) == [("delete", "threat", "Acquirer outage")]
    assert not any(t["name"] == "Acquirer outage" for t in fake.threats.values())


def test_builtin_framework_cannot_be_overwritten(client: ThreatAtlasClient) -> None:
    raw = example(FRAMEWORK)
    raw["framework"]["name"] = "stride"
    with pytest.raises(ImportFileError, match="built-in"):
        sync(client, raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (lambda r: r["threats"].append(dict(r["threats"][0])), "duplicate threat name"),
        (lambda r: r["threats"][0]["mitigations"].append("Nope"), "lists mitigation 'Nope'"),
        (lambda r: r["threats"][0].update(category="Weather"), "category 'Weather'"),
        (lambda r: r["risk_scale"]["likelihood"].pop(5), "exactly the levels"),
        (
            lambda r: r["risk_scale"].update(bands={"critical": 5, "high": 10, "medium": 3}),
            "critical > high > medium",
        ),
        (lambda r: r.update(kind="frameworks"), "'kind' must be"),
        (lambda r: r["framework"].update(name=""), "at least 1 character"),
    ],
)
def test_framework_file_errors(change: Any, message: str) -> None:
    raw = example(FRAMEWORK)
    change(raw)
    with pytest.raises(ImportFileError, match=message):
        parse_document(raw, "x.yaml")


# ── threat models ─────────────────────────────────────────────────────────────


@pytest.fixture
def with_framework(fake: FakeThreatAtlasAPI, client: ThreatAtlasClient) -> FakeThreatAtlasAPI:
    sync(client, example(FRAMEWORK))
    return fake


def test_threat_model_import_creates_everything(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    fake = with_framework
    sync(client, example(MODEL))
    product = next(iter(fake.products.values()))
    assert product["name"] == "Payments API" and product["owner_email"] == "pat.owner@example.com"
    diagram = next(iter(fake.diagrams.values()))
    nodes = {n["id"]: n for n in diagram["diagram_data"]["nodes"]}
    assert all(n["type"] == "custom" for n in nodes.values())
    assert nodes["dmz"]["zIndex"] == -1 and nodes["dmz"]["width"] > 0
    edges = {e["id"]: e for e in diagram["diagram_data"]["edges"]}
    assert (
        edges["f-checkout"]["sourceHandle"].startswith("source-") and edges["f-checkout"]["animated"] is True
    )
    models = {m["name"]: m for m in fake.models.values()}
    assert set(models) == {"Payments review 2026", "STRIDE"}
    threats = {fake.threats[t["threat_id"]]["name"]: t for t in fake.diagram_threats.values()}
    assert (
        threats["Card testing attack"]["element_type"] == "edge"
        and threats["Card testing attack"]["risk_score"] == 12
    )
    logs = threats["Cardholder data exposure in logs"]
    assert logs["status"] == "mitigated" and logs["residual_risk_score"] == 5
    outage = threats["Acquirer outage"]
    assert (
        outage["status"] == "accepted" and outage["accepted_at"] is not None
    )  # stamped like the ThreatAtlas UI
    assert outage["acceptance_justification"].startswith("Outages are short")
    assert outage["acceptance_review_status"] is None  # approval is never done by an import
    linked = {fake.mitigations[m["mitigation_id"]]["name"]: m for m in fake.diagram_mitigations.values()}
    assert linked["Velocity limits"]["threat_id"] == threats["Card testing attack"]["id"]
    assert linked["Parameterised queries"]["threat_id"] == threats["SQL injection"]["id"]


def test_threat_model_reimport_is_a_no_op(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    sync(client, example(MODEL))
    writes = len(with_framework.writes)
    assert actions(sync(client, example(MODEL))) == []
    assert len(with_framework.writes) == writes


def test_threat_model_dry_run_writes_nothing(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    writes = len(with_framework.writes)
    s = sync(client, example(MODEL), dry_run=True)
    assert len(with_framework.writes) == writes
    kinds = [k for _, k, _ in actions(s)]
    assert kinds.count("threat on diagram") == 4 and kinds.count("mitigation on diagram") == 5


def test_changes_are_applied_and_unmanaged_fields_left_alone(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    fake = with_framework
    sync(client, example(MODEL))
    card = next(
        t
        for t in fake.diagram_threats.values()
        if fake.threats[t["threat_id"]]["name"] == "Card testing attack"
    )
    card["status"] = "mitigated"  # changed by someone in ThreatAtlas; the file doesn't set a status
    card["comments"] = "Reviewed in the UI"
    raw = example(MODEL)
    raw["diagrams"][0]["models"][0]["threats"][0]["likelihood"] = 5
    s = sync(client, raw)
    assert actions(s) == [
        (
            "update",
            "threat on diagram",
            "Payment flow / Payments review 2026: Card testing attack on f-checkout",
        )
    ]
    assert s.changes[0].detail == "likelihood"
    assert card["likelihood"] == 5 and card["risk_score"] == 15
    assert card["status"] == "mitigated" and card["comments"] == "Reviewed in the UI"


def test_prune_removes_threats_and_their_mitigations(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    fake = with_framework
    sync(client, example(MODEL))
    raw = example(MODEL)
    raw["diagrams"][0]["models"][0]["threats"] = raw["diagrams"][0]["models"][0]["threats"][
        1:
    ]  # drop card testing
    s = sync(client, raw)
    assert actions(s) == []  # without --prune nothing is deleted...
    assert (
        sum(c.action == "note" for c in s.changes) == 3
    )  # ...but the threat and its 2 mitigations are listed
    s = sync(client, raw, prune=True)
    deletes = [k for a, k, _ in actions(s) if a == "delete"]
    assert deletes == ["mitigation on diagram", "mitigation on diagram", "threat on diagram"]
    assert not any(
        fake.threats[t["threat_id"]]["name"] == "Card testing attack" for t in fake.diagram_threats.values()
    )
    assert len(fake.diagram_mitigations) == 3


def test_layout_changes_in_threatatlas_survive_reimport(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    fake = with_framework
    sync(client, example(MODEL))
    diagram = next(iter(fake.diagrams.values()))
    node = next(n for n in diagram["diagram_data"]["nodes"] if n["id"] == "shopper")
    node["position"] = {"x": 5.0, "y": 600.0}  # moved in the editor
    node["measured"] = {"width": 120, "height": 44}  # editor-only field
    diagram["diagram_data"]["nodes"].append(
        {
            "id": "note-1",
            "type": "custom",
            "position": {"x": 0, "y": 0},
            "data": {"label": "Added in UI", "type": "external"},
        }
    )
    s = sync(client, example(MODEL))
    assert [a for a, k, _ in actions(s) if k == "diagram"] == ["update"]  # edge handles follow the moved node
    nodes = {n["id"]: n for n in diagram["diagram_data"]["nodes"]}
    assert (
        nodes["shopper"]["position"] == {"x": 5.0, "y": 600.0}
        and nodes["shopper"]["measured"]["width"] == 120
    )
    assert "note-1" in nodes and any("note-1" in c.detail for c in s.changes if c.action == "note")
    sync(client, example(MODEL), prune=True)
    assert "note-1" not in {n["id"] for n in diagram["diagram_data"]["nodes"]}
    assert fake.versions[diagram["id"]][-1] == "Synced from test.yaml by tae"


def test_preflight_reports_every_missing_reference(
    fake: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    raw = example(MODEL)
    raw["diagrams"][0]["models"][1]["threats"][0]["threat"] = "Teleportation"
    with pytest.raises(ImportFileError) as info:
        sync(client, raw)
    text = str(info.value)
    assert "framework 'Card Payments Threat Model' not found" in text and "same account" in text
    assert "STRIDE has no threat named 'Teleportation'" in text
    assert fake.writes == []  # nothing written before the check


def test_frameworks_of_other_users_are_invisible(fake: FakeThreatAtlasAPI, client: ThreatAtlasClient) -> None:
    sync(client, example(FRAMEWORK))
    other = copy.copy(fake)
    other.user_id = 2  # same data, different account
    with (
        ThreatAtlasClient("https://ta.test", "ta_y", transport=other.transport, retries=0) as c2,
        pytest.raises(ImportFileError, match="only visible to the user who created them"),
    ):
        sync(c2, example(MODEL))


def test_model_with_a_different_framework_is_refused(
    with_framework: FakeThreatAtlasAPI, client: ThreatAtlasClient
) -> None:
    sync(client, example(MODEL))
    raw = example(MODEL)
    raw["diagrams"][0]["models"][1]["framework"] = "Card Payments Threat Model"
    raw["diagrams"][0]["models"][1]["name"] = "STRIDE"
    raw["diagrams"][0]["models"][1]["threats"] = []
    with pytest.raises(ImportFileError, match="uses framework 'STRIDE'"):
        sync(client, raw)


@pytest.mark.parametrize(
    ("change", "message"),
    [
        (
            lambda d: d["elements"].append({"id": "shopper", "type": "process", "label": "Dup"}),
            "used more than once",
        ),
        (lambda d: d["elements"][0].update(boundary="nowhere"), "isn't a boundary"),
        (lambda d: d["flows"][0].update(to="dmz"), "not boundaries"),
        (lambda d: d["flows"][0].update(to="ghost"), "'ghost' isn't an element"),
        (lambda d: d["models"][0]["threats"][0].update(element="ghost"), "not an element or flow"),
        (lambda d: d["models"][0]["threats"][0].update(likelihood=7), "less than or equal to 5"),
        (lambda d: d["models"][0]["threats"][0].update(impact=None), "both likelihood and impact"),
        (
            lambda d: d["models"][0]["threats"][2].update(status="identified"),
            "only allowed with status accepted",
        ),
        (lambda d: d["models"][0]["threats"].append(dict(d["models"][0]["threats"][0])), "listed twice"),
        (
            lambda d: d["elements"][1].update(boundary="internal") or d["elements"][3].update(boundary="dmz"),
            "contain each other",
        ),
        (lambda d: d["elements"][0].update(id="has space"), "pattern"),
    ],
)
def test_threat_model_file_errors(change: Any, message: str) -> None:
    raw = example(MODEL)
    change(raw["diagrams"][0])
    with pytest.raises(ImportFileError, match=message):
        parse_document(raw, "x.yaml")


def test_yaml_on_key_trap_is_explained() -> None:
    raw = yaml.safe_load("kind: threat-model\nproduct: {name: P}\ndiagrams:\n- name: D\n  elements: [{id: a, type: process, label: A}]\n"
                         "  models: [{framework: STRIDE, threats: [{threat: X, on: a}]}]\n")  # fmt: skip
    with pytest.raises(ImportFileError, match="element"):
        parse_document(raw, "x.yaml")


def test_risk_scale_files_are_not_imported() -> None:
    with pytest.raises(ImportFileError, match="aren't imported"):
        parse_document({"kind": "risk-scale"}, "x.yaml")


# ── diagram builder ───────────────────────────────────────────────────────────


def test_auto_layout_keeps_boundaries_to_their_members() -> None:
    doc = parse_document(example(MODEL), "x")
    data = build_diagram_data(doc.diagrams[0]).data  # type: ignore[union-attr]
    boxes = {}
    for n in data["nodes"]:
        w, h = (n["width"], n["height"]) if n["data"]["type"] == "boundary" else NODE_SIZES[n["data"]["type"]]
        boxes[n["id"]] = (n["position"]["x"], n["position"]["y"], w, h)

    def inside(i: str, b: str) -> bool:
        x, y, w, h = boxes[i]
        bx, by, bw, bh = boxes[b]
        return x >= bx and y >= by and x + w <= bx + bw and y + h <= by + bh

    members = {"dmz": {"checkout"}, "internal": {"payments", "vault"}}
    for b, expected in members.items():
        assert {i for i in boxes if i not in members and inside(i, b)} == expected


def test_flows_run_left_to_right_and_rebuilds_are_stable() -> None:
    doc = parse_document(example(MODEL), "x")
    first = build_diagram_data(doc.diagrams[0]).data  # type: ignore[union-attr]
    x = {n["id"]: n["position"]["x"] for n in first["nodes"]}
    assert x["shopper"] < x["checkout"] < x["payments"] < x["acquirer"]
    again = build_diagram_data(doc.diagrams[0], first).data  # type: ignore[union-attr]
    assert canonical(again) == canonical(first)


def test_explicit_positions_and_sizes_win() -> None:
    raw = example(MODEL)
    raw["diagrams"][0]["elements"][0]["position"] = [1, 2]
    raw["diagrams"][0]["elements"][1]["size"] = [500, 400]
    doc = parse_document(raw, "x")
    nodes = {n["id"]: n for n in build_diagram_data(doc.diagrams[0]).data["nodes"]}  # type: ignore[union-attr]
    assert nodes["shopper"]["position"] == {"x": 1, "y": 2}
    assert (nodes["dmz"]["width"], nodes["dmz"]["height"]) == (500, 400)


# ── CLI ──────────────────────────────────────────────────────────────────────


@pytest.fixture
def cli(fake: FakeThreatAtlasAPI, monkeypatch: pytest.MonkeyPatch) -> CliRunner:
    real = ThreatAtlasClient

    def with_fake(url: str, token: str | None, **kw: Any) -> ThreatAtlasClient:
        return real(url, token, transport=fake.transport, retries=0)

    monkeypatch.setattr("tae.cli.common.ThreatAtlasClient", with_fake)
    return CliRunner()


ENV = {"TAE_URL": "https://ta.test", "TAE_TOKEN": "ta_x", "COLUMNS": "200"}


def test_cli_dry_run_then_import(cli: CliRunner, fake: FakeThreatAtlasAPI) -> None:
    path = str(EXAMPLES / FRAMEWORK)
    result = cli.invoke(app, ["import", path, "--dry-run"], env=ENV)
    assert result.exit_code == 0, result.output
    assert "Plan: 13 to create." in result.output and fake.writes == []
    result = cli.invoke(app, ["import", path], env=ENV)
    assert result.exit_code == 0, result.output
    assert "Applied 13 change(s)" in result.output and "risk_scales" in result.output
    assert "nothing to change" in cli.invoke(app, ["import", path], env=ENV).output


def test_cli_prune_needs_confirmation(cli: CliRunner, fake: FakeThreatAtlasAPI, tmp_path: Path) -> None:
    cli.invoke(app, ["import", str(EXAMPLES / FRAMEWORK)], env=ENV)
    raw = example(FRAMEWORK)
    raw["threats"] = raw["threats"][1:]
    path = tmp_path / "fw.yaml"
    path.write_text(yaml.safe_dump(raw))
    result = cli.invoke(app, ["import", str(path), "--prune"], env=ENV)
    assert result.exit_code == 2 and "Add --yes" in result.output
    assert any(t["name"] == "Card-not-present fraud" for t in fake.threats.values())
    result = cli.invoke(app, ["import", str(path), "--prune", "--yes"], env=ENV)
    assert result.exit_code == 0, result.output
    assert not any(t["name"] == "Card-not-present fraud" for t in fake.threats.values())


def test_cli_reports_bad_files_and_schema(cli: CliRunner, tmp_path: Path) -> None:
    bad = tmp_path / "bad.yaml"
    bad.write_text("kind: framework\nframework: {name: X}\nthreats: [{name: A, mitigations: [Missing]}]\n")
    result = cli.invoke(app, ["import", str(bad)], env=ENV)
    assert result.exit_code == 3 and "isn't in this file" in result.output
    schema = json.loads(cli.invoke(app, ["import", "--schema", "threat-model"], env=ENV).stdout)
    assert "elements" in json.dumps(schema) and schema["title"].endswith("threat-model file")
    assert cli.invoke(app, ["import"], env=ENV).exit_code == 2


def test_cli_partial_failure_says_how_to_continue(
    cli: CliRunner, fake: FakeThreatAtlasAPI, monkeypatch: pytest.MonkeyPatch
) -> None:
    calls = {"n": 0}
    real_route = fake.route

    def failing(method: str, path: str, q: dict[str, str], body: dict[str, Any]) -> Any:
        if method == "POST" and path == "/mitigations":
            calls["n"] += 1
            if calls["n"] == 3:
                raise ValueError("database is locked")
        return real_route(method, path, q, body)

    monkeypatch.setattr(fake, "route", failing)
    result = cli.invoke(app, ["import", str(EXAMPLES / FRAMEWORK)], env=ENV)
    assert result.exit_code == 7
    assert "stopped after 3 change(s)" in result.output and "picks up where it left off" in result.output
    monkeypatch.setattr(fake, "route", real_route)
    result = cli.invoke(app, ["import", str(EXAMPLES / FRAMEWORK)], env=ENV)
    assert result.exit_code == 0 and "Applied 10 change(s)" in result.output
