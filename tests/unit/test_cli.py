from __future__ import annotations

import json

import pytest
import respx
import yaml
from typer.testing import CliRunner

from tae import __version__
from tae.cli.app import app
from tests.conftest import BASE, load

ENV = {"TAE_URL": BASE, "TAE_TOKEN": "ta_supersecret", "COLUMNS": "200"}


@pytest.fixture
def runner() -> CliRunner:
    return CliRunner()


def run(runner: CliRunner, *args: str, env: dict[str, str] | None = None):  # type: ignore[no-untyped-def]
    return runner.invoke(app, list(args), env=ENV if env is None else env)


def test_version(runner: CliRunner) -> None:
    result = run(runner, "--version")
    assert result.exit_code == 0
    assert __version__ in result.output


def test_products_list_table(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products").respond(json=load("products"))
    result = run(runner, "products", "list")
    assert result.exit_code == 0, result.output
    assert "Payments API" in result.output
    assert "Customer Portal" in result.output


def test_products_list_json_is_parseable(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products").respond(json=load("products"))
    result = run(runner, "-o", "json", "products", "list")
    assert result.exit_code == 0, result.output
    data = json.loads(result.stdout)
    assert data[0]["id"] == 12


def test_threats_list_yaml(runner: CliRunner, api: respx.MockRouter) -> None:
    route = api.get("/diagram-threats").respond(json=load("diagram_threats"))
    result = run(runner, "-o", "yaml", "threats", "list", "--diagram", "31")
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.url.params["diagram_id"] == "31"
    assert yaml.safe_load(result.stdout)[0]["threat"]["name"] == "SQL injection"


def test_threats_catalog_list(runner: CliRunner, api: respx.MockRouter) -> None:
    route = api.get("/threats").respond(json=load("threats"))
    result = run(runner, "threats", "catalog", "list", "--framework", "1", "--builtin")
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.url.params["is_custom"] == "false"
    assert "Spoofed client" in result.output


def test_mitigations_list(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/diagram-mitigations").respond(json=load("diagram_mitigations"))
    result = run(runner, "mitigations", "list", "-d", "31")
    assert result.exit_code == 0, result.output
    assert "Parameterised queries" in result.output


def test_diagram_get_table_hides_raw_data(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/diagrams/31").respond(json=load("diagrams")[0])
    result = run(runner, "diagrams", "get", "31")
    assert result.exit_code == 0, result.output
    assert "4 nodes, 2 edges" in result.output
    assert "Transactions DB" not in result.output


def test_diagram_get_json_includes_data(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/diagrams/31").respond(json=load("diagrams")[0])
    result = run(runner, "-o", "json", "diagrams", "get", "31")
    assert json.loads(result.stdout)["diagram_data"]["nodes"][2]["data"]["label"] == "Transactions DB"


def test_models_and_versions(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/models/diagram/31").respond(json=load("models"))
    api.get("/diagram-versions/31/versions").respond(json=load("versions"))
    assert "STRIDE review 2026" in run(runner, "models", "list", "-d", "31").output
    assert "Added DMZ" in run(runner, "diagrams", "versions", "list", "31").output


def test_risks_pending_hides_reviewed(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/approvals/my").respond(json=load("approvals"))
    result = run(runner, "risks", "pending")
    assert "Spoofed client" in result.output
    assert "Log tampering" not in result.output
    assert "Log tampering" in run(runner, "risks", "pending", "--all").output


def test_empty_list_message(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/frameworks").respond(json=[])
    result = run(runner, "frameworks", "list")
    assert result.exit_code == 0
    assert "No frameworks found" in result.output


def test_not_found_exit_code(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products/99").respond(404, json={"detail": "Product not found"})
    result = run(runner, "products", "get", "99")
    assert result.exit_code == 5
    assert "Product not found" in result.output


def test_auth_failure_exit_code_and_hint(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/products").respond(401, json={"detail": "API token expired"})
    result = run(runner, "products", "list")
    assert result.exit_code == 4
    assert "tae auth login" in result.output


def test_missing_token_exit_code(runner: CliRunner) -> None:
    result = run(runner, "products", "list", env={"TAE_URL": BASE})
    assert result.exit_code == 3
    assert "No API token found" in result.output


def test_missing_url_exit_code(runner: CliRunner) -> None:
    result = run(runner, "products", "list", env={"TAE_TOKEN": "ta_x"})
    assert result.exit_code == 3
    assert "No ThreatAtlas URL" in result.output


def test_connection_error_exit_code(
    runner: CliRunner, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    import httpx

    monkeypatch.setattr("tae.client.http.time.sleep", lambda s: None)
    api.get("/products").mock(side_effect=httpx.ConnectError("[SSL: CERTIFICATE_VERIFY_FAILED]"))
    result = run(runner, "--timeout", "1", "products", "list", env={**ENV, "TAE_CONFIG": ""})
    assert result.exit_code == 6
    assert "TAE_CA_BUNDLE" in result.output


def test_config_show_never_prints_token(runner: CliRunner) -> None:
    result = run(runner, "config", "show")
    assert result.exit_code == 0, result.output
    assert "set (from TAE_TOKEN)" in result.output
    assert "ta_supersecret" not in result.output


def test_auth_status(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/auth/me").respond(json=load("me"))
    result = run(runner, "auth", "status")
    assert result.exit_code == 0, result.output
    assert "analyst <analyst@example.com> (role: standard)" in result.output
    assert "ta_supersecret" not in result.output


def test_auth_login_stores_verified_token(
    runner: CliRunner, api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored: dict[str, str] = {}

    class FakeKeyring:
        @staticmethod
        def get_password(service: str, user: str) -> None:
            return None

        @staticmethod
        def set_password(service: str, user: str, token: str) -> None:
            stored[user] = token

    monkeypatch.setattr("tae.config._keyring", lambda: FakeKeyring)
    route = api.get("/auth/me").respond(json=load("me"))
    result = runner.invoke(app, ["auth", "login", "--token-stdin"], input="ta_new\n", env={"TAE_URL": BASE})
    assert result.exit_code == 0, result.output
    assert route.calls.last.request.headers["Authorization"] == "Bearer ta_new"
    assert stored == {BASE: "ta_new"}


def test_auth_login_rejects_bad_token(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/auth/me").respond(401, json={"detail": "Could not validate credentials"})
    result = runner.invoke(app, ["auth", "login", "--token-stdin"], input="ta_bad\n", env={"TAE_URL": BASE})
    assert result.exit_code == 4


def test_auth_login_without_keyring(runner: CliRunner, api: respx.MockRouter) -> None:
    api.get("/auth/me").respond(json=load("me"))
    result = runner.invoke(app, ["auth", "login", "--token-stdin"], input="ta_new\n", env={"TAE_URL": BASE})
    assert result.exit_code == 3
    assert "keyring" in result.output


def test_server_text_is_not_rich_markup(runner: CliRunner, api: respx.MockRouter) -> None:
    product = {**load("products")[0], "name": "Legacy [bold]API[/bold] [/oops]"}
    api.get("/products").respond(json=[product])
    api.get("/products/12").respond(json=product)
    result = run(runner, "products", "list")
    assert result.exit_code == 0, result.output
    assert "[bold]API[/bold]" in result.output
    assert "[/oops]" in run(runner, "products", "get", "12").output
