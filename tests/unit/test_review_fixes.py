"""Regression tests for the review of the API client, config and read-only commands."""

from __future__ import annotations

import json
import ssl
import warnings
from pathlib import Path
from typing import ClassVar

import certifi
import httpx
import pytest
import respx
import truststore
from typer.testing import CliRunner

from tae.cli.app import app
from tae.client import ThreatAtlasClient
from tae.client import errors as e
from tae.client.http import HttpClient
from tae.config import ConfigError, Overrides, load_config_file, resolve
from tae.output import OutputFormat, dumps, safe_text
from tests.conftest import BASE, load

ENV = {"TAE_URL": BASE, "TAE_TOKEN": "ta_x", "COLUMNS": "200"}
ESC = "\x1b"


def client(**kw: object) -> HttpClient:
    return HttpClient(BASE, "ta_x", sleep=lambda s: None, **kw)  # type: ignore[arg-type]


# ── paging ───────────────────────────────────────────────────────────────────────


def test_paging_skips_repeated_ids(api: respx.MockRouter) -> None:
    # ThreatAtlas doesn't order most lists, so offset pages can overlap.
    api.get("/products", params={"skip": "0"}).respond(json=[{"id": 1}, {"id": 2}])
    api.get("/products", params={"skip": "2"}).respond(json=[{"id": 2}, {"id": 3}])
    api.get("/products", params={"skip": "4"}).respond(json=[{"id": 4}])
    assert [i["id"] for i in client().paginate("/products", page_size=2)] == [1, 2, 3, 4]


def test_large_default_page(api: respx.MockRouter) -> None:
    route = api.get("/products").respond(json=load("products"))
    ThreatAtlasClient(BASE, "ta_x").products.list()
    assert route.calls.last.request.url.params["limit"] == "1000"
    assert route.call_count == 1


# ── Retry-After ────────────────────────────────────────────────────────────────


@pytest.mark.parametrize("value", ["-5", "nan", "inf", "-inf", "Wed, 21 Oct 2026 07:28:00 GMT", ""])
def test_bad_retry_after_falls_back_to_backoff(api: respx.MockRouter, value: str) -> None:
    api.get("/products").mock(
        side_effect=[httpx.Response(503, headers={"Retry-After": value}), httpx.Response(200, json=[])]
    )
    sleeps: list[float] = []
    HttpClient(BASE, "ta_x", sleep=sleeps.append, backoff=0.5).get_json("/products")
    assert sleeps == [0.5]


def test_retry_after_zero_is_honoured(api: respx.MockRouter) -> None:
    api.get("/products").mock(
        side_effect=[httpx.Response(429, headers={"Retry-After": "0"}), httpx.Response(200, json=[])]
    )
    sleeps: list[float] = []
    HttpClient(BASE, "ta_x", sleep=sleeps.append).get_json("/products")
    assert sleeps == [0.0]


# ── no replay of writes ─────────────────────────────────────────────────────────


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_writes_are_not_replayed_after_reaching_the_server(api: respx.MockRouter, method: str) -> None:
    route = api.route(method=method, path="/diagrams/42").mock(side_effect=httpx.ReadTimeout("slow"))
    with pytest.raises(e.ConnectionFailed):
        client().request(method, "/diagrams/42", json={} if method == "PUT" else None)
    assert route.call_count == 1
    route = api.route(method=method, path="/diagrams/43").respond(504)
    with pytest.raises(e.ServerError):
        client().request(method, "/diagrams/43", json={} if method == "PUT" else None)
    assert route.call_count == 1


@pytest.mark.parametrize("method", ["PUT", "DELETE"])
def test_writes_are_retried_when_never_sent(api: respx.MockRouter, method: str) -> None:
    route = api.route(method=method, path="/diagrams/42").mock(
        side_effect=[httpx.ConnectError("refused"), httpx.Response(429), httpx.Response(204)]
    )
    client().request(method, "/diagrams/42")
    assert route.call_count == 3


# ── security-status ────────────────────────────────────────────────────────────

STATUS = {
    "product_id": 12,
    "product_name": "Payments API",
    "thresholds": {"fail_on_critical": True, "fail_on_unmitigated_high": False, "min_mitigation_ratio": 0.8},
    "summary": {"total_threats": 5, "by_severity": {"critical": 3, "high": 1, "medium": 1, "low": 0, "unscored": 0},
                "total_mitigations": 2, "active_mitigations": 1, "mitigated_threats": 1, "mitigation_ratio": 0.2},
    "pass": False,
    "failures": ["3 critical threat(s) require immediate attention", "Mitigation ratio 20% is below required threshold 80%"],
}  # fmt: skip


def test_security_status_thresholds_and_exit_code(api: respx.MockRouter) -> None:
    route = api.get("/products/12/security-status").respond(json=STATUS)
    result = CliRunner().invoke(
        app,
        ["products", "security-status", "12", "--fail-on-critical", "--min-mitigation-ratio", "0.8"],
        env=ENV,
    )
    assert result.exit_code == 10, result.output
    params = route.calls.last.request.url.params
    assert params["fail_on_critical"] == "true" and params["min_mitigation_ratio"] == "0.8"
    assert "fail_on_unmitigated_high" not in params
    assert "summary.by_severity.critical" in result.output and "3 critical threat(s)" in result.output
    assert "use -o json" not in result.output


def test_security_status_without_thresholds_says_so(api: respx.MockRouter) -> None:
    api.get("/products/12/security-status").respond(json={**STATUS, "pass": True, "failures": []})
    result = CliRunner().invoke(app, ["products", "security-status", "12"], env=ENV)
    assert result.exit_code == 0
    assert "always passes" in result.output


# ── auth login ───────────────────────────────────────────────────────────────


class FakeKeyring:
    stored: ClassVar[dict[str, str]] = {}

    @staticmethod
    def get_password(service: str, user: str) -> str | None:
        return FakeKeyring.stored.get(user)

    @staticmethod
    def set_password(service: str, user: str, token: str) -> None:
        FakeKeyring.stored[user] = token


def test_login_works_with_a_broken_token_file(
    api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch, tmp_path: Path
) -> None:
    FakeKeyring.stored = {}
    monkeypatch.setattr("tae.config._keyring", lambda: FakeKeyring)
    api.get("/auth/me").respond(json=load("me"))
    env = {"TAE_URL": BASE, "TAE_TOKEN_FILE": str(tmp_path / "deleted")}
    result = CliRunner().invoke(app, ["auth", "login", "--token-stdin"], input="ta_new\n", env=env)
    assert result.exit_code == 0, result.output
    assert FakeKeyring.stored == {BASE: "ta_new"}
    assert "broken and takes precedence" in result.output


def test_login_warns_when_env_token_wins(api: respx.MockRouter, monkeypatch: pytest.MonkeyPatch) -> None:
    FakeKeyring.stored = {}
    monkeypatch.setattr("tae.config._keyring", lambda: FakeKeyring)
    api.get("/auth/me").respond(json=load("me"))
    result = CliRunner().invoke(app, ["auth", "login", "--token-stdin"], input="ta_new\n", env=ENV)
    assert result.exit_code == 0
    assert "TAE_TOKEN takes precedence" in result.output


# ── config value types ─────────────────────────────────────────────────────────


@pytest.mark.parametrize(
    ("line", "message"),
    [
        ("url = 8080", "url must be a string"),
        ("ca_bundle = true", "ca_bundle must be a string"),
        ("token_file = 1", "token_file must be a string"),
        ("retries = true", "retries must be a number"),
        ('timeout = "slow"', "timeout must be a number"),
        ("timeout = 0", "timeout must be positive"),
        ("retries = -1", "retries zero or more"),
    ],
)
def test_config_value_types(tmp_path: Path, line: str, message: str) -> None:
    path = tmp_path / "c.toml"
    path.write_text(
        f'[profiles.p]\nurl = "https://a.test"\n{line}\n'.replace('url = "https://a.test"\nurl', "url")
    )
    with pytest.raises(ConfigError, match=message):
        load_config_file(path)


def test_config_type_error_is_a_clean_cli_error(tmp_path: Path) -> None:
    path = tmp_path / "c.toml"
    path.write_text('default_profile = "p"\n[profiles.p]\nurl = 8080\n')
    result = CliRunner().invoke(app, ["products", "list"], env={"TAE_CONFIG": str(path), "TAE_TOKEN": "ta_x"})
    assert result.exit_code == 3
    assert "url must be a string" in result.output


# ── users endpoint ──────────────────────────────────────────────────────────────


def test_users_endpoint_matches_upstream(api: respx.MockRouter) -> None:
    c = ThreatAtlasClient(BASE, "ta_x")
    with pytest.raises(NotImplementedError):
        c.users.get(3)
    route = api.get("/users").respond(json=[load("me")] * 150)  # upstream ignores skip/limit
    assert len(c.users._list()) == 150
    assert route.call_count == 1 and "skip" not in route.calls.last.request.url.params


# ── TLS context ─────────────────────────────────────────────────────────────────


def settings_with(env: dict[str, str]):  # type: ignore[no-untyped-def]
    return resolve(Overrides(url="https://a.test"), env=env)


def test_tls_context_from_ca_bundle_without_deprecation_warning() -> None:
    ctx = settings_with({"TAE_CA_BUNDLE": certifi.where()}).ssl_context()
    assert isinstance(ctx, ssl.SSLContext) and ctx.verify_mode is ssl.CERT_REQUIRED
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        ThreatAtlasClient(
            "https://a.test", "ta_x", **settings_with({"TAE_CA_BUNDLE": certifi.where()}).client_options()
        ).close()


def test_tls_default_uses_the_os_store() -> None:
    assert isinstance(settings_with({}).ssl_context(), truststore.SSLContext)
    assert settings_with({"TAE_VERIFY_TLS": "false"}).ssl_context() is False


def test_invalid_ca_bundle_is_a_config_error(tmp_path: Path) -> None:
    bad = tmp_path / "ca.pem"
    bad.write_text("not a certificate")
    with pytest.raises(ConfigError, match="not a readable PEM"):
        settings_with({"TAE_CA_BUNDLE": str(bad)}).ssl_context()


# ── terminal escape sequences from server data ──────────────────────────────────


def test_safe_text() -> None:
    assert safe_text("a\x1b[2Jb") == "a\\x1b[2Jb"
    assert safe_text("tab\tand\nnewline") == "tab\tand\nnewline"
    assert safe_text("x\x9by‮z\x7f") == "x\\x9by\\u202ez\\x7f"
    assert safe_text(None) == "None"


def test_json_output_escapes_c1_and_bidi() -> None:
    text = dumps({"n": "a\x1bb\x9bc‮d"}, OutputFormat.json)
    assert "\x9b" not in text and "‮" not in text and ESC not in text
    assert json.loads(text)["n"] == "a\x1bb\x9bc‮d"  # same value once parsed


PAYLOAD = "Evil\x1b]52;c;ZWNobyBwd25lZA==\x07\x1b[2J[bold]X[/bold]"


def test_tables_and_errors_never_emit_escape_sequences(api: respx.MockRouter) -> None:
    api.get("/products").respond(json=[{**load("products")[0], "name": PAYLOAD}])
    api.get("/products/12").respond(json={**load("products")[0], "owner_name": PAYLOAD})
    api.get("/products/13").respond(404, json={"detail": PAYLOAD})
    api.get("/auth/me").respond(json={**load("me"), "username": PAYLOAD})
    runner = CliRunner()
    for args in (
        ["products", "list"],
        ["products", "get", "12"],
        ["products", "get", "13"],
        ["auth", "status"],
    ):
        result = runner.invoke(app, args, env=ENV, color=True)
        assert "\x1b]52" not in result.output and "\x1b[2J" not in result.output, args
        assert "\\x1b]52" in result.output, args  # shown, harmlessly
        assert "[bold]X[/bold]" in result.output, args  # and not interpreted as markup


def test_progress_messages_are_sanitised(api: respx.MockRouter, tmp_path: Path) -> None:
    from tests.unit.test_snapshot import mock_product_endpoints

    diagrams = load("diagrams")
    diagrams[0]["name"] = PAYLOAD
    api.get("/products/12").respond(json=load("products")[0])
    mock_product_endpoints(api)
    api.get("/diagrams").respond(json=diagrams)
    result = CliRunner().invoke(
        app, ["pull", "-P", "12", "-f", str(tmp_path / "s.json")], env=ENV, color=True
    )
    assert result.exit_code == 0, result.output
    assert "\x1b[2J" not in result.output and "[bold]X[/bold]" in result.output
