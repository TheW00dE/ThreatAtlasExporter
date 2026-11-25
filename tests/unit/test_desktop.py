"""The desktop app over real HTTP, against a fake ThreatAtlas."""

from __future__ import annotations

import http.client
import json
import re
import threading
from collections.abc import Iterator
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlencode

import pytest

from tae.desktop.runs import ReportStore, RunManager, RunRecord, load_presets
from tae.desktop.server import DesktopApp, make_server
from tae.report.pdf import PdfEngine
from tests.fake_threatatlas import FakeThreatAtlas

TOKEN = "ta_demo"


@dataclass
class Resp:
    status: int
    headers: dict[str, str]
    body: bytes

    @property
    def text(self) -> str:
        return self.body.decode("utf-8", errors="replace")


class Browser:
    """A tiny HTTP client that behaves like a browser tab on the app."""

    def __init__(self, app: DesktopApp) -> None:
        self.app = app
        self.cookie: str | None = None

    @property
    def host(self) -> str:
        return f"127.0.0.1:{self.app.port}"

    def request(
        self,
        method: str,
        path: str,
        form: dict[str, str] | None = None,
        headers: dict[str, str] | None = None,
        raw_body: bytes | None = None,
    ) -> Resp:
        conn = http.client.HTTPConnection("127.0.0.1", self.app.port, timeout=30)
        hdrs = {"Host": self.host, **(headers or {})}
        if self.cookie and "Cookie" not in hdrs:
            hdrs["Cookie"] = self.cookie
        body = raw_body
        if form is not None:
            body = urlencode(form).encode()
            hdrs.setdefault("Content-Type", "application/x-www-form-urlencoded")
            hdrs.setdefault("Origin", f"http://{self.host}")
        conn.request(method, path, body=body, headers=hdrs)
        r = conn.getresponse()
        data = r.read()
        out = Resp(r.status, {k.lower(): v for k, v in r.getheaders()}, data)
        conn.close()
        return out

    def get(self, path: str, **kw: object) -> Resp:
        return self.request("GET", path, **kw)  # type: ignore[arg-type]

    def post(self, path: str, form: dict[str, str] | None = None, **kw: object) -> Resp:
        form = {"csrf": self.app.csrf_token, **(form or {})}
        return self.request("POST", path, form=form, **kw)  # type: ignore[arg-type]

    def launch(self) -> None:
        r = self.get(f"/launch?k={self.app.launch_key}")
        assert r.status == 303
        self.cookie = r.headers["set-cookie"].split(";", 1)[0]

    def sign_in(self, url: str, token: str = TOKEN, **extra: str) -> Resp:
        return self.post("/signin", {"url": url, "token": token, **extra})


@pytest.fixture
def fake() -> Iterator[FakeThreatAtlas]:
    with FakeThreatAtlas(TOKEN) as f:
        yield f


@pytest.fixture
def desktop(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> Iterator[tuple[DesktopApp, Browser]]:
    monkeypatch.setenv("NO_PROXY", "127.0.0.1,localhost")
    monkeypatch.setenv("no_proxy", "127.0.0.1,localhost")
    store = ReportStore(tmp_path / "reports")
    opened: list[Path] = []
    app = DesktopApp(
        store=store,
        runs=RunManager(store, PdfEngine.weasyprint),
        presets=load_presets(),
        engine_label="WeasyPrint",
        client_options={"retries": 0},
        opener=opened.append,
    )
    app.opened = opened  # type: ignore[attr-defined]
    server = make_server(app)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield app, Browser(app)
    finally:
        server.shutdown()
        server.server_close()


@pytest.fixture
def signed_in(desktop: tuple[DesktopApp, Browser], fake: FakeThreatAtlas) -> tuple[DesktopApp, Browser]:
    app, b = desktop
    b.launch()
    assert b.sign_in(fake.url).status == 303
    return app, b


# ── security ──────────────────────────────────────────────────────────────────


def test_binds_to_localhost_only(desktop: tuple[DesktopApp, Browser]) -> None:
    app, _ = desktop
    assert app.port > 0


def test_pages_need_the_launch_cookie(desktop: tuple[DesktopApp, Browser]) -> None:
    app, b = desktop
    assert b.get("/").status == 403
    assert b.get("/launch?k=wrong").status == 403
    r = b.get(f"/launch?k={app.launch_key}")
    assert r.status == 303
    cookie = r.headers["set-cookie"]
    assert "HttpOnly" in cookie and "SameSite=Strict" in cookie
    b.cookie = cookie.split(";", 1)[0]
    assert b.get("/").status == 200
    assert b.get("/", headers={"Cookie": "tae_desktop=forged"}).status == 403


def test_host_header_must_be_local(desktop: tuple[DesktopApp, Browser]) -> None:
    app, b = desktop
    b.launch()
    assert b.get("/", headers={"Host": "evil.example"}).status == 400
    assert b.get("/", headers={"Host": f"evil.example:{app.port}"}).status == 400
    assert b.get("/", headers={"Host": f"localhost:{app.port}"}).status == 200


def test_static_css_is_public_but_nothing_else(desktop: tuple[DesktopApp, Browser]) -> None:
    _, b = desktop
    r = b.get("/static/app.css")
    assert r.status == 200 and r.headers["content-type"].startswith("text/css")
    assert b.get("/static/../server.py").status == 403


def test_security_headers(desktop: tuple[DesktopApp, Browser]) -> None:
    _, b = desktop
    b.launch()
    r = b.get("/")
    csp = r.headers["content-security-policy"]
    assert "default-src 'none'" in csp and "frame-ancestors 'none'" in csp and "script-src" not in csp
    assert r.headers["x-frame-options"] == "DENY"
    assert r.headers["cache-control"] == "no-store"


def test_form_posts_are_protected(desktop: tuple[DesktopApp, Browser], fake: FakeThreatAtlas) -> None:
    app, b = desktop
    b.launch()
    ok = {"url": fake.url, "token": TOKEN}
    assert b.request("POST", "/signin", form={**ok, "csrf": "wrong"}).status == 403
    assert b.request("POST", "/signin", form=ok).status == 403  # no csrf at all
    for origin in ("https://evil.example", "null"):
        r = b.post("/signin", ok, headers={"Origin": origin})
        assert r.status == 403, origin
    r = b.request(
        "POST", "/signin", raw_body=b"{}", headers={"Content-Type": "application/json", "Content-Length": "2"}
    )
    assert r.status == 415
    r = b.request(
        "POST",
        "/signin",
        raw_body=b"x",
        headers={"Content-Type": "application/x-www-form-urlencoded", "Content-Length": str(10**7)},
    )
    assert r.status == 413
    assert not app.signed_in


# ── sign-in ────────────────────────────────────────────────────────────────────


def test_sign_in_and_out(desktop: tuple[DesktopApp, Browser], fake: FakeThreatAtlas) -> None:
    app, b = desktop
    b.launch()
    r = b.sign_in(fake.url, "ta_wrong")
    assert r.status == 200 and "rejected this token" in r.text
    assert b.sign_in(fake.url + "/api/").status == 303
    assert app.connection.url == fake.url
    page = b.get("/")
    assert "Payments API" in page.text and "Customer Portal" in page.text
    assert TOKEN not in page.text
    assert b.post("/signout").status == 303
    assert not app.signed_in
    assert "Sign in to ThreatAtlas" in b.get("/").text


def test_sign_in_validation(desktop: tuple[DesktopApp, Browser]) -> None:
    _, b = desktop
    b.launch()
    assert "Enter both" in b.sign_in("", "").text
    assert "http://" in b.sign_in("threatatlas.example", TOKEN).text  # URL without scheme


def test_remember_token_uses_keyring(
    desktop: tuple[DesktopApp, Browser], fake: FakeThreatAtlas, monkeypatch: pytest.MonkeyPatch
) -> None:
    stored: dict[str, str] = {}

    class FakeKeyring:
        @staticmethod
        def set_password(service: str, user: str, token: str) -> None:
            stored[user] = token

        @staticmethod
        def delete_password(service: str, user: str) -> None:
            stored.pop(user, None)

    monkeypatch.setattr("tae.config._keyring", lambda: FakeKeyring)
    _, b = desktop
    b.launch()
    b.sign_in(fake.url, remember="1")
    assert stored == {fake.url: TOKEN}
    b.post("/signout", {"forget": "1"})
    assert stored == {}


def test_revoked_token_signs_out(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    app.connection.token = "ta_revoked"
    r = b.get("/")
    assert r.status == 303 and r.headers["location"] == "/?expired=1"
    assert not app.signed_in
    assert "no longer accepts your token" in b.get("/?expired=1").text


# ── products and reports ──────────────────────────────────────────────────────


def test_product_page(signed_in: tuple[DesktopApp, Browser]) -> None:
    _, b = signed_in
    page = b.get("/products/12")
    assert page.status == 200
    for text in ("Payments API", "Full technical report", "Executive summary", "No reports yet"):
        assert text in page.text
    assert b.get("/products/999").status == 404
    assert b.get("/nope").status == 404


def generate(app: DesktopApp, b: Browser, preset: str) -> tuple[str, RunRecord]:
    r = b.post("/products/12/generate", {"preset": preset})
    assert r.status == 303, r.text
    location = r.headers["location"]
    run_id = location.rsplit("/", 1)[-1]
    app.runs.wait()
    run_dir = app.store.run_dir(12, run_id)
    assert run_dir is not None
    record = app.store.load(run_dir)
    assert record is not None
    return location, record


def test_generate_and_download(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    location, record = generate(app, b, "full-technical")
    assert record.status == "done", record.message
    assert record.user == "analyst"
    assert record.validation["passed"] is False
    assert set(record.files) == {"snapshot.json", "findings.json", "report.pdf"}

    page = b.get(location)
    assert "Open PDF" in page.text and 'http-equiv="refresh"' not in page.text

    pdf = b.get(location + "/report.pdf")
    assert pdf.status == 200 and pdf.body.startswith(b"%PDF")
    assert pdf.headers["content-type"] == "application/pdf"
    assert pdf.headers["content-disposition"].startswith("inline;")
    assert "content-security-policy" not in pdf.headers  # the browser's PDF viewer must run
    assert pdf.headers["x-content-type-options"] == "nosniff"
    dl = b.get(location + "/report.pdf?download=1")
    assert dl.headers["content-disposition"].startswith("attachment;")
    assert "Payments-API" in dl.headers["content-disposition"]
    findings = b.get(location + "/findings.json")
    assert findings.headers["content-disposition"].startswith("attachment;")
    assert json.loads(findings.body)["counts"]["error"] == 2

    history = b.get("/products/12").text
    assert record.run_id in history and "Full technical report" in history
    assert re.search(r"<td class=\"num\">1</td>", b.get("/").text)  # saved report count


def test_blocked_report_keeps_findings_only(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    location, record = generate(app, b, "audit-acceptance")
    assert record.status == "blocked"
    assert "report.pdf" not in record.files and "findings.json" in record.files
    assert b.get(location + "/report.pdf").status == 404
    assert "blocked" in b.get(location).text


def test_failed_run_is_reported(
    signed_in: tuple[DesktopApp, Browser], monkeypatch: pytest.MonkeyPatch
) -> None:
    app, b = signed_in

    def boom(*a: object, **k: object) -> None:
        raise RuntimeError("renderer exploded\nwith details")

    monkeypatch.setattr("tae.desktop.runs.write_pdf", boom)
    location, record = generate(app, b, "full-technical")
    assert record.status == "failed"
    assert record.message == "renderer exploded"
    assert "renderer exploded" in b.get(location).text


def test_generate_errors(signed_in: tuple[DesktopApp, Browser]) -> None:
    _, b = signed_in
    assert b.post("/products/12/generate", {"preset": "nope"}).status == 400
    assert b.post("/products/999/generate", {"preset": "full-technical"}).status == 502


def test_file_access_is_restricted(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    location, _ = generate(app, b, "full-technical")
    for path in (
        location + "/run.json",
        location + "/secret.pdf",
        "/products/12/runs/..%2f..%2f/report.pdf",
        "/products/12/runs/20260101T000000Z-00000000/report.pdf",
        "/products/13/runs/" + location.rsplit("/", 1)[-1] + "/report.pdf",
    ):
        assert b.get(path).status == 404, path


def test_open_folder(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    r = b.post("/open-folder", {"back": "/products/12"})
    assert r.status == 303 and r.headers["location"] == "/products/12"
    assert app.opened == [app.store.root]  # type: ignore[attr-defined]
    for evil in ("//evil.example/x", "https://evil.example"):
        assert b.post("/open-folder", {"back": evil}).headers["location"] == "/"


def test_one_run_per_product_at_a_time(signed_in: tuple[DesktopApp, Browser]) -> None:
    app, b = signed_in
    gate = threading.Event()
    original = app.runs._run

    def slow(*args: object) -> None:
        gate.wait(10)
        original(*args)  # type: ignore[arg-type]

    app.runs._run = slow  # type: ignore[method-assign]
    first = b.post("/products/12/generate", {"preset": "full-technical"}).headers["location"]
    assert "is being generated" in b.get("/products/12").text
    second = b.post("/products/12/generate", {"preset": "executive-summary"}).headers["location"]
    assert first == second
    assert 'http-equiv="refresh"' in b.get(first).text
    gate.set()
    app.runs.wait()


# ── storage ──────────────────────────────────────────────────────────────────


def test_interrupted_runs_are_marked(tmp_path: Path) -> None:
    store = ReportStore(tmp_path)
    run_dir = tmp_path / "12-payments-api" / "20260101T000000Z-0000abcd"
    run_dir.mkdir(parents=True)
    store.save(
        run_dir,
        RunRecord("20260101T000000Z-0000abcd", 12, "Payments API", "x", "X", "2026-01-01T00:00:00+00:00"),
    )
    assert store.mark_interrupted() == 1
    assert store.runs(12)[0].status == "interrupted"
    assert store.mark_interrupted() == 0


def test_custom_presets(tmp_path: Path) -> None:
    (tmp_path / "Board Pack.yaml").write_text("title: Board pack\n")
    presets = load_presets(tmp_path)
    assert [p.id for p in presets][:3] == ["full-technical", "executive-summary", "audit-acceptance"]
    assert presets[-1].id == "custom-board-pack"


def test_builtin_presets_are_valid() -> None:
    from tae.report.definition import ReportDefinition

    for preset in load_presets():
        ReportDefinition.load(preset.path)
