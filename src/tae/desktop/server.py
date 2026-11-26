"""The desktop proof of concept: a local web page for generating and downloading reports.

It runs on the user's own machine, listens on 127.0.0.1 only, and acts with the
user's own ThreatAtlas API token, so ThreatAtlas's permissions apply unchanged.

Local web servers can be reached by any website the user visits, so every request
is checked:

- the Host header must be this server's own address (stops DNS rebinding);
- a random key, given only in the launch link, becomes a SameSite=Strict cookie that
  every page requires;
- forms carry a CSRF token, and an Origin header must be this server's;
- responses forbid framing, scripts and cross-origin loads (Content-Security-Policy).

The API token is kept in memory only, unless the user asks to remember it, in
which case it goes to the operating system's credential store.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import secrets
import subprocess
import sys
import threading
import webbrowser
from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from http import HTTPStatus
from http.cookies import SimpleCookie
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs, quote, urlparse, urlsplit

from jinja2 import Environment, FileSystemLoader, select_autoescape

from tae import __version__
from tae.client import ThreatAtlasClient
from tae.client import errors as api_errors
from tae.client.http import normalize_base_url
from tae.config import ConfigError, keyring_available, keyring_delete, keyring_set
from tae.desktop.runs import DOWNLOADABLE, Preset, ReportStore, RunManager
from tae.models.api import User
from tae.report.pdf import PdfEngine

log = logging.getLogger(__name__)

TEMPLATES = resources.files("tae.desktop") / "templates"
STATIC = resources.files("tae.desktop") / "static"
COOKIE = "tae_desktop"
MAX_BODY = 64 * 1024

SECURITY_HEADERS = {
    "Content-Security-Policy": (
        "default-src 'none'; style-src 'self'; img-src 'self'; form-action 'self'; "
        "frame-ancestors 'none'; base-uri 'none'"
    ),
    "X-Content-Type-Options": "nosniff",
    "X-Frame-Options": "DENY",
    # "same-origin", not "no-referrer": with no-referrer, Chromium sends "Origin: null" on the
    # app's own form posts, which the Origin check (rightly) refuses.
    "Referrer-Policy": "same-origin",
    "Cache-Control": "no-store",
    "Cross-Origin-Opener-Policy": "same-origin",
    "Cross-Origin-Resource-Policy": "same-origin",
}


@dataclass
class Connection:
    url: str | None = None
    token: str | None = None
    user: User | None = None
    remembered: bool = False
    notice: str | None = None  # shown once on the next page, e.g. "token could not be remembered"


@dataclass
class DesktopApp:
    store: ReportStore
    runs: RunManager
    presets: list[Preset]
    engine_label: str
    client_options: dict[str, Any] = field(default_factory=dict)
    connection: Connection = field(default_factory=Connection)
    launch_key: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    csrf_token: str = field(default_factory=lambda: secrets.token_urlsafe(32))
    port: int = 0
    opener: Callable[[Path], None] | None = None

    def __post_init__(self) -> None:
        self.templates = Environment(
            loader=FileSystemLoader(str(TEMPLATES)),
            autoescape=select_autoescape(default=True, default_for_string=True),
            trim_blocks=True,
            lstrip_blocks=True,
        )
        self.templates.filters["when"] = _when
        self._lock = threading.Lock()

    # ── connection ─────────────────────────────────────────────────────────────

    def client(self, url: str | None = None, token: str | None = None) -> ThreatAtlasClient:
        url = url or self.connection.url
        token = token or self.connection.token
        if not url or not token:
            raise api_errors.AuthenticationError(401, "GET", "", "Not signed in")
        return ThreatAtlasClient(url, token, **self.client_options)

    def sign_in(self, url: str, token: str, remember: bool = False) -> User:
        url = normalize_base_url(url)
        with self.client(url, token) as client:
            user = client.users.me()
        with self._lock:
            self.connection = Connection(url=url, token=token, user=user)
        if remember:
            try:
                keyring_set(url, token)
                self.connection.remembered = True
            except ConfigError as exc:
                # Signing in worked; only remembering failed (e.g. no credential store).
                log.warning("Could not remember the token: %s", exc)
                self.connection.notice = (
                    "You're signed in, but your token could not be remembered on this computer "
                    "(no usable credential store). You'll need to sign in again next time."
                )
        log.info("Signed in to %s as %s", url, user.username)
        return user

    def sign_out(self) -> None:
        """Sign out and forget any token remembered for this ThreatAtlas address.

        Always forgetting is deliberate: on a shared computer, "Sign out" must mean the
        next person to start the app is not signed in as you.
        """
        with self._lock:
            url = self.connection.url
            self.connection = Connection(url=url)
        if url:
            keyring_delete(url)

    def take_notice(self) -> str | None:
        with self._lock:
            notice, self.connection.notice = self.connection.notice, None
        return notice

    @property
    def signed_in(self) -> bool:
        return self.connection.user is not None

    def preset(self, preset_id: str) -> Preset | None:
        return next((p for p in self.presets if p.id == preset_id), None)

    def open_folder(self, path: Path) -> None:
        path.mkdir(parents=True, exist_ok=True)
        if self.opener is not None:
            self.opener(path)
        elif sys.platform == "win32":
            os.startfile(path)  # type: ignore[attr-defined]  # noqa: S606
        elif sys.platform == "darwin":
            subprocess.Popen(["open", str(path)])  # noqa: S603, S607
        else:
            subprocess.Popen(["xdg-open", str(path)])  # noqa: S603, S607

    def render(self, template: str, **ctx: Any) -> str:
        return self.templates.get_template(template).render(
            app=self,
            user=self.connection.user,
            url=self.connection.url,
            csrf=self.csrf_token,
            version=__version__,
            **ctx,
        )


def _when(iso: str | None) -> str:
    if not iso:
        return "—"
    try:
        dt = datetime.fromisoformat(iso)
    except ValueError:
        return iso
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone().strftime("%Y-%m-%d %H:%M")


# ── HTTP handling ─────────────────────────────────────────────────────────────────


class Handler(BaseHTTPRequestHandler):
    app: DesktopApp  # set on the subclass created in make_server()
    server_version = "tae-desktop"
    sys_version = ""

    def log_message(self, format: str, *args: Any) -> None:
        # The query string of /launch carries the key: never log query strings.
        path = self.path.split("?", 1)[0]
        log.debug("%s %s → %s", self.command, path, args[1] if len(args) > 1 else "")

    # Entry points ---------------------------------------------------------------

    def do_GET(self) -> None:
        self._dispatch("GET")

    def do_POST(self) -> None:
        self._dispatch("POST")

    def _dispatch(self, method: str) -> None:
        try:
            if not self._host_ok():
                self._plain(HTTPStatus.BAD_REQUEST, "Bad Host header")
                return
            parsed = urlparse(self.path)
            path = parsed.path
            if method == "GET" and path == "/static/app.css":
                self._static("app.css", "text/css; charset=utf-8")
                return
            if method == "GET" and path == "/launch":
                self._launch(parse_qs(parsed.query))
                return
            if not self._session_ok():
                self._page(
                    HTTPStatus.FORBIDDEN,
                    "message.html.j2",
                    title="Open the app from its own link",
                    text="For your security, this page only works when opened from the link the app shows "
                    "when it starts. Close this tab and use that link, or restart the app.",
                    back=False,
                )
                return
            form: dict[str, str] = {}
            if method == "POST":
                parsed_form = self._read_form()
                if parsed_form is None:
                    return
                form = parsed_form
            self._route(method, path, parse_qs(parsed.query), form)
        except api_errors.AuthenticationError:
            self.app.sign_out()  # also drops a remembered token that no longer works
            self._redirect("/?expired=1")
        except api_errors.ThreatAtlasError as exc:
            self._page(
                HTTPStatus.BAD_GATEWAY, "message.html.j2", title="ThreatAtlas request failed", text=str(exc)
            )
        except Exception:
            log.exception("Unexpected error handling %s %s", method, self.path.split("?", 1)[0])
            self._page(
                HTTPStatus.INTERNAL_SERVER_ERROR,
                "message.html.j2",
                title="Something went wrong",
                text="An unexpected error occurred. Details are in the app's console window.",
            )

    # Security checks ---------------------------------------------------------------

    def _allowed_hosts(self) -> set[str]:
        return {f"127.0.0.1:{self.app.port}", f"localhost:{self.app.port}"}

    def _host_ok(self) -> bool:
        return self.headers.get("Host", "") in self._allowed_hosts()

    def _cookie(self) -> str | None:
        raw = self.headers.get("Cookie")
        if not raw:
            return None
        jar: SimpleCookie = SimpleCookie()
        try:
            jar.load(raw)
        except Exception:
            return None
        morsel = jar.get(COOKIE)
        return morsel.value if morsel else None

    def _session_ok(self) -> bool:
        value = self._cookie()
        return value is not None and hmac.compare_digest(value, self.app.launch_key)

    def _launch(self, query: dict[str, list[str]]) -> None:
        key = (query.get("k") or [""])[0]
        if not hmac.compare_digest(key, self.app.launch_key):
            self._plain(HTTPStatus.FORBIDDEN, "Invalid launch link")
            return
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Set-Cookie", f"{COOKIE}={self.app.launch_key}; HttpOnly; SameSite=Strict; Path=/")
        self.send_header("Location", "/")
        self._security_headers()
        self.end_headers()

    def _read_form(self) -> dict[str, str] | None:
        origin = self.headers.get("Origin")
        if origin is not None and origin not in {f"http://{h}" for h in self._allowed_hosts()}:
            self._plain(HTTPStatus.FORBIDDEN, "Cross-origin request refused")
            return None
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            length = -1
        if length < 0 or length > MAX_BODY:
            self._plain(HTTPStatus.REQUEST_ENTITY_TOO_LARGE, "Request too large")
            return None
        ctype = self.headers.get("Content-Type", "").split(";", 1)[0].strip()
        if ctype != "application/x-www-form-urlencoded":
            self._plain(HTTPStatus.UNSUPPORTED_MEDIA_TYPE, "Unsupported form encoding")
            return None
        body = self.rfile.read(length).decode("utf-8", errors="replace")
        form = {k: v[0] for k, v in parse_qs(body, keep_blank_values=True).items()}
        if not hmac.compare_digest(form.get("csrf", ""), self.app.csrf_token):
            self._plain(
                HTTPStatus.FORBIDDEN, "Form expired or invalid. Go back, reload the page and try again."
            )
            return None
        return form

    # Routing ---------------------------------------------------------------------------

    def _route(self, method: str, path: str, query: dict[str, list[str]], form: dict[str, str]) -> None:
        app = self.app
        if method == "GET" and path == "/":
            if not app.signed_in:
                self._page(
                    HTTPStatus.OK,
                    "signin.html.j2",
                    expired="expired" in query,
                    error=None,
                    form_url=app.connection.url or "",
                )
                return
            self._products()
            return
        if method == "POST" and path == "/signin":
            self._signin(form)
            return
        if method == "POST" and path == "/signout":
            app.sign_out()
            self._redirect("/")
            return
        if method == "POST" and path == "/open-folder":
            app.open_folder(app.store.root)
            self._redirect(safe_local_path(form.get("back", "/")))
            return
        if not app.signed_in:
            self._redirect("/")
            return

        m = re.fullmatch(r"/products/(\d+)", path)
        if m and method == "GET":
            self._product(int(m.group(1)))
            return
        m = re.fullmatch(r"/products/(\d+)/generate", path)
        if m and method == "POST":
            self._generate(int(m.group(1)), form.get("preset", ""))
            return
        m = re.fullmatch(r"/products/(\d+)/runs/([0-9A-Za-z-]+)", path)
        if m and method == "GET":
            self._run(int(m.group(1)), m.group(2))
            return
        m = re.fullmatch(r"/products/(\d+)/runs/([0-9A-Za-z-]+)/([a-z]+\.(?:pdf|json))", path)
        if m and method == "GET":
            self._file(int(m.group(1)), m.group(2), m.group(3), download="download" in query)
            return
        self._page(
            HTTPStatus.NOT_FOUND,
            "message.html.j2",
            title="Not found",
            text="There is nothing at this address.",
        )

    # Pages ---------------------------------------------------------------------------

    def _signin(self, form: dict[str, str]) -> None:
        url, token = form.get("url", "").strip(), form.get("token", "").strip()
        remember = form.get("remember") == "1"
        error = None
        if not url or not token:
            error = "Enter both the ThreatAtlas address and your API token."
        else:
            try:
                self.app.sign_in(url, token, remember=remember and keyring_available())
            except ValueError as exc:
                error = str(exc)
            except api_errors.AuthenticationError:
                error = "ThreatAtlas rejected this token. Check it hasn't expired, or create a new one."
            except api_errors.ThreatAtlasError as exc:
                error = f"Could not reach ThreatAtlas: {exc}"
        if error:
            self._page(HTTPStatus.OK, "signin.html.j2", expired=False, error=error, form_url=url)
            return
        self._redirect("/")

    def _products(self) -> None:
        with self.app.client() as client:
            products = sorted(client.products.list(), key=lambda p: p.name.casefold())
        counts = self.app.store.counts()
        self._page(
            HTTPStatus.OK, "products.html.j2", products=products, counts=counts, notice=self.app.take_notice()
        )

    def _product(self, product_id: int) -> None:
        try:
            with self.app.client() as client:
                product = client.products.get(product_id)
        except api_errors.NotFound:
            self._page(
                HTTPStatus.NOT_FOUND,
                "message.html.j2",
                title="Product not found",
                text="This product doesn't exist, or your ThreatAtlas account can't see it.",
            )
            return
        self._page(
            HTTPStatus.OK,
            "product.html.j2",
            product=product,
            runs=self.app.store.runs(product_id),
            active=self.app.runs.active_run(product_id),
            presets=self.app.presets,
        )

    def _generate(self, product_id: int, preset_id: str) -> None:
        preset = self.app.preset(preset_id)
        if preset is None:
            self._page(HTTPStatus.BAD_REQUEST, "message.html.j2", title="Unknown report type", text=preset_id)
            return
        with self.app.client() as client:
            product = client.products.get(product_id)
        user = self.app.connection.user
        run_id, _started = self.app.runs.start(
            product,
            preset,
            self.app.client,
            user=user.username if user else None,
            source_url=self.app.connection.url or "",
        )
        self._redirect(f"/products/{product_id}/runs/{run_id}")

    def _run(self, product_id: int, run_id: str) -> None:
        run_dir = self.app.store.run_dir(product_id, run_id)
        record = self.app.store.load(run_dir) if run_dir else None
        if record is None:
            self._page(
                HTTPStatus.NOT_FOUND, "message.html.j2", title="Report not found", text="No such report run."
            )
            return
        self._page(HTTPStatus.OK, "run.html.j2", run=record, folder=str(run_dir))

    def _file(self, product_id: int, run_id: str, name: str, download: bool) -> None:
        path = self.app.store.file(product_id, run_id, name)
        if path is None:
            self._page(HTTPStatus.NOT_FOUND, "message.html.j2", title="File not found", text=name)
            return
        record = self.app.store.load(path.parent)
        stem = re.sub(
            r"[^A-Za-z0-9._-]+", "-", f"{record.product_name if record else 'report'}-{run_id[:15]}"
        )
        filename = f"{stem}-{name}"
        disposition = "attachment" if download or not name.endswith(".pdf") else "inline"
        data = path.read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", DOWNLOADABLE[name])
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Content-Disposition", f"{disposition}; filename*=UTF-8''{quote(filename)}")
        # The browser's own PDF viewer needs to run, so only the non-CSP headers apply here.
        for header in (
            "X-Content-Type-Options",
            "Referrer-Policy",
            "Cache-Control",
            "Cross-Origin-Resource-Policy",
        ):
            self.send_header(header, SECURITY_HEADERS[header])
        self.end_headers()
        self.wfile.write(data)

    # Response helpers ------------------------------------------------------------

    def _security_headers(self) -> None:
        for name, value in SECURITY_HEADERS.items():
            self.send_header(name, value)

    def _page(self, status: HTTPStatus, template: str, **ctx: Any) -> None:
        body = self.app.render(template, **ctx).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _plain(self, status: HTTPStatus, text: str) -> None:
        body = text.encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "text/plain; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.end_headers()
        self.wfile.write(body)

    def _redirect(self, location: str) -> None:
        self.send_response(HTTPStatus.SEE_OTHER)
        self.send_header("Location", location)
        self.send_header("Content-Length", "0")
        self._security_headers()
        self.end_headers()

    def _static(self, name: str, ctype: str) -> None:
        body = (STATIC / name).read_bytes()
        self.send_response(HTTPStatus.OK)
        self.send_header("Content-Type", ctype)
        self.send_header("Content-Length", str(len(body)))
        self._security_headers()
        self.send_header("Cache-Control", "max-age=300")
        self.end_headers()
        self.wfile.write(body)


def safe_local_path(target: str) -> str:
    """Return ``target`` if it is a path on this app, else ``/``.

    Browsers read ``//host`` and ``/\\host`` as other sites, so both are refused, as is
    anything with a scheme, a host, a backslash or control characters.
    """
    parts = urlsplit(target)
    if (
        not target.startswith("/")
        or target.startswith("//")
        or "\\" in target
        or parts.scheme
        or parts.netloc
        or any(ord(c) < 32 or ord(c) == 127 for c in target)
    ):
        return "/"
    return target


def make_server(app: DesktopApp, port: int = 0) -> ThreadingHTTPServer:
    """Bind to 127.0.0.1 (never other interfaces) and return the server."""
    handler = type("BoundHandler", (Handler,), {"app": app})
    server = ThreadingHTTPServer(("127.0.0.1", port), handler)
    server.daemon_threads = True
    app.port = server.server_address[1]
    return server


def launch_url(app: DesktopApp) -> str:
    return f"http://127.0.0.1:{app.port}/launch?k={app.launch_key}"


def open_browser(url: str) -> bool:
    try:
        return webbrowser.open(url, new=2)
    except webbrowser.Error:
        return False


def engine_label(engine: PdfEngine) -> str:
    return {"weasyprint": "WeasyPrint", "browser": "Edge/Chrome (headless)"}.get(engine.value, engine.value)
