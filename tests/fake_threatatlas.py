"""A minimal fake ThreatAtlas API serving the test fixtures over real HTTP.

Used by end-to-end tests of the desktop app (and handy for trying the UI locally):

    python -m tests.fake_threatatlas 8001 ta_demo
"""

from __future__ import annotations

import contextlib
import json
import re
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any
from urllib.parse import parse_qs, urlparse

from tests.conftest import load


def _routes() -> list[tuple[re.Pattern[str], Any]]:
    products = load("products")
    diagrams = load("diagrams")
    by_diagram = lambda name: lambda q, d: [x for x in load(name) if str(x["diagram_id"]) == d]  # noqa: E731
    return [
        (re.compile(r"/api/auth/me"), lambda q: load("me")),
        (re.compile(r"/api/products"), lambda q: products),
        (
            re.compile(r"/api/products/(\d+)"),
            lambda q, i: next((p for p in products if str(p["id"]) == i), None),
        ),
        (re.compile(r"/api/frameworks"), lambda q: load("frameworks")),
        (
            re.compile(r"/api/diagrams"),
            lambda q: [d for d in diagrams if str(d["product_id"]) == q.get("product_id", [""])[0]],
        ),
        (
            re.compile(r"/api/diagrams/(\d+)"),
            lambda q, i: next((d for d in diagrams if str(d["id"]) == i), None),
        ),
        (
            re.compile(r"/api/models/diagram/(\d+)"),
            lambda q, d: [m for m in load("models") if str(m["diagram_id"]) == d],
        ),
        (
            re.compile(r"/api/diagram-threats"),
            lambda q: by_diagram("diagram_threats")(q, q.get("diagram_id", [""])[0]),
        ),
        (
            re.compile(r"/api/diagram-mitigations"),
            lambda q: by_diagram("diagram_mitigations")(q, q.get("diagram_id", [""])[0]),
        ),
    ]


class FakeThreatAtlas:
    def __init__(self, token: str = "ta_demo", port: int = 0) -> None:  # noqa: S107  (test token)
        routes = _routes()
        expected = f"Bearer {token}"

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args: Any) -> None:
                pass

            def do_GET(self) -> None:
                if self.headers.get("Authorization") != expected:
                    return self._send(401, {"detail": "Could not validate credentials"})
                parsed = urlparse(self.path)
                query = parse_qs(parsed.query)
                for pattern, handler in routes:
                    m = pattern.fullmatch(parsed.path)
                    if m:
                        data = handler(query, *m.groups())
                        if data is None:
                            return self._send(404, {"detail": "Not found"})
                        if isinstance(data, list) and query.get("skip", ["0"])[0] != "0":
                            data = []  # everything fits on the first page
                        return self._send(200, data)
                return self._send(404, {"detail": "Not found"})

            def _send(self, status: int, data: Any) -> None:
                body = json.dumps(data).encode()
                self.send_response(status)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)

        self.server = ThreadingHTTPServer(("127.0.0.1", port), Handler)
        self.url = f"http://127.0.0.1:{self.server.server_address[1]}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def __enter__(self) -> FakeThreatAtlas:
        self.thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self.server.shutdown()
        self.server.server_close()


if __name__ == "__main__":
    port = int(sys.argv[1]) if len(sys.argv) > 1 else 8001
    token = sys.argv[2] if len(sys.argv) > 2 else "ta_demo"
    with FakeThreatAtlas(token, port) as fake:
        print(f"Fake ThreatAtlas at {fake.url} (token {token}). Ctrl+C to stop.")
        with contextlib.suppress(KeyboardInterrupt):
            fake.thread.join()
