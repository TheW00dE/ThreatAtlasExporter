"""Low-level HTTP access to the ThreatAtlas REST API.

Handles the base URL, bearer authentication, TLS settings, retries with backoff,
``skip``/``limit`` pagination, and turning error responses into typed exceptions.
"""

from __future__ import annotations

import logging
import ssl
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from tae import __version__
from tae.client.errors import ConnectionFailed, ResponseFormatError, error_for_response

log = logging.getLogger(__name__)

API_PREFIX = "/api"
DEFAULT_PAGE_SIZE = 100
RETRY_STATUSES = frozenset({429, 502, 503, 504})
IDEMPOTENT_METHODS = frozenset({"GET", "HEAD", "PUT", "DELETE", "OPTIONS"})
MAX_RETRY_AFTER = 30.0

Params = dict[str, Any]


def normalize_base_url(url: str) -> str:
    """Return the instance root URL without a trailing slash or ``/api`` suffix."""
    url = url.strip().rstrip("/")
    if not url.startswith(("http://", "https://")):
        raise ValueError(f"ThreatAtlas URL must start with http:// or https://, got {url!r}")
    if url.endswith(API_PREFIX):
        url = url[: -len(API_PREFIX)]
    return url


class HttpClient:
    """Thin wrapper over ``httpx.Client`` with ThreatAtlas conventions."""

    def __init__(
        self,
        base_url: str,
        token: str | None,
        *,
        timeout: float = 30.0,
        verify: bool | str | ssl.SSLContext = True,
        retries: int = 3,
        backoff: float = 0.5,
        transport: httpx.BaseTransport | None = None,
        sleep: Callable[[float], None] | None = None,
    ) -> None:
        self.base_url = normalize_base_url(base_url)
        self.retries = max(0, retries)
        self.backoff = backoff
        self._sleep = sleep or (lambda seconds: time.sleep(seconds))
        headers = {
            "Accept": "application/json",
            "User-Agent": f"threatatlas-exporter/{__version__}",
        }
        if token:
            headers["Authorization"] = f"Bearer {token}"
        self._client = httpx.Client(
            base_url=self.base_url + API_PREFIX,
            headers=headers,
            timeout=timeout,
            verify=verify,
            transport=transport,
            follow_redirects=False,
        )

    # ── lifecycle ──────────────────────────────────────────────────────────────

    def close(self) -> None:
        self._client.close()

    def __enter__(self) -> HttpClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()

    # ── requests ───────────────────────────────────────────────────────────────

    def request(
        self,
        method: str,
        path: str,
        *,
        params: Params | None = None,
        json: Any = None,
    ) -> httpx.Response:
        """Send a request, retrying transient failures; raise on error responses."""
        method = method.upper()
        clean_params = {k: v for k, v in (params or {}).items() if v is not None}
        attempt = 0
        while True:
            try:
                response = self._client.request(method, path, params=clean_params or None, json=json)
            except httpx.TransportError as exc:
                # A connect failure means the request never reached the server, so
                # it is safe to retry for every method. Other transport errors (read
                # timeouts, dropped connections) are only retried when idempotent.
                retriable = isinstance(exc, httpx.ConnectError) or method in IDEMPOTENT_METHODS
                if retriable and attempt < self.retries:
                    delay = self._delay(attempt, None)
                    log.debug("%s %s failed (%s); retry in %.1fs", method, path, exc, delay)
                    self._sleep(delay)
                    attempt += 1
                    continue
                raise ConnectionFailed(f"{method} {self.base_url}{API_PREFIX}{path}: {exc}") from exc

            # 429 is rejected before any work happens, so retrying is safe for all
            # methods; gateway errors are only retried for idempotent ones.
            retriable_status = response.status_code == 429 or (
                response.status_code in RETRY_STATUSES and method in IDEMPOTENT_METHODS
            )
            if retriable_status and attempt < self.retries:
                delay = self._delay(attempt, response.headers.get("Retry-After"))
                log.debug("%s %s returned %s; retry in %.1fs", method, path, response.status_code, delay)
                self._sleep(delay)
                attempt += 1
                continue

            if response.is_redirect:
                # Usually http→https or a proxy login page; surfacing it is clearer
                # than silently following it with the token attached.
                location = response.headers.get("Location", "?")
                raise ConnectionFailed(
                    f"{method} {response.request.url} redirected to {location}. "
                    "Check the configured URL (scheme, host, and any reverse-proxy path)."
                )
            if response.is_error:
                raise error_for_response(response)
            return response

    def _delay(self, attempt: int, retry_after: str | None) -> float:
        if retry_after:
            try:
                return min(float(retry_after), MAX_RETRY_AFTER)
            except ValueError:
                pass
        return float(self.backoff * (2**attempt))

    def get_json(self, path: str, params: Params | None = None) -> Any:
        return _json(self.request("GET", path, params=params))

    def post_json(self, path: str, body: Any = None, params: Params | None = None) -> Any:
        return _json(self.request("POST", path, params=params, json=body))

    def put_json(self, path: str, body: Any = None) -> Any:
        return _json(self.request("PUT", path, json=body))

    def delete(self, path: str) -> None:
        self.request("DELETE", path)

    def paginate(
        self,
        path: str,
        params: Params | None = None,
        page_size: int = DEFAULT_PAGE_SIZE,
    ) -> Iterator[dict[str, Any]]:
        """Yield every item from a ``skip``/``limit`` list endpoint."""
        skip = 0
        while True:
            page = self.get_json(path, {**(params or {}), "skip": skip, "limit": page_size})
            if not isinstance(page, list):
                raise ResponseFormatError(f"GET {path}: expected a JSON list, got {type(page).__name__}")
            yield from page
            if len(page) < page_size:
                return
            skip += page_size


def _json(response: httpx.Response) -> Any:
    if response.status_code == 204 or not response.content:
        return None
    try:
        return response.json()
    except ValueError as exc:
        ctype = response.headers.get("Content-Type", "?")
        raise ResponseFormatError(
            f"{response.request.method} {response.request.url}: expected JSON, got {ctype}. "
            "Is the URL pointing at the ThreatAtlas backend (or its /api proxy)?"
        ) from exc
