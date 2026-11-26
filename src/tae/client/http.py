"""Low-level HTTP access to the ThreatAtlas REST API.

Handles the base URL, bearer authentication, TLS settings, retries with backoff,
``skip``/``limit`` pagination, and turning error responses into typed exceptions.
"""

from __future__ import annotations

import logging
import math
import ssl
import time
from collections.abc import Callable, Iterator
from typing import Any

import httpx

from tae import __version__
from tae.client.errors import ConnectionFailed, ResponseFormatError, error_for_response

log = logging.getLogger(__name__)

API_PREFIX = "/api"
# ThreatAtlas doesn't sort most list endpoints, so pages taken with skip/limit can
# overlap or miss rows. Asking for large pages means real collections arrive in one
# response; paginate() also drops repeated IDs in case a collection is bigger.
DEFAULT_PAGE_SIZE = 1000
RETRY_STATUSES = frozenset({429, 502, 503, 504})
# Methods that are safe to send again after the request may have reached the server.
# PUT and DELETE are not: in ThreatAtlas a repeated diagram PUT creates another version
# snapshot, and a repeated DELETE fails with 404 after the first one worked.
SAFE_TO_REPEAT = frozenset({"GET", "HEAD", "OPTIONS"})
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
                # A connect failure means the request never reached the server, so it
                # is safe to retry for every method. After other transport errors (read
                # timeouts, dropped connections) the server may have acted on it, so
                # only reads are retried.
                retriable = isinstance(exc, httpx.ConnectError) or method in SAFE_TO_REPEAT
                if retriable and attempt < self.retries:
                    delay = self._delay(attempt, None)
                    log.debug("%s %s failed (%s); retry in %.1fs", method, path, exc, delay)
                    self._sleep(delay)
                    attempt += 1
                    continue
                raise ConnectionFailed(f"{method} {self.base_url}{API_PREFIX}{path}: {exc}") from exc

            # 429 is rejected before any work happens, so retrying is safe for all
            # methods; after a gateway error only reads are retried (see SAFE_TO_REPEAT).
            retriable_status = response.status_code == 429 or (
                response.status_code in RETRY_STATUSES and method in SAFE_TO_REPEAT
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
        """Seconds to wait: the server's Retry-After if it's a sane number, else backoff."""
        backoff = float(self.backoff * (2**attempt))
        if retry_after:
            try:
                seconds = float(retry_after)
            except ValueError:
                return backoff  # e.g. an HTTP date, which we don't parse
            if math.isfinite(seconds) and seconds >= 0:
                return min(seconds, MAX_RETRY_AFTER)
        return backoff

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
        """Yield every item from a ``skip``/``limit`` list endpoint, each ID once."""
        skip = 0
        seen: set[Any] = set()
        while True:
            page = self.get_json(path, {**(params or {}), "skip": skip, "limit": page_size})
            if not isinstance(page, list):
                raise ResponseFormatError(f"GET {path}: expected a JSON list, got {type(page).__name__}")
            for item in page:
                key = item.get("id") if isinstance(item, dict) else None
                if key is not None:
                    if key in seen:
                        log.debug("GET %s: skipping repeated id %s across pages", path, key)
                        continue
                    seen.add(key)
                yield item
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
