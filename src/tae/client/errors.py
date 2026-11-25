"""Typed errors raised by the ThreatAtlas client."""

from __future__ import annotations

from typing import Any

import httpx


class ThreatAtlasError(Exception):
    """Base class for every error the client raises."""


class ConnectionFailed(ThreatAtlasError):
    """The server could not be reached (DNS, TLS, refused, timeout)."""


class ApiError(ThreatAtlasError):
    """The server answered with an error status."""

    def __init__(self, status_code: int, method: str, url: str, detail: Any = None) -> None:
        self.status_code = status_code
        self.method = method
        self.url = url
        self.detail = detail
        super().__init__(self._format())

    def _format(self) -> str:
        msg = f"{self.method} {self.url} returned {self.status_code}"
        text = format_detail(self.detail)
        return f"{msg}: {text}" if text else msg


class AuthenticationError(ApiError):
    """401: the token is missing, invalid or expired."""


class PermissionDenied(ApiError):
    """403: the token's user may not do this."""


class NotFound(ApiError):
    """404: the resource doesn't exist or isn't visible to this user."""


class ValidationFailed(ApiError):
    """400 or 422: the server rejected the request body or parameters."""


class RateLimited(ApiError):
    """429: too many requests, even after retrying."""


class ServerError(ApiError):
    """5xx: the server failed, even after retrying."""


class ResponseFormatError(ThreatAtlasError):
    """The server's response didn't match the expected shape."""


def format_detail(detail: Any) -> str:
    """Render a FastAPI error ``detail`` (string, or a list of validation errors)."""
    if detail is None:
        return ""
    if isinstance(detail, str):
        return detail
    if isinstance(detail, list):
        parts = []
        for item in detail:
            if isinstance(item, dict):
                loc = ".".join(str(p) for p in item.get("loc", []) if p != "body")
                parts.append(f"{loc}: {item.get('msg', item)}" if loc else str(item.get("msg", item)))
            else:
                parts.append(str(item))
        return "; ".join(parts)
    return str(detail)


def error_for_response(response: httpx.Response) -> ApiError:
    """Build the matching ``ApiError`` subclass for an error response."""
    try:
        body = response.json()
        detail = body.get("detail", body) if isinstance(body, dict) else body
    except ValueError:
        detail = response.text[:500] or None

    status = response.status_code
    cls: type[ApiError]
    if status == 401:
        cls = AuthenticationError
    elif status == 403:
        cls = PermissionDenied
    elif status == 404:
        cls = NotFound
    elif status in (400, 422):
        cls = ValidationFailed
    elif status == 429:
        cls = RateLimited
    elif status >= 500:
        cls = ServerError
    else:
        cls = ApiError
    request = response.request
    return cls(status, request.method, str(request.url), detail)
