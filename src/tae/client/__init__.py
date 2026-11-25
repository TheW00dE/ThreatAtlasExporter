"""ThreatAtlas REST client."""

from __future__ import annotations

from tae.client.endpoints.resources import (
    Approvals,
    DiagramMitigations,
    Diagrams,
    DiagramThreats,
    DiagramVersions,
    Frameworks,
    Mitigations,
    Models,
    Products,
    Threats,
    Users,
)
from tae.client.http import HttpClient


class ThreatAtlasClient:
    """Entry point: ``ThreatAtlasClient(url, token).products.list()``.

    Accepts the same keyword arguments as :class:`HttpClient` (timeout, verify,
    retries, transport, ...).
    """

    def __init__(self, base_url: str, token: str | None, **http_options: object) -> None:
        self.http = HttpClient(base_url, token, **http_options)  # type: ignore[arg-type]
        self.users = Users(self.http)
        self.products = Products(self.http)
        self.frameworks = Frameworks(self.http)
        self.diagrams = Diagrams(self.http)
        self.diagram_versions = DiagramVersions(self.http)
        self.models = Models(self.http)
        self.threats = Threats(self.http)
        self.mitigations = Mitigations(self.http)
        self.diagram_threats = DiagramThreats(self.http)
        self.diagram_mitigations = DiagramMitigations(self.http)
        self.approvals = Approvals(self.http)

    @property
    def base_url(self) -> str:
        return self.http.base_url

    def close(self) -> None:
        self.http.close()

    def __enter__(self) -> ThreatAtlasClient:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()


__all__ = ["HttpClient", "ThreatAtlasClient"]
