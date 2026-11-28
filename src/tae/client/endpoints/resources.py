"""One class per ThreatAtlas REST resource."""

from __future__ import annotations

from typing import Any

from tae.client.endpoints.base import Resource, body, parse, parse_list
from tae.models import api
from tae.models.api import RequestModel


class Users(Resource[api.User]):
    path = "/users"
    model = api.User
    paginated = False  # upstream returns every user at once and ignores skip/limit

    def get(self, item_id: int) -> api.User:
        raise NotImplementedError("ThreatAtlas has no endpoint for reading a single user")

    def me(self) -> api.User:
        return parse(api.User, self.http.get_json("/auth/me"), "GET /auth/me")


class Products(Resource[api.Product]):
    path = "/products"
    model = api.Product

    def list(self) -> list[api.Product]:
        return self._list()

    def duplicate(self, product_id: int, name: str) -> api.Product:
        path = f"{self.path}/{product_id}/duplicate"
        data = self.http.post_json(path, api.ProductDuplicate(name=name).payload())
        return parse(api.Product, data, f"POST {path}")

    def security_status(
        self,
        product_id: int,
        *,
        fail_on_critical: bool = False,
        fail_on_unmitigated_high: bool = False,
        min_mitigation_ratio: float | None = None,
    ) -> dict[str, Any]:
        """ThreatAtlas's own pass/fail check. Without thresholds it always passes."""
        params = {
            "fail_on_critical": "true" if fail_on_critical else None,
            "fail_on_unmitigated_high": "true" if fail_on_unmitigated_high else None,
            "min_mitigation_ratio": min_mitigation_ratio,
        }
        data = self.http.get_json(f"{self.path}/{product_id}/security-status", params)
        return data if isinstance(data, dict) else {}


class Frameworks(Resource[api.Framework]):
    path = "/frameworks"
    model = api.Framework

    def list(self) -> list[api.Framework]:
        return self._list()


class Diagrams(Resource[api.Diagram]):
    path = "/diagrams"
    model = api.Diagram

    def list(self, product_id: int | None = None) -> list[api.Diagram]:
        return self._list({"product_id": product_id})


class DiagramVersions:
    """``/api/diagram-versions/{diagram_id}/versions`` — not a flat collection."""

    def __init__(self, http: Any) -> None:
        self.http = http

    @staticmethod
    def _base(diagram_id: int) -> str:
        return f"/diagram-versions/{diagram_id}/versions"

    def list(self, diagram_id: int) -> list[api.DiagramVersionSummary]:
        path = self._base(diagram_id)
        return parse_list(api.DiagramVersionSummary, self.http.get_json(path) or [], f"GET {path}")

    def get(self, diagram_id: int, version_number: int) -> api.DiagramVersion:
        path = f"{self._base(diagram_id)}/{version_number}"
        return parse(api.DiagramVersion, self.http.get_json(path), f"GET {path}")

    def create(self, diagram_id: int, comment: str | None = None) -> api.DiagramVersion:
        path = self._base(diagram_id)
        return parse(api.DiagramVersion, self.http.post_json(path, {"comment": comment}), f"POST {path}")

    def compare(self, diagram_id: int, from_version: int, to_version: int) -> dict[str, Any]:
        path = f"{self._base(diagram_id)}/compare"
        data = self.http.get_json(path, {"from_version": from_version, "to_version": to_version})
        return data if isinstance(data, dict) else {}

    def restore(self, diagram_id: int, version_number: int) -> api.DiagramVersion:
        path = f"{self._base(diagram_id)}/{version_number}/restore"
        return parse(api.DiagramVersion, self.http.post_json(path), f"POST {path}")

    def delete(self, diagram_id: int, version_number: int) -> None:
        self.http.delete(f"{self._base(diagram_id)}/{version_number}")


class Models(Resource[api.ModelWithFramework]):
    """Threat models: a framework bound to a diagram."""

    path = "/models"
    model = api.ModelWithFramework
    paginated = False  # upstream returns every visible model in one response

    def list(self, diagram_id: int | None = None) -> list[api.ModelWithFramework]:
        if diagram_id is None:
            return self._list()
        path = f"{self.path}/diagram/{diagram_id}"
        return parse_list(api.ModelWithFramework, self.http.get_json(path) or [], f"GET {path}")


class _Catalog(Resource[Any]):
    def list(self, framework_id: int | None = None, is_custom: bool | None = None) -> list[Any]:
        return self._list({"framework_id": framework_id, "is_custom": _bool_param(is_custom)})

    def revert(self, item_id: int) -> Any:
        """Restore a modified built-in entry to its original text."""
        path = f"{self.path}/{item_id}/revert"
        return parse(self.model, self.http.post_json(path), f"POST {path}")


class Threats(_Catalog):
    path = "/threats"
    model = api.Threat


class Mitigations(_Catalog):
    path = "/mitigations"
    model = api.Mitigation


class DiagramThreats(Resource[api.DiagramThreatWithDetails]):
    """Catalog threats identified on diagram elements, with risk and acceptance data.

    List and get return the threat and model inline; create and update return the
    bare record (upstream behaviour).
    """

    path = "/diagram-threats"
    model = api.DiagramThreatWithDetails

    def list(
        self,
        diagram_id: int | None = None,
        model_id: int | None = None,
        element_id: str | None = None,
    ) -> list[api.DiagramThreatWithDetails]:
        return self._list({"diagram_id": diagram_id, "model_id": model_id, "element_id": element_id})

    def create(self, data: RequestModel | dict[str, Any]) -> api.DiagramThreat:  # type: ignore[override]
        return parse(api.DiagramThreat, self.http.post_json(self.path, body(data)), f"POST {self.path}")

    def update(  # type: ignore[override]
        self, item_id: int, data: RequestModel | dict[str, Any]
    ) -> api.DiagramThreat:
        path = f"{self.path}/{item_id}"
        return parse(api.DiagramThreat, self.http.put_json(path, body(data)), f"PUT {path}")


class DiagramMitigations(Resource[api.DiagramMitigationWithDetails]):
    path = "/diagram-mitigations"
    model = api.DiagramMitigationWithDetails

    def list(
        self,
        diagram_id: int | None = None,
        model_id: int | None = None,
        element_id: str | None = None,
    ) -> list[api.DiagramMitigationWithDetails]:
        return self._list({"diagram_id": diagram_id, "model_id": model_id, "element_id": element_id})

    def create(self, data: RequestModel | dict[str, Any]) -> api.DiagramMitigation:  # type: ignore[override]
        return parse(api.DiagramMitigation, self.http.post_json(self.path, body(data)), f"POST {self.path}")

    def update(  # type: ignore[override]
        self, item_id: int, data: RequestModel | dict[str, Any]
    ) -> api.DiagramMitigation:
        path = f"{self.path}/{item_id}"
        return parse(api.DiagramMitigation, self.http.put_json(path, body(data)), f"PUT {path}")


class Approvals:
    """The current user's risk-acceptance review queue."""

    def __init__(self, http: Any) -> None:
        self.http = http

    def mine(self) -> list[api.ApprovalItem]:
        return parse_list(api.ApprovalItem, self.http.get_json("/approvals/my") or [], "GET /approvals/my")

    def pending_count(self) -> int:
        data = self.http.get_json("/approvals/my/count")
        if isinstance(data, dict):
            return int(data.get("count", 0))
        return int(data or 0)


def _bool_param(value: bool | None) -> str | None:
    return None if value is None else str(value).lower()
