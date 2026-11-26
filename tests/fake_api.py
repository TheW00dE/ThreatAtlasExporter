"""An in-memory ThreatAtlas API that accepts writes, for import tests.

It mirrors the upstream behaviour the importer depends on (checked against the
ThreatAtlas v0.9.x routers): custom frameworks and their entries are visible only
to their owner, framework names must be unique, updates apply only the fields sent,
risk score and severity are computed server-side, accepting a threat stamps
``accepted_at``, and deletes cascade (diagram → models → threats → mitigations).
Use it as an httpx transport: ``ThreatAtlasClient(url, token, transport=fake.transport)``.
"""

from __future__ import annotations

import itertools
import json
import re
from datetime import UTC, datetime
from typing import Any
from urllib.parse import parse_qs

import httpx

from tae.models.api import severity_for_score

NOW = "2026-11-26T10:00:00+00:00"


class FakeThreatAtlasAPI:
    def __init__(self, user_id: int = 1) -> None:
        self.user_id = user_id
        self.ids = itertools.count(1000)
        self.requests: list[tuple[str, str]] = []
        self.frameworks: dict[int, dict[str, Any]] = {}
        self.threats: dict[int, dict[str, Any]] = {}
        self.mitigations: dict[int, dict[str, Any]] = {}
        self.products: dict[int, dict[str, Any]] = {}
        self.diagrams: dict[int, dict[str, Any]] = {}
        self.models: dict[int, dict[str, Any]] = {}
        self.diagram_threats: dict[int, dict[str, Any]] = {}
        self.diagram_mitigations: dict[int, dict[str, Any]] = {}
        self.versions: dict[int, list[str | None]] = {}
        # Built-in STRIDE framework with a few catalogue entries.
        stride = self._add(
            self.frameworks, name="STRIDE", description="Microsoft STRIDE", is_custom=False, user_id=None
        )
        for name, cat in (("SQL injection", "Tampering"), ("Spoofed client", "Spoofing")):
            self._add(self.threats, framework_id=stride["id"], name=name, category=cat, description=None,
                      is_custom=False, user_id=None)  # fmt: skip
        self._add(self.mitigations, framework_id=stride["id"], name="Parameterised queries", category="Tampering",
                  description=None, is_custom=False, user_id=None)  # fmt: skip

    # ── helpers ───────────────────────────────────────────────────────────────

    def _add(self, table: dict[int, dict[str, Any]], **fields: Any) -> dict[str, Any]:
        item = {"id": next(self.ids), "created_at": NOW, "updated_at": NOW, **fields}
        table[item["id"]] = item
        return item

    def _visible(self, item: dict[str, Any]) -> bool:
        return not item.get("is_custom") or item.get("user_id") == self.user_id

    @staticmethod
    def _catalog(item: dict[str, Any]) -> dict[str, Any]:
        return {"is_modified": False, "original_name": None, "original_description": None,
                "original_category": None, **item}  # fmt: skip

    def _model_out(self, m: dict[str, Any]) -> dict[str, Any]:
        fw = self.frameworks[m["framework_id"]]
        threats = [t for t in self.diagram_threats.values() if t["model_id"] == m["id"]]
        mits = [x for x in self.diagram_mitigations.values() if x["model_id"] == m["id"]]
        return {
            **m,
            "framework_name": fw["name"],
            "threat_count": len(threats),
            "mitigation_count": len(mits),
        }

    def _score(self, t: dict[str, Any]) -> None:
        for prefix in ("", "residual_"):
            li, im = t.get(f"{prefix}likelihood"), t.get(f"{prefix}impact")
            score = li * im if li and im else None
            t[f"{prefix}risk_score"] = score
            t[f"{prefix}severity"] = severity_for_score(score)

    def _dt_out(self, t: dict[str, Any]) -> dict[str, Any]:
        model = self.models.get(t["model_id"])
        return {**t, "threat": self._catalog(self.threats[t["threat_id"]]), "model": model,
                "acceptance_approver_name": None}  # fmt: skip

    def _dm_out(self, m: dict[str, Any]) -> dict[str, Any]:
        return {**m, "mitigation": self._catalog(self.mitigations[m["mitigation_id"]]),
                "model": self.models.get(m["model_id"])}  # fmt: skip

    def _delete_model(self, model_id: int) -> None:
        for tid in [t for t, x in self.diagram_threats.items() if x["model_id"] == model_id]:
            self._delete_dt(tid)
        for mid in [m for m, x in self.diagram_mitigations.items() if x["model_id"] == model_id]:
            del self.diagram_mitigations[mid]
        del self.models[model_id]

    def _delete_dt(self, dt_id: int) -> None:
        for mid in [m for m, x in self.diagram_mitigations.items() if x.get("threat_id") == dt_id]:
            del self.diagram_mitigations[mid]
        del self.diagram_threats[dt_id]

    @property
    def writes(self) -> list[tuple[str, str]]:
        return [r for r in self.requests if r[0] != "GET"]

    # ── transport ─────────────────────────────────────────────────────────────

    @property
    def transport(self) -> httpx.MockTransport:
        return httpx.MockTransport(self.handle)

    def handle(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/api")
        self.requests.append((request.method, path))
        query = {k: v[0] for k, v in parse_qs(request.url.query.decode()).items()}
        body = json.loads(request.content) if request.content else {}
        try:
            result = self.route(request.method, path, query, body)
        except LookupError as exc:
            return httpx.Response(404, json={"detail": str(exc)})
        except PermissionError as exc:
            return httpx.Response(403, json={"detail": str(exc)})
        except ValueError as exc:
            return httpx.Response(400, json={"detail": str(exc)})
        if result is None:
            return httpx.Response(204)
        status = 201 if request.method == "POST" else 200
        return httpx.Response(status, json=result)

    def _get(self, table: dict[int, dict[str, Any]], item_id: str) -> dict[str, Any]:
        item = table.get(int(item_id))
        if item is None or not self._visible(item):
            raise LookupError("Not found")
        return item

    def route(self, method: str, path: str, q: dict[str, str], body: dict[str, Any]) -> Any:
        m = re.fullmatch(r"/(\w[\w-]*)(?:/(\d+))?(?:/(\w+))?", path)
        if path == "/auth/me":
            return {"id": self.user_id, "email": "analyst@example.com", "username": "analyst",
                    "full_name": "Ana Lyst", "is_active": True, "role": "standard",
                    "effective_role": "standard", "created_at": NOW}  # fmt: skip
        mm = re.fullmatch(r"/models/diagram/(\d+)", path)
        if mm and method == "GET":
            return [self._model_out(x) for x in self.models.values() if x["diagram_id"] == int(mm.group(1))]
        assert m, path
        coll, item_id = m.group(1), m.group(2)

        if coll == "frameworks":
            if method == "GET" and item_id is None:
                return (
                    [f for f in self.frameworks.values() if self._visible(f)]
                    if q.get("skip", "0") == "0"
                    else []
                )
            if method == "POST":
                clash = [
                    f for f in self.frameworks.values() if f["name"] == body["name"] and self._visible(f)
                ]
                if clash:
                    raise ValueError(f"Framework with name '{body['name']}' already exists")
                return self._add(self.frameworks, name=body["name"], description=body.get("description"),
                                 is_custom=True, user_id=self.user_id)  # fmt: skip
            f = self._get(self.frameworks, item_id)
            if method == "PUT":
                if not f["is_custom"]:
                    raise PermissionError("Only admins can update standard frameworks")
                f.update({k: v for k, v in body.items() if k in ("name", "description")})
                return f
            if method == "DELETE":
                for table in (self.threats, self.mitigations):
                    for k in [k for k, v in table.items() if v["framework_id"] == f["id"]]:
                        del table[k]
                del self.frameworks[f["id"]]
                return None
            return f

        if coll in ("threats", "mitigations"):
            table = self.threats if coll == "threats" else self.mitigations
            if method == "GET" and item_id is None:
                if q.get("skip", "0") != "0":
                    return []
                items = [x for x in table.values() if self._visible(x)]
                if "framework_id" in q:
                    items = [x for x in items if x["framework_id"] == int(q["framework_id"])]
                return [self._catalog(x) for x in items]
            if method == "POST":
                fw = self._get(self.frameworks, str(body["framework_id"]))
                if fw["is_custom"] and fw["user_id"] != self.user_id:
                    raise PermissionError("You cannot add entries to this framework")
                return self._catalog(self._add(table, framework_id=fw["id"], name=body["name"],
                    category=body.get("category"), description=body.get("description"),
                    is_custom=body.get("is_custom", True), user_id=self.user_id))  # fmt: skip
            item = self._get(table, item_id)
            if method == "PUT":
                item.update({k: v for k, v in body.items() if k in ("name", "description", "category")})
                return self._catalog(item)
            if method == "DELETE":
                del table[item["id"]]
                return None
            return self._catalog(item)

        if coll == "products":
            if method == "GET" and item_id is None:
                return list(self.products.values()) if q.get("skip", "0") == "0" else []
            if method == "POST":
                return self._add(self.products, **{"is_public": False, "can_edit": True, "status": None,
                                                    "description": None, **body})  # fmt: skip
            p = self._get(self.products, item_id)
            if method == "PUT":
                p.update(body)
            return p

        if coll == "diagrams":
            if method == "GET" and item_id is None:
                if q.get("skip", "0") != "0":
                    return []
                return [d for d in self.diagrams.values() if str(d["product_id"]) == q.get("product_id")]
            if method == "POST":
                self._get(self.products, str(body["product_id"]))
                d = self._add(self.diagrams, **{"can_edit": True, "current_version": 0, "auto_version": True,
                                                "description": None, "diagram_data": None, **body})  # fmt: skip
                self.versions[d["id"]] = []
                return d
            d = self._get(self.diagrams, item_id)
            if method == "PUT":
                comment = body.pop("version_comment", None)
                body.pop("auto_version", None)
                d.update(body)
                if "diagram_data" in body:
                    self.versions[d["id"]].append(comment)
                    d["current_version"] += 1
                return d
            if method == "DELETE":
                for mid in [k for k, v in self.models.items() if v["diagram_id"] == d["id"]]:
                    self._delete_model(mid)
                del self.diagrams[d["id"]]
                return None
            return d

        if coll == "models":
            if method == "POST":
                fw = self._get(self.frameworks, str(body["framework_id"]))
                created = self._add(self.models, diagram_id=body["diagram_id"], framework_id=fw["id"],
                    name=body["name"], description=body.get("description"), status="in_progress",
                    created_by=self.user_id, completed_at=None)  # fmt: skip
                return self._model_out(created)
            model = self._get(self.models, item_id)
            if method == "PUT":
                model.update(body)
                return self._model_out(model)
            if method == "DELETE":
                self._delete_model(model["id"])
                return None
            return self._model_out(model)

        if coll == "diagram-threats":
            if method == "GET" and item_id is None:
                if q.get("skip", "0") != "0":
                    return []
                return [
                    self._dt_out(t)
                    for t in self.diagram_threats.values()
                    if str(t["diagram_id"]) == q.get("diagram_id")
                ]
            if method == "POST":
                defaults = dict.fromkeys(("comments", "likelihood", "impact", "residual_likelihood",
                    "residual_impact", "residual_comments", "acceptance_justification", "acceptance_approver_id",
                    "acceptance_review_date", "accepted_at", "acceptance_review_status", "acceptance_review_note",
                    "acceptance_reviewed_at"))  # fmt: skip
                t = self._add(self.diagram_threats, **{**defaults, "status": "identified", **body})
                self._score(t)
                return {k: v for k, v in t.items()}
            t = self._get(self.diagram_threats, item_id)
            if method == "PUT":
                if body.get("status") == "accepted" and t["status"] != "accepted" and not t["accepted_at"]:
                    t["accepted_at"] = datetime.now(UTC).isoformat()
                if body.get("acceptance_review_date"):
                    body["acceptance_review_date"] = f"{body['acceptance_review_date']}T00:00:00"
                t.update(body)
                self._score(t)
                return t
            if method == "DELETE":
                self._delete_dt(t["id"])
                return None
            return self._dt_out(t)

        if coll == "diagram-mitigations":
            if method == "GET" and item_id is None:
                if q.get("skip", "0") != "0":
                    return []
                return [
                    self._dm_out(x)
                    for x in self.diagram_mitigations.values()
                    if str(x["diagram_id"]) == q.get("diagram_id")
                ]
            if method == "POST":
                if body.get("threat_id") is not None and body["threat_id"] not in self.diagram_threats:
                    raise LookupError("Diagram threat not found")
                return self._add(self.diagram_mitigations, **{"status": "proposed", "comments": None,
                                                              "threat_id": None, **body})  # fmt: skip
            x = self._get(self.diagram_mitigations, item_id)
            if method == "PUT":
                x.update(body)
                return x
            if method == "DELETE":
                del self.diagram_mitigations[x["id"]]
                return None
            return self._dm_out(x)

        raise LookupError(f"No route for {method} {path}")
