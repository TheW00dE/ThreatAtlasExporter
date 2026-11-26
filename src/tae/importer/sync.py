"""Sync an import file into ThreatAtlas: create what's missing, update what changed.

Matching is by name (frameworks, catalogue entries, products, diagrams, threat
models) and by element and catalogue entry (threats and mitigations on diagrams).
Entries that exist in ThreatAtlas but not in the file are only deleted with
``prune``. Optional fields left out of the file are not managed: re-importing a
file without ``status`` won't reset a status someone changed in ThreatAtlas.

The same code produces the plan (``dry_run``) and applies it, so the preview
matches what an import does.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass, field
from datetime import date, datetime
from functools import partial
from typing import Any, TypeVar

from tae.client import ThreatAtlasClient
from tae.importer.diagram import build_diagram_data, canonical
from tae.importer.schema import (
    CatalogMitigation,
    CatalogThreat,
    DiagramEntry,
    FrameworkDocument,
    ImportFileError,
    ModelEntry,
    ThreatModelDocument,
    ThreatOnElement,
)
from tae.models import api

T = TypeVar("T")

SUGGESTED = "Suggested mitigations: "


@dataclass
class Change:
    action: str  # create | update | delete | note
    kind: str
    name: str
    detail: str = ""


@dataclass
class Sync:
    client: ThreatAtlasClient
    dry_run: bool
    prune: bool
    source: str = "import"
    changes: list[Change] = field(default_factory=list)

    def do(self, action: str, kind: str, name: str, fn: Callable[[], T], detail: str = "") -> T | None:
        self.changes.append(Change(action, kind, name, detail))
        return None if self.dry_run else fn()

    def note(self, kind: str, name: str, detail: str) -> None:
        self.changes.append(Change("note", kind, name, detail))

    @property
    def deletes(self) -> list[Change]:
        return [c for c in self.changes if c.action == "delete"]


def _by_name(items: list[Any], what: str) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for item in items:
        key = item.name.casefold()
        if key in out:
            raise ImportFileError(
                f"ThreatAtlas has two {what}s named {item.name!r}; rename one so names are unique"
            )
        out[key] = item
    return out


def _diff(current: Any, wanted: dict[str, Any]) -> dict[str, Any]:
    """Fields in ``wanted`` whose value differs from ``current``."""
    out = {}
    for key, value in wanted.items():
        have: Any = getattr(current, key, None)
        if isinstance(have, datetime) and isinstance(value, date) and not isinstance(value, datetime):
            have = have.date()  # compare datetimes from the API with dates from the file
        if have != value:
            out[key] = value
    return out


def _fields(changed: dict[str, Any]) -> str:
    return ", ".join(sorted(changed))


# ── frameworks ────────────────────────────────────────────────────────────────


def framework_description(doc: FrameworkDocument) -> str:
    parts = [doc.framework.description.strip()] if doc.framework.description else []
    if doc.risk_scale is not None:
        parts.append(doc.risk_scale.describe())
    return "\n\n".join(parts)


def threat_description(threat: CatalogThreat, mitigations: dict[str, CatalogMitigation]) -> str | None:
    """ThreatAtlas has no catalogue links, so suggested mitigations go in the description."""
    text = threat.description.strip() if threat.description else ""
    if threat.mitigations:
        names = "; ".join(mitigations[m.casefold()].name for m in threat.mitigations)
        text = f"{text}\n\n{SUGGESTED}{names}" if text else f"{SUGGESTED}{names}"
    return text or None


def sync_framework(s: Sync, doc: FrameworkDocument) -> None:
    c = s.client
    name = doc.framework.name
    description = framework_description(doc)
    existing = _by_name(c.frameworks.list(), "framework").get(name.casefold())
    if existing is not None and not existing.is_custom:
        raise ImportFileError(
            f"{name!r} is a built-in ThreatAtlas framework and can't be changed by an import; "
            "use a different framework name"
        )

    threats: dict[str, api.Threat] = {}
    mitigations: dict[str, api.Mitigation] = {}
    if existing is None:
        created = s.do(
            "create",
            "framework",
            name,
            lambda: c.frameworks.create(api.FrameworkCreate(name=name, description=description or None)),
        )
        framework_id = created.id if created else None
    else:
        framework_id = existing.id
        changed = _diff(existing, {"name": name, "description": description or None})
        if changed:
            s.do(
                "update",
                "framework",
                name,
                lambda: c.frameworks.update(existing.id, api.FrameworkUpdate(**changed)),
                _fields(changed),
            )
        threats = _by_name(c.threats.list(framework_id=existing.id), "threat")
        mitigations = _by_name(c.mitigations.list(framework_id=existing.id), "mitigation")

    catalog_mitigations = {m.name.casefold(): m for m in doc.mitigations}
    for m in doc.mitigations:
        _sync_entry(
            s, "mitigation", c.mitigations, framework_id, mitigations, m.name, m.category, m.description
        )
    for t in doc.threats:
        desc = threat_description(t, catalog_mitigations)
        _sync_entry(s, "threat", c.threats, framework_id, threats, t.name, t.category, desc)

    wanted = {t.name.casefold() for t in doc.threats}, {m.name.casefold() for m in doc.mitigations}
    for kind, current, keep, resource in (
        ("threat", threats, wanted[0], c.threats),
        ("mitigation", mitigations, wanted[1], c.mitigations),
    ):
        for key, entry in current.items():
            if key in keep:
                continue
            if s.prune:
                s.do("delete", kind, entry.name, partial(resource.delete, entry.id))
            else:
                s.note(kind, entry.name, "in ThreatAtlas but not in the file (kept; --prune removes it)")


def _sync_entry(
    s: Sync,
    kind: str,
    resource: Any,
    framework_id: int | None,
    current: dict[str, Any],
    name: str,
    category: str | None,
    description: str | None,
) -> None:
    existing = current.get(name.casefold())
    if existing is None:
        s.do(
            "create",
            kind,
            name,
            lambda: resource.create(
                api.CatalogEntryCreate(
                    framework_id=framework_id or 0, name=name, category=category, description=description
                )
            ),
        )
        return
    changed = _diff(existing, {"name": name, "category": category, "description": description})
    if changed:
        s.do(
            "update",
            kind,
            name,
            lambda: resource.update(existing.id, api.CatalogEntryUpdate(**changed)),
            _fields(changed),
        )


# ── threat models ─────────────────────────────────────────────────────────────


@dataclass
class Catalog:
    framework: api.Framework
    threats: dict[str, api.Threat]
    mitigations: dict[str, api.Mitigation]


def preflight(c: ThreatAtlasClient, doc: ThreatModelDocument) -> dict[str, Catalog]:
    """Check every framework, threat and mitigation the file names exists, before any change."""
    frameworks = _by_name(c.frameworks.list(), "framework")
    catalogs: dict[str, Catalog] = {}
    problems: list[str] = []
    for d in doc.diagrams:
        for m in d.models:
            key = m.framework.casefold()
            if key not in catalogs:
                fw = frameworks.get(key)
                if fw is None:
                    problems.append(
                        f"framework {m.framework!r} not found (custom frameworks are only visible to "
                        "the user who created them; import the framework file first, with the same account)"
                    )
                    continue
                catalogs[key] = Catalog(
                    fw,
                    _by_name(c.threats.list(framework_id=fw.id), "threat"),
                    _by_name(c.mitigations.list(framework_id=fw.id), "mitigation"),
                )
            catalog = catalogs[key]
            for t in m.threats:
                if t.threat.casefold() not in catalog.threats:
                    problems.append(f"diagram {d.name!r}: {m.framework} has no threat named {t.threat!r}")
                for mt in t.mitigations:
                    if mt.mitigation.casefold() not in catalog.mitigations:
                        problems.append(
                            f"diagram {d.name!r}: {m.framework} has no mitigation named {mt.mitigation!r}"
                        )
    if problems:
        raise ImportFileError(
            "The file refers to things that don't exist in ThreatAtlas:\n- " + "\n- ".join(problems)
        )
    return catalogs


def sync_threat_model(s: Sync, doc: ThreatModelDocument) -> None:
    c = s.client
    catalogs = preflight(c, doc)

    info = doc.product.model_dump(exclude_unset=True)
    product = _by_name(c.products.list(), "product").get(doc.product.name.casefold())
    if product is None:
        created = s.do(
            "create", "product", doc.product.name, lambda: c.products.create(api.ProductCreate(**info))
        )
        product_id = created.id if created else None
        existing_diagrams: dict[str, api.Diagram] = {}
    else:
        product_id = product.id
        changed = _diff(product, info)
        if changed:
            s.do(
                "update",
                "product",
                doc.product.name,
                lambda: c.products.update(product.id, api.ProductUpdate(**changed)),
                _fields(changed),
            )
        existing_diagrams = _by_name(c.diagrams.list(product_id=product.id), "diagram")

    for d in doc.diagrams:
        _sync_diagram(s, d, product_id, existing_diagrams.get(d.name.casefold()), catalogs)

    wanted = {d.name.casefold() for d in doc.diagrams}
    for key, diagram in existing_diagrams.items():
        if key in wanted:
            continue
        if s.prune:
            s.do(
                "delete",
                "diagram",
                diagram.name,
                partial(c.diagrams.delete, diagram.id),
                "with its threat models",
            )
        else:
            s.note("diagram", diagram.name, "in ThreatAtlas but not in the file (kept; --prune removes it)")


def _sync_diagram(
    s: Sync,
    d: DiagramEntry,
    product_id: int | None,
    existing: api.Diagram | None,
    catalogs: dict[str, Catalog],
) -> None:
    c = s.client
    built = build_diagram_data(d, existing.diagram_data if existing else None, prune=s.prune)
    if existing is None:
        created = s.do(
            "create",
            "diagram",
            d.name,
            lambda: c.diagrams.create(
                api.DiagramCreate(
                    product_id=product_id or 0,
                    name=d.name,
                    description=d.description,
                    diagram_data=built.data,
                )
            ),
            f"{len(d.elements)} element(s), {len(d.flows)} flow(s)",
        )
        diagram_id = created.id if created else None
        models: dict[str, api.ModelWithFramework] = {}
        threats: list[api.DiagramThreatWithDetails] = []
        mitigations: list[api.DiagramMitigationWithDetails] = []
    else:
        diagram_id = existing.id
        update: dict[str, Any] = {}
        if d.description is not None and d.description != existing.description:
            update["description"] = d.description
        if canonical(built.data) != canonical(existing.diagram_data):
            update["diagram_data"] = built.data
            update["version_comment"] = f"Synced from {s.source} by tae"
        if update:
            detail = "layout and elements" if "diagram_data" in update else "description"
            if built.removed:
                detail += f"; removes {len(built.removed)} element(s) not in the file"
            s.do(
                "update",
                "diagram",
                d.name,
                lambda: c.diagrams.update(existing.id, api.DiagramUpdate(**update)),
                detail,
            )
        if built.kept:
            s.note(
                "diagram",
                d.name,
                f"keeps {len(built.kept)} element(s) drawn in ThreatAtlas that aren't in the file "
                f"({', '.join(built.kept[:5])}); --prune removes them",
            )
        models = _by_name(c.models.list(diagram_id=existing.id), "threat model")
        threats = c.diagram_threats.list(diagram_id=existing.id)
        mitigations = c.diagram_mitigations.list(diagram_id=existing.id)

    kinds = {e.id: "node" for e in d.elements} | {f.id: "edge" for f in d.flows}
    for m in d.models:
        current = models.get(m.model_name.casefold())
        catalog = catalogs[m.framework.casefold()]
        _sync_model(s, d, m, diagram_id, current, catalog, threats, mitigations, kinds)

    wanted = {m.model_name.casefold() for m in d.models}
    for key, model in models.items():
        if key in wanted:
            continue
        label = f"{d.name} / {model.name}"
        if s.prune:
            s.do("delete", "threat model", label, partial(c.models.delete, model.id), "with its threats")
        else:
            s.note("threat model", label, "in ThreatAtlas but not in the file (kept; --prune removes it)")


def _sync_model(
    s: Sync,
    d: DiagramEntry,
    m: ModelEntry,
    diagram_id: int | None,
    existing: api.ModelWithFramework | None,
    catalog: Catalog,
    all_threats: list[api.DiagramThreatWithDetails],
    all_mitigations: list[api.DiagramMitigationWithDetails],
    kinds: dict[str, str],
) -> None:
    c = s.client
    label = f"{d.name} / {m.model_name}"
    if existing is None:
        created = s.do(
            "create",
            "threat model",
            label,
            lambda: c.models.create(
                api.ModelCreate(
                    diagram_id=diagram_id or 0,
                    framework_id=catalog.framework.id,
                    name=m.model_name,
                    description=m.description,
                )
            ),
            f"framework {catalog.framework.name}",
        )
        model_id = created.id if created else None
        if m.status not in (None, "in_progress"):
            s.do(
                "update",
                "threat model",
                label,
                lambda: c.models.update(model_id or 0, api.ModelUpdate(status=m.status)),
                "status",
            )
        threats: list[api.DiagramThreatWithDetails] = []
        mitigations: list[api.DiagramMitigationWithDetails] = []
    else:
        model_id = existing.id
        if existing.framework_id != catalog.framework.id:
            raise ImportFileError(
                f"Threat model {label!r} in ThreatAtlas uses framework {existing.framework_name!r}, "
                f"but the file says {m.framework!r}. Rename the model in the file, "
                "or delete it in ThreatAtlas."
            )
        wanted = {k: v for k, v in (("description", m.description), ("status", m.status)) if v is not None}
        changed = _diff(existing, wanted)
        if changed:
            s.do(
                "update",
                "threat model",
                label,
                lambda: c.models.update(existing.id, api.ModelUpdate(**changed)),
                _fields(changed),
            )
        threats = [t for t in all_threats if t.model_id == existing.id]
        mitigations = [x for x in all_mitigations if x.model_id == existing.id]

    by_key = {(t.element_id, t.threat_id): t for t in threats}
    keep_threats: set[int] = set()
    keep_mitigations: set[int] = set()
    for entry in m.threats:
        catalog_threat = catalog.threats[entry.threat.casefold()]
        current = by_key.get((entry.element, catalog_threat.id))
        dt_id = _sync_threat(s, label, entry, diagram_id, model_id, catalog_threat, current, kinds)
        if current is not None:
            keep_threats.add(current.id)
        for mt in entry.mitigations:
            catalog_mitigation = catalog.mitigations[mt.mitigation.casefold()]
            existing_m = next(
                (x for x in mitigations
                 if x.mitigation_id == catalog_mitigation.id and x.element_id == entry.element
                 and current is not None and x.threat_id == current.id),
                None,
            )  # fmt: skip
            name = f"{label}: {mt.mitigation} for {entry.threat} on {entry.element}"
            if existing_m is None:
                s.do(
                    "create",
                    "mitigation on diagram",
                    name,
                    partial(
                        c.diagram_mitigations.create,
                        api.DiagramMitigationCreate(
                            diagram_id=diagram_id or 0,
                            model_id=model_id or 0,
                            mitigation_id=catalog_mitigation.id,
                            threat_id=dt_id,
                            element_id=entry.element,
                            element_type=kinds[entry.element],
                            **({"status": mt.status} if "status" in mt.model_fields_set else {}),
                            comments=mt.comments,
                        ),
                    ),
                    mt.status,
                )
            else:
                keep_mitigations.add(existing_m.id)
                wanted = {"status": mt.status} if "status" in mt.model_fields_set else {}
                if mt.comments is not None:
                    wanted["comments"] = mt.comments
                changed = _diff(existing_m, wanted)
                if changed:
                    s.do(
                        "update",
                        "mitigation on diagram",
                        name,
                        partial(
                            c.diagram_mitigations.update,
                            existing_m.id,
                            api.DiagramMitigationUpdate(**changed),
                        ),
                        _fields(changed),
                    )

    # Mitigations first: deleting a threat on a diagram also deletes its mitigations.
    for x in mitigations:
        if x.id not in keep_mitigations:
            _prune_or_note(s, "mitigation on diagram", f"{label}: {x.mitigation.name} on {x.element_id}",
                           partial(c.diagram_mitigations.delete, x.id))  # fmt: skip
    for t in threats:
        if t.id not in keep_threats:
            _prune_or_note(s, "threat on diagram", f"{label}: {t.threat.name} on {t.element_id}",
                           partial(c.diagram_threats.delete, t.id))  # fmt: skip


def _prune_or_note(s: Sync, kind: str, name: str, fn: Callable[[], Any]) -> None:
    if s.prune:
        s.do("delete", kind, name, fn)
    else:
        s.note(kind, name, "in ThreatAtlas but not in the file (kept; --prune removes it)")


def _threat_fields(entry: ThreatOnElement) -> dict[str, Any]:
    """The fields of a threat on a diagram that the file manages."""
    out: dict[str, Any] = {}
    if entry.likelihood is not None:
        out.update(likelihood=entry.likelihood, impact=entry.impact)
    if "status" in entry.model_fields_set:
        out["status"] = entry.status
    if entry.comments is not None:
        out["comments"] = entry.comments
    if entry.residual is not None:
        out.update(residual_likelihood=entry.residual.likelihood, residual_impact=entry.residual.impact)
        if entry.residual.comments is not None:
            out["residual_comments"] = entry.residual.comments
    if entry.acceptance is not None:
        out["acceptance_justification"] = entry.acceptance.justification
        if entry.acceptance.approver_id is not None:
            out["acceptance_approver_id"] = entry.acceptance.approver_id
        if entry.acceptance.review_date is not None:
            out["acceptance_review_date"] = entry.acceptance.review_date
    return out


def _sync_threat(
    s: Sync,
    label: str,
    entry: ThreatOnElement,
    diagram_id: int | None,
    model_id: int | None,
    catalog_threat: api.Threat,
    current: api.DiagramThreatWithDetails | None,
    kinds: dict[str, str],
) -> int | None:
    """Create or update one threat on a diagram; returns its ID (or, in a dry run, None)."""
    c = s.client
    name = f"{label}: {entry.threat} on {entry.element}"
    wanted = _threat_fields(entry)

    def as_update(fields: dict[str, Any]) -> api.DiagramThreatUpdate:
        values = dict(fields)
        if "acceptance_review_date" in values:
            values["acceptance_review_date"] = values["acceptance_review_date"].isoformat()
        return api.DiagramThreatUpdate(**values)

    if current is None:
        # Created as identified; anything else (status, residual, acceptance) is a follow-up
        # update, so ThreatAtlas records the acceptance time as it does in its own UI.
        basic = {k: wanted[k] for k in ("likelihood", "impact", "comments") if k in wanted}
        rest = {k: v for k, v in wanted.items() if k not in basic}
        created = s.do(
            "create",
            "threat on diagram",
            name,
            lambda: c.diagram_threats.create(
                api.DiagramThreatCreate(
                    diagram_id=diagram_id or 0,
                    model_id=model_id or 0,
                    threat_id=catalog_threat.id,
                    element_id=entry.element,
                    element_type=kinds[entry.element],
                    **basic,
                )
            ),
            _risk(entry),
        )
        if rest and created is not None:
            c.diagram_threats.update(created.id, as_update(rest))
        return created.id if created is not None else None

    changed = _diff(current, wanted)
    if changed:
        s.do(
            "update",
            "threat on diagram",
            name,
            lambda: c.diagram_threats.update(current.id, as_update(changed)),
            _fields(changed),
        )
    return current.id


def _risk(entry: ThreatOnElement) -> str:
    parts = []
    if entry.likelihood is not None:
        parts.append(f"L{entry.likelihood} × I{entry.impact}")
    parts.append(entry.status)
    return ", ".join(parts)
