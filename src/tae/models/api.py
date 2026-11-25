"""Pydantic mirrors of the ThreatAtlas REST API schemas (upstream v0.9.x).

Response models are deliberately tolerant: unknown fields are kept (``extra="allow"``)
and status-like fields are plain strings, so a newer server version doesn't break
pulling. Strict checks on vocabularies and value ranges belong in the validation
stage, which reports them as findings instead of crashing.

Request models (``*Create`` / ``*Update``) mirror the server's input schemas, and
are serialized with ``exclude_unset`` so that updates only send the fields given.
"""

from __future__ import annotations

from datetime import datetime
from typing import Any, Final

from pydantic import BaseModel, ConfigDict, Field

# ── Vocabularies known from upstream (used by validation and CLI help) ──────────

PRODUCT_STATUSES: Final = ("design", "development", "testing", "deployment", "production")
MODEL_STATUSES: Final = ("in_progress", "completed", "archived")
DIAGRAM_THREAT_STATUSES: Final = ("identified", "mitigated", "accepted")
DIAGRAM_MITIGATION_STATUSES: Final = ("proposed", "implemented", "verified")
ACCEPTANCE_REVIEW_STATUSES: Final = ("approved", "rejected")
NODE_TYPES: Final = ("process", "datastore", "external", "boundary")
USER_ROLES: Final = ("admin", "standard", "read_only")
SEVERITIES: Final = ("critical", "high", "medium", "low")

# Severity bands (minimum score, label), evaluated high to low; matches upstream risk_service.
SEVERITY_BANDS: Final = ((20, "critical"), (12, "high"), (6, "medium"), (0, "low"))


def severity_for_score(score: int | None) -> str | None:
    """Map a likelihood x impact score onto the upstream severity label."""
    if score is None:
        return None
    for minimum, label in SEVERITY_BANDS:
        if score >= minimum:
            return label
    return "low"


class ApiModel(BaseModel):
    """Base for response models."""

    model_config = ConfigDict(extra="allow", populate_by_name=True)


class RequestModel(BaseModel):
    """Base for request bodies."""

    model_config = ConfigDict(extra="forbid")

    def payload(self) -> dict[str, Any]:
        return self.model_dump(mode="json", exclude_unset=True)


# ── Users ───────────────────────────────────────────────────────────────────────


class User(ApiModel):
    id: int
    email: str
    username: str
    full_name: str | None = None
    is_active: bool = True
    role: str
    effective_role: str | None = None
    ldap_provider: str | None = None
    created_at: datetime | None = None


# ── Products ────────────────────────────────────────────────────────────────────


class _ProductFields(BaseModel):
    description: str | None = None
    status: str | None = None
    repository_url: str | None = None
    confluence_url: str | None = None
    application_url: str | None = None
    business_area: str | None = None
    owner_name: str | None = None
    owner_email: str | None = None
    jira_project_key: str | None = None
    reviewer: str | None = None
    contributors: str | None = None


class Product(ApiModel, _ProductFields):
    id: int
    name: str
    is_public: bool = False
    can_edit: bool = False
    created_at: datetime
    updated_at: datetime


class ProductCreate(RequestModel, _ProductFields):
    name: str
    is_public: bool = False


class ProductUpdate(RequestModel, _ProductFields):
    name: str | None = None
    is_public: bool | None = None


class ProductDuplicate(RequestModel):
    name: str = Field(min_length=1, max_length=200)


# ── Frameworks ──────────────────────────────────────────────────────────────────


class Framework(ApiModel):
    id: int
    name: str | None = None
    description: str | None = None
    is_custom: bool = False
    user_id: int | None = None
    created_at: datetime
    updated_at: datetime


class FrameworkCreate(RequestModel):
    name: str
    description: str | None = None
    is_custom: bool = True


class FrameworkUpdate(RequestModel):
    name: str | None = None
    description: str | None = None


# ── Diagrams ────────────────────────────────────────────────────────────────────


class Diagram(ApiModel):
    id: int
    product_id: int
    name: str
    description: str | None = None
    diagram_data: dict[str, Any] | None = None
    can_edit: bool = False
    current_version: int = 0
    auto_version: bool = True
    created_at: datetime
    updated_at: datetime

    @property
    def nodes(self) -> list[dict[str, Any]]:
        return list((self.diagram_data or {}).get("nodes") or [])

    @property
    def edges(self) -> list[dict[str, Any]]:
        return list((self.diagram_data or {}).get("edges") or [])


class DiagramCreate(RequestModel):
    product_id: int
    name: str
    description: str | None = None
    diagram_data: dict[str, Any] | None = None


class DiagramUpdate(RequestModel):
    name: str | None = None
    description: str | None = None
    diagram_data: dict[str, Any] | None = None
    product_id: int | None = None
    auto_version: bool | None = None
    version_comment: str | None = None
    snapshot: str | None = None


class DiagramVersionSummary(ApiModel):
    id: int
    diagram_id: int
    version_number: int
    name: str
    comment: str | None = None
    created_at: datetime
    node_count: int = 0
    edge_count: int = 0
    threat_count: int = 0
    mitigation_count: int = 0
    total_risk_score: int = 0


class DiagramVersion(ApiModel):
    """A full snapshot. Threat and mitigation snapshots are kept as raw dicts."""

    id: int
    diagram_id: int
    version_number: int
    name: str
    description: str | None = None
    comment: str | None = None
    diagram_data: dict[str, Any] | None = None
    created_at: datetime
    created_by: int | None = None
    threat_versions: list[dict[str, Any]] = Field(default_factory=list)
    mitigation_versions: list[dict[str, Any]] = Field(default_factory=list)


# ── Models (a framework bound to a diagram, i.e. a threat model) ───────────────


class Model(ApiModel):
    id: int
    diagram_id: int
    framework_id: int
    name: str
    description: str | None = None
    status: str
    created_by: int | None = None
    created_at: datetime
    completed_at: datetime | None = None


class ModelWithFramework(Model):
    framework_name: str
    threat_count: int = 0
    mitigation_count: int = 0


class ModelCreate(RequestModel):
    diagram_id: int
    framework_id: int
    name: str
    description: str | None = None


class ModelUpdate(RequestModel):
    name: str | None = None
    description: str | None = None
    status: str | None = None
    completed_at: datetime | None = None


# ── Catalog threats and mitigations ────────────────────────────────────────────


class _CatalogEntry(ApiModel):
    id: int
    framework_id: int
    name: str
    description: str | None = None
    category: str | None = None
    user_id: int | None = None
    is_custom: bool = False
    is_modified: bool = False
    original_name: str | None = None
    original_description: str | None = None
    original_category: str | None = None
    created_at: datetime
    updated_at: datetime


class Threat(_CatalogEntry):
    pass


class Mitigation(_CatalogEntry):
    pass


class CatalogEntryCreate(RequestModel):
    framework_id: int
    name: str
    description: str | None = None
    category: str | None = None
    is_custom: bool = True


class CatalogEntryUpdate(RequestModel):
    name: str | None = None
    description: str | None = None
    category: str | None = None
    framework_id: int | None = None


ThreatCreate = CatalogEntryCreate
ThreatUpdate = CatalogEntryUpdate
MitigationCreate = CatalogEntryCreate
MitigationUpdate = CatalogEntryUpdate


# ── Diagram threats (a catalog threat identified on a diagram element) ─────────


class DiagramThreat(ApiModel):
    id: int
    diagram_id: int
    model_id: int
    threat_id: int
    element_id: str
    element_type: str
    status: str = "identified"
    comments: str | None = None
    likelihood: int | None = None
    impact: int | None = None
    risk_score: int | None = None
    severity: str | None = None
    residual_likelihood: int | None = None
    residual_impact: int | None = None
    residual_risk_score: int | None = None
    residual_severity: str | None = None
    residual_comments: str | None = None
    acceptance_justification: str | None = None
    acceptance_approver_id: int | None = None
    acceptance_review_date: datetime | None = None
    accepted_at: datetime | None = None
    acceptance_review_status: str | None = None
    acceptance_review_note: str | None = None
    acceptance_reviewed_at: datetime | None = None
    created_at: datetime
    updated_at: datetime


class DiagramThreatWithDetails(DiagramThreat):
    threat: Threat
    model: Model | None = None
    acceptance_approver_name: str | None = None


class DiagramThreatCreate(RequestModel):
    diagram_id: int
    model_id: int
    threat_id: int
    element_id: str
    element_type: str
    status: str = "identified"
    comments: str | None = None
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)


class DiagramThreatUpdate(RequestModel):
    status: str | None = None
    comments: str | None = None
    likelihood: int | None = Field(default=None, ge=1, le=5)
    impact: int | None = Field(default=None, ge=1, le=5)
    residual_likelihood: int | None = Field(default=None, ge=1, le=5)
    residual_impact: int | None = Field(default=None, ge=1, le=5)
    residual_comments: str | None = None
    acceptance_justification: str | None = None
    acceptance_approver_id: int | None = None
    acceptance_review_date: str | None = None
    accepted_at: str | None = None
    acceptance_review_status: str | None = None
    acceptance_review_note: str | None = None
    acceptance_reviewed_at: datetime | None = None


# ── Diagram mitigations ────────────────────────────────────────────────────────


class DiagramMitigation(ApiModel):
    id: int
    diagram_id: int
    model_id: int
    mitigation_id: int
    threat_id: int | None = None
    element_id: str
    element_type: str
    status: str = "proposed"
    comments: str | None = None
    created_at: datetime
    updated_at: datetime


class DiagramMitigationWithDetails(DiagramMitigation):
    mitigation: Mitigation
    model: Model | None = None


class DiagramMitigationCreate(RequestModel):
    diagram_id: int
    model_id: int
    mitigation_id: int
    threat_id: int | None = None
    element_id: str
    element_type: str
    status: str = "proposed"
    comments: str | None = None


class DiagramMitigationUpdate(RequestModel):
    status: str | None = None
    comments: str | None = None


# ── Approvals ──────────────────────────────────────────────────────────────────


class ApprovalItem(ApiModel):
    """An accepted diagram threat assigned to the current user for review."""

    id: int
    diagram_threat_id: int
    threat_name: str
    category: str | None = None
    element_id: str
    diagram_id: int
    diagram_name: str | None = None
    product_id: int | None = None
    product_name: str | None = None
    accepted_by_name: str | None = None
    accepted_at: datetime | None = None
    acceptance_justification: str | None = None
    acceptance_review_date: datetime | None = None
    acceptance_review_status: str | None = None
    acceptance_review_note: str | None = None
    acceptance_reviewed_at: datetime | None = None
