"""The report definition: a YAML file that says what goes into the PDF.

See ``docs/report-definition.md`` for the full reference, and ``tae report init``
for a commented starting point.
"""

from __future__ import annotations

import re
from enum import StrEnum
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import (
    BaseModel,
    ConfigDict,
    Field,
    PrivateAttr,
    ValidationError,
    field_validator,
    model_validator,
)

from tae.errors import InputError
from tae.models.api import DIAGRAM_MITIGATION_STATUSES, DIAGRAM_THREAT_STATUSES, MODEL_STATUSES
from tae.validate.findings import FailLevel, Level

Severity = Literal["low", "medium", "high", "critical"]
ThreatStatus = Literal["identified", "mitigated", "accepted"]
MitigationStatus = Literal["proposed", "implemented", "verified"]


class ReportDefinitionError(InputError):
    """The report definition is invalid."""


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


class OnFailure(StrEnum):
    block = "block"  # no PDF, exit 10
    annotate = "annotate"  # PDF with banner and findings section, exit 10
    warn = "warn"  # PDF with findings section, exit 0
    ignore = "ignore"  # PDF without findings, exit 0


class Branding(Strict):
    organisation: str | None = Field(None, description="Shown on the cover and in the footer.")
    logo: str | None = Field(None, description="Logo image (PNG/SVG/JPG), relative to the definition file.")
    primary_color: str = Field("#1f3a5f", description="Headings, table headers, cover band.")
    accent_color: str = Field("#2f80ed", description="Links and highlights.")
    classification: str | None = Field(None, description="Banner text such as CONFIDENTIAL, on every page.")
    footer: str | None = Field(None, description="Extra footer text.")

    @field_validator("primary_color", "accent_color")
    @classmethod
    def _hex(cls, v: str) -> str:
        if not re.fullmatch(r"#[0-9a-fA-F]{3}([0-9a-fA-F]{3})?", v):
            raise ValueError(f"{v!r} is not a hex colour such as #1f3a5f")
        return v


class Scope(Strict):
    diagrams: list[str | int] | Literal["all"] = Field(
        "all", description="Diagram names or IDs to include, or 'all'."
    )
    frameworks: list[str] = Field(default_factory=list, description="Framework names (empty = all).")
    model_status: list[str] = Field(
        default_factory=lambda: ["in_progress", "completed"],
        description="Only threats from threat models in these statuses.",
    )

    @field_validator("model_status")
    @classmethod
    def _model_status(cls, v: list[str]) -> list[str]:
        bad = set(v) - set(MODEL_STATUSES)
        if bad:
            raise ValueError(f"unknown model status(es): {', '.join(sorted(bad))}")
        return v


class Filters(Strict):
    min_severity: Severity | None = Field(None, description="Hide threats below this severity.")
    include_unscored: bool = Field(True, description="Keep threats without a score when min_severity is set.")
    statuses: list[ThreatStatus] | None = Field(None, description="Only threats in these statuses.")
    categories: list[str] | None = Field(None, description="Only threats in these categories.")


class ValidationSettings(Strict):
    rules: str | None = Field(None, description="Validation config file, relative to the definition file.")
    on_failure: OnFailure = OnFailure.annotate
    fail_level: FailLevel = FailLevel.error


# ── defaults (typed, so mypy checks the literals) ────────────────────────────────


def _default_product_fields() -> list[ProductField]:
    return [
        "name",
        "description",
        "status",
        "business_area",
        "owner_name",
        "owner_email",
        "reviewer",
        "contributors",
        "repository_url",
        "application_url",
        "jira_project_key",
    ]


def _default_threat_columns() -> list[ThreatColumn]:
    return ["ref", "threat", "element", "likelihood", "impact", "severity", "status", "mitigations"]


def _default_mitigation_columns() -> list[MitigationColumn]:
    return ["ref", "mitigation", "element", "threat", "status"]


def _default_catalog() -> list[Literal["threats", "mitigations"]]:
    return ["threats", "mitigations"]


# ── sections ─────────────────────────────────────────────────────────────────────


class _Section(Strict):
    title: str | None = Field(None, description="Heading (defaults per section type).")
    page_break: bool = Field(True, description="Start the section on a new page.")


class CoverSection(_Section):
    type: Literal["cover"]
    page_break: bool = False


class TocSection(_Section):
    type: Literal["toc"]


class TextSection(_Section):
    type: Literal["text"]
    body: str = Field(
        description="Paragraphs separated by blank lines. {{ product.name }} etc. are filled in."
    )


class ExecutiveSummarySection(_Section):
    type: Literal["executive_summary"]


ProductField = Literal[
    "name",
    "description",
    "status",
    "business_area",
    "owner_name",
    "owner_email",
    "reviewer",
    "contributors",
    "repository_url",
    "confluence_url",
    "application_url",
    "jira_project_key",
]


class ProductInfoSection(_Section):
    type: Literal["product_info"]
    fields: list[ProductField] = Field(default_factory=_default_product_fields)


class DiagramSection(_Section):
    type: Literal["diagram"]
    annotate_threats: bool = Field(True, description="Badges with the threat count on each element.")
    legend: bool = True
    element_table: bool = Field(True, description="Table of elements and the threats on each.")


class RiskMatrixSection(_Section):
    type: Literal["risk_matrix"]
    residual: bool = Field(False, description="Also show the residual-risk matrix.")
    page_break: bool = False


class RiskScaleSection(_Section):
    type: Literal["risk_scale"]
    page_break: bool = False


ThreatColumn = Literal[
    "ref",
    "threat",
    "category",
    "element",
    "diagram",
    "framework",
    "likelihood",
    "impact",
    "score",
    "severity",
    "residual",
    "status",
    "mitigations",
    "description",
    "comments",
]
GroupBy = Literal["none", "diagram", "element", "severity", "category", "status", "framework"]
THREAT_SORT_KEYS = (
    "ref",
    "name",
    "severity",
    "risk_score",
    "residual_score",
    "status",
    "element",
    "category",
    "diagram",
)


class ThreatTableSection(_Section):
    type: Literal["threat_table"]
    group_by: GroupBy = "diagram"
    sort: list[str] = Field(default_factory=lambda: ["-severity", "-risk_score", "ref"])
    columns: list[ThreatColumn] = Field(default_factory=_default_threat_columns)
    filters: Filters | None = Field(None, description="Overrides the report-level filters for this table.")
    details: bool = Field(False, description="Show descriptions and comments under each threat.")

    @field_validator("sort")
    @classmethod
    def _sort(cls, v: list[str]) -> list[str]:
        for key in v:
            if key.lstrip("-") not in THREAT_SORT_KEYS:
                raise ValueError(
                    f"unknown sort key {key!r}; use {', '.join(THREAT_SORT_KEYS)} (prefix - for descending)"
                )
        return v


MitigationColumn = Literal[
    "ref", "mitigation", "category", "element", "diagram", "threat", "status", "description"
]


class MitigationTableSection(_Section):
    type: Literal["mitigation_table"]
    statuses: list[MitigationStatus] | None = None
    group_by: Literal["none", "diagram", "status", "element"] = "status"
    columns: list[MitigationColumn] = Field(default_factory=_default_mitigation_columns)


class AcceptedRisksSection(_Section):
    type: Literal["accepted_risks"]


class ValidationFindingsSection(_Section):
    type: Literal["validation_findings"]
    min_level: Level = Level.warning


class AppendixCatalogSection(_Section):
    type: Literal["appendix_catalog"]
    include: list[Literal["threats", "mitigations"]] = Field(default_factory=_default_catalog)


Section = Annotated[
    CoverSection
    | TocSection
    | TextSection
    | ExecutiveSummarySection
    | ProductInfoSection
    | DiagramSection
    | RiskMatrixSection
    | RiskScaleSection
    | ThreatTableSection
    | MitigationTableSection
    | AcceptedRisksSection
    | ValidationFindingsSection
    | AppendixCatalogSection,
    Field(discriminator="type"),
]


def default_sections() -> list[Any]:
    return [
        CoverSection(type="cover"),
        TocSection(type="toc"),
        ExecutiveSummarySection(type="executive_summary"),
        RiskMatrixSection(type="risk_matrix", residual=True),
        RiskScaleSection(type="risk_scale"),
        ProductInfoSection(type="product_info"),
        DiagramSection(type="diagram"),
        ThreatTableSection(type="threat_table"),
        MitigationTableSection(type="mitigation_table"),
        AcceptedRisksSection(type="accepted_risks"),
        ValidationFindingsSection(type="validation_findings"),
        AppendixCatalogSection(type="appendix_catalog"),
    ]


class ReportDefinition(Strict):
    title: str = "Threat Model Report"
    subtitle: str | None = "{{ product.name }}"
    template: str | None = Field(
        None, description="Directory with template overrides, relative to this file."
    )
    page_size: Literal["A4", "Letter"] = "A4"
    language: str = "en"
    branding: Branding = Field(default_factory=Branding)
    scope: Scope = Field(default_factory=Scope)
    filters: Filters = Field(default_factory=Filters)
    validation: ValidationSettings = Field(default_factory=ValidationSettings)
    risk_scales: list[str] = Field(
        default_factory=list,
        description="Framework or risk-scale files (relative to this file) whose custom risk scales "
        "set threat severities, the risk matrix and the risk scale section.",
    )
    sections: list[Section] = Field(default_factory=default_sections, min_length=1)

    # Directory the definition was loaded from; relative paths resolve against it.
    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    @model_validator(mode="after")
    def _single_cover(self) -> ReportDefinition:
        if sum(isinstance(s, CoverSection) for s in self.sections) > 1:
            raise ValueError("only one cover section is allowed")
        return self

    def resolve(self, relative: str) -> Path:
        path = Path(relative).expanduser()
        return path if path.is_absolute() else (self.base_dir / path)

    @classmethod
    def load(cls, path: Path) -> ReportDefinition:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ReportDefinitionError(f"Cannot read report definition {path}: {exc}") from exc
        return cls.from_data(raw, base_dir=path.resolve().parent, source=str(path))

    @classmethod
    def from_data(
        cls, raw: Any, base_dir: Path | None = None, source: str = "report definition"
    ) -> ReportDefinition:
        if raw is None:
            raw = {}
        if isinstance(raw, dict) and set(raw) == {"report"}:
            raw = raw["report"]  # allow an optional top-level `report:` key
        if not isinstance(raw, dict):
            raise ReportDefinitionError(f"{source}: expected a mapping at the top level")
        try:
            definition = cls.model_validate(raw)
        except ValidationError as exc:
            raise ReportDefinitionError(f"{source}: {exc}") from exc
        if base_dir is not None:
            definition._base_dir = base_dir
        return definition


def json_schema() -> dict[str, Any]:
    schema = ReportDefinition.model_json_schema()
    schema["$schema"] = "https://json-schema.org/draft/2020-12/schema"
    schema["title"] = "ThreatAtlasExporter report definition"
    return schema


# Re-exported for templates and docs.
STATUS_VOCAB = {"threat": DIAGRAM_THREAT_STATUSES, "mitigation": DIAGRAM_MITIGATION_STATUSES}
