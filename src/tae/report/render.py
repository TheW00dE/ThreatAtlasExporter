"""Build the report: validate, select data per section, render HTML, write PDF."""

from __future__ import annotations

import base64
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from jinja2 import ChoiceLoader, FileSystemLoader, StrictUndefined, select_autoescape
from jinja2.exceptions import SecurityError
from jinja2.sandbox import SandboxedEnvironment
from markupsafe import Markup

from tae import __version__
from tae.errors import EnvironmentProblem
from tae.models.api import severity_for_score
from tae.report import charts
from tae.report.definition import (
    AcceptedRisksSection,
    AppendixCatalogSection,
    CoverSection,
    DiagramSection,
    DocumentControlSection,
    DocumentInfo,
    ExecutiveSummarySection,
    MitigationTableSection,
    OnFailure,
    ProductInfoSection,
    ReportDefinition,
    ReportDefinitionError,
    RiskMatrixSection,
    RiskScaleSection,
    TextSection,
    ThreatTableSection,
    TocSection,
    ValidationFindingsSection,
)
from tae.report.diagram_svg import legend_svg, render_svg
from tae.report.query import (
    Scoped,
    apply_scope,
    filter_threats,
    group_mitigations,
    group_threats,
    sort_threats,
)
from tae.report.theme import DEFAULT_FOOTER, DEFAULT_HEADER, Theme, ThemeError, css_string, theme_css
from tae.risk import DEFAULT_BANDS, RiskScale, load_risk_scales
from tae.snapshot import Snapshot, build_view
from tae.snapshot.view import ACTIVE_MITIGATION_STATUSES, ProductView
from tae.validate import ValidationConfig, ValidationResult, run
from tae.validate.findings import Level

TEMPLATES = resources.files("tae.report") / "templates"


class ReportBlocked(Exception):
    """Validation failed and the definition says not to produce a PDF."""

    def __init__(self, result: ValidationResult) -> None:
        self.result = result
        super().__init__("Validation failed; report generation is blocked (on_failure: block)")


@dataclass
class RenderedSection:
    type: str
    anchor: str
    title: str
    number: str | None
    page_break: bool
    data: dict[str, Any] = field(default_factory=dict)


@dataclass
class ReportOutput:
    html: str
    validation: ValidationResult
    validation_failed: bool
    on_failure: OnFailure
    base_url: str
    allowed_dirs: list[Path]

    @property
    def exit_with_failure(self) -> bool:
        """``annotate`` (and ``block``) mean a failing run, even though a PDF exists."""
        return self.validation_failed and self.on_failure in (OnFailure.annotate, OnFailure.block)

    def write_pdf(self, path: Path) -> None:
        html_cls = _weasyprint_html()
        path.parent.mkdir(parents=True, exist_ok=True)
        fetcher = make_url_fetcher(self.allowed_dirs)
        html_cls(string=self.html, base_url=self.base_url, url_fetcher=fetcher).write_pdf(str(path))


def _weasyprint_html() -> Any:
    """Import WeasyPrint lazily, explaining what to do if its system libraries are missing."""
    try:
        from weasyprint import HTML
    except OSError as exc:
        first_line = str(exc).splitlines()[0] if str(exc) else exc.__class__.__name__
        raise EnvironmentProblem(
            f"PDF rendering needs the Pango and HarfBuzz libraries, which were not found ({first_line}). "
            "Use the Docker image, or install them: apt-get install libpango-1.0-0 libpangoft2-1.0-0 "
            "libharfbuzz-subset0 (Debian/Ubuntu), brew install pango (macOS). --html works without them."
        ) from None
    return HTML


def make_url_fetcher(allowed_dirs: list[Path]) -> Any:
    """A WeasyPrint URL fetcher that allows ``data:`` URIs and template files only.

    Report content comes from the ThreatAtlas server, so the renderer must never
    fetch remote URLs or read arbitrary local files on its behalf.
    """
    from weasyprint.urls import URLFetcher

    roots = [d.resolve() for d in allowed_dirs]

    class SafeUrlFetcher(URLFetcher):  # type: ignore[misc]
        def __init__(self) -> None:
            super().__init__(allowed_protocols={"data", "file"}, allow_redirects=False)

        def fetch(self, url: str, headers: Any = None) -> Any:
            parsed = urlparse(url)
            if parsed.scheme == "file":
                path = Path(unquote(parsed.path)).resolve()
                if not any(path.is_relative_to(root) for root in roots):
                    raise ValueError(f"Blocked file outside the report templates: {url}")
            elif parsed.scheme != "data":
                raise ValueError(f"Blocked resource: {url}")
            return super().fetch(url, headers)

    return SafeUrlFetcher()


# ── helpers ─────────────────────────────────────────────────────────────────────────


def data_uri(content: bytes | str, mime: str) -> str:
    raw = content.encode() if isinstance(content, str) else content
    return f"data:{mime};base64,{base64.b64encode(raw).decode()}"


def _fmt_date(value: Any) -> str:
    if value is None:
        return "—"
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d")
    if isinstance(value, date):
        return value.isoformat()
    return str(value)


def _paragraphs(text: str | None) -> list[str]:
    if not text:
        return []
    return [p.strip() for p in re.split(r"\n\s*\n", text) if p.strip()]


def _finalize(value: Any) -> Any:
    """How placeholder values print: nothing for missing values, dates without microseconds."""
    if value is None:
        return ""
    if isinstance(value, datetime):
        return value.strftime("%Y-%m-%d %H:%M UTC") if value.tzinfo else value.strftime("%Y-%m-%d %H:%M")
    return value


_user_env = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined, finalize=_finalize)
_user_env.filters["date"] = lambda v: _fmt_date(v)


def render_user_string(template: str | None, **ctx: Any) -> str:
    """Fill ``{{ product.name }}``-style placeholders in definition text, safely."""
    if not template:
        return ""
    try:
        return _user_env.from_string(template).render(**ctx)
    except Exception as exc:
        raise ReportDefinitionError(f"Cannot fill in {template!r}: {exc}") from exc


# Logos are embedded in the PDF, so a definition must not be able to smuggle any other
# file in: the content has to really be one of these image formats.
LOGO_MAX_BYTES = 2 * 1024 * 1024
IMAGE_MAX_BYTES = 4 * 1024 * 1024
_IMAGE_SIGNATURES = (
    (b"\x89PNG\r\n\x1a\n", "image/png"),
    (b"\xff\xd8\xff", "image/jpeg"),
    (b"GIF87a", "image/gif"),
    (b"GIF89a", "image/gif"),
)


def load_logo(path: Path, max_bytes: int = LOGO_MAX_BYTES) -> tuple[bytes, str]:
    """Read a logo and return (content, MIME type), refusing anything but real images."""
    if path.stat().st_size > max_bytes:
        raise ReportDefinitionError(f"Image is larger than {max_bytes // (1024 * 1024)} MB: {path}")
    data = path.read_bytes()
    for signature, mime in _IMAGE_SIGNATURES:
        if data.startswith(signature):
            return data, mime
    if data[:4] == b"RIFF" and data[8:12] == b"WEBP":
        return data, "image/webp"
    if path.suffix.lower() == ".svg":
        head = data[:2048].decode("utf-8", errors="replace").lower()
        if "<svg" in head:
            return data, "image/svg+xml"
    raise ReportDefinitionError(f"Logo must be a PNG, JPEG, GIF, WebP or SVG image: {path}")


# ── theme ──────────────────────────────────────────────────────────────────────────

EXTRA_CSS_MAX = 200_000


def load_theme(definition: ReportDefinition, override: Path | None = None) -> Theme:
    """The theme for a report: ``override``, else the definition's ``theme:``, else the default."""
    if override is not None:
        theme = Theme.load(override)
    elif isinstance(definition.theme, str):
        path = definition.resolve(definition.theme)
        if not path.is_file():
            raise ThemeError(f"Theme not found: {path}")
        theme = Theme.load(path)
    elif isinstance(definition.theme, dict):
        theme = Theme.from_data(definition.theme, definition.base_dir, "inline theme")
    else:
        theme = Theme.from_data({}, definition.base_dir)
    if "page_size" in definition.model_fields_set:  # an explicit definition setting wins
        theme.page = theme.page.model_copy(update={"size": definition.page_size})
    return theme


@dataclass
class EffectiveBranding:
    """Branding after merging the theme with the definition (definition wins)."""

    organisation: str | None
    classification: str | None
    footer: str | None
    logo: Path | None
    primary_color: str
    accent_color: str

    @property
    def footer_line(self) -> str:
        return " · ".join(x for x in (self.organisation, self.footer) if x)


def effective_branding(definition: ReportDefinition, theme: Theme) -> EffectiveBranding:
    db, tb = definition.branding, theme.branding
    explicit = db.model_fields_set

    def pick(name: str) -> str | None:
        value: str | None = getattr(db, name) if name in explicit else getattr(tb, name)
        return value

    if "logo" in explicit:
        logo = definition.resolve(db.logo) if db.logo else None
    else:
        logo = theme.resolve(tb.logo) if tb.logo else None
    return EffectiveBranding(
        organisation=pick("organisation"),
        classification=pick("classification"),
        footer=pick("footer"),
        logo=logo,
        primary_color=db.primary_color if "primary_color" in explicit else theme.colors.primary,
        accent_color=db.accent_color if "accent_color" in explicit else theme.colors.accent,
    )


def render_slots(theme: Theme, ctx: dict[str, Any]) -> dict[str, str]:
    """Header/footer slot texts with placeholders filled in, keyed by margin box."""
    out: dict[str, str] = {}
    for where, slots, defaults in (
        ("top", theme.header, DEFAULT_HEADER),
        ("bottom", theme.footer, DEFAULT_FOOTER),
    ):
        for pos in ("left", "center", "right"):
            text = getattr(slots, pos)
            if text is None:
                text = defaults[pos]
            out[f"{where}-{pos}"] = render_user_string(text, **ctx).strip()
    return out


def cover_image_css(theme: Theme) -> str:
    if theme.cover.layout != "image":
        return ""
    if not theme.cover.background_image:
        raise ThemeError("Cover layout 'image' needs cover.background_image")
    path = theme.resolve(theme.cover.background_image)
    if not path.is_file():
        raise ThemeError(f"Cover image not found: {path}")
    uri = data_uri(*load_logo(path, max_bytes=IMAGE_MAX_BYTES))
    return f'.cover-layout-image {{ background-image: url("{uri}"); }}'


def extra_css(theme: Theme) -> str:
    css = theme.extra_css or ""
    if len(css) > EXTRA_CSS_MAX:
        raise ThemeError(f"extra_css is longer than {EXTRA_CSS_MAX} characters")
    return css.replace("</", "<\\/")


# ── section builders ────────────────────────────────────────────────────────────────


class Builder:
    def __init__(
        self,
        view: ProductView,
        scoped: Scoped,
        definition: ReportDefinition,
        validation: ValidationResult,
        validation_failed: bool,
        as_of: date,
        theme: Theme | None = None,
        branding: EffectiveBranding | None = None,
    ) -> None:
        self.theme = theme or Theme()
        self.branding = branding or effective_branding(definition, self.theme)
        self.t = self.theme.label
        sev = self.theme.colors.severity
        levels = ("critical", "high", "medium", "low")
        self.colors: dict[str | None, str] = {k: getattr(sev, k) for k in levels}
        self.view = view
        self.scoped = scoped
        self.d = definition
        self.validation = validation
        self.validation_failed = validation_failed
        self.as_of = as_of
        self.threats = filter_threats(scoped.threats, definition.filters)
        threat_ids = {t.id for t in self.threats}
        self.mitigations = [m for m in scoped.mitigations if m.threat is None or m.threat.id in threat_ids]
        b = self.branding
        self.user_ctx = {
            "product": view.product,
            "meta": view.snapshot.meta,
            "organisation": b.organisation or "",
            "classification": b.classification or "",
            "footer": b.footer_line,
            "document": definition.document or DocumentInfo(),
            "report_date": as_of.isoformat(),
        }
        self.user_ctx["document"] = self._filled_document(definition.document or DocumentInfo())

    def _filled_document(self, doc: DocumentInfo) -> DocumentInfo:
        """Document control data with its own placeholders ({{ product.name }} etc.) filled in."""
        ctx = {**self.user_ctx, "document": doc}

        def fill_all(item: Any) -> Any:
            return item.model_copy(
                update={
                    k: render_user_string(v, **ctx)
                    for k, v in item.model_dump().items()
                    if isinstance(v, str)
                }
            )

        filled: DocumentInfo = fill_all(doc).model_copy(
            update={
                "revisions": [fill_all(r) for r in doc.revisions],
                "approvals": [fill_all(a) for a in doc.approvals],
            }
        )
        return filled

    # Each builder returns the template data for one section.

    def cover(self, s: CoverSection) -> dict[str, Any]:
        p = self.view.product
        meta = self.view.snapshot.meta
        logo = None
        if self.branding.logo is not None:
            if not self.branding.logo.is_file():
                raise ReportDefinitionError(f"Logo not found: {self.branding.logo}")
            logo = data_uri(*load_logo(self.branding.logo))
        t = self.t
        if self.theme.cover.facts is not None:
            facts = [
                (
                    render_user_string(label, **self.user_ctx),
                    render_user_string(value, **self.user_ctx) or "—",
                )
                for label, value in self.theme.cover.facts
            ]
        else:
            facts = [
                (t("field.product"), p.name),
                (t("product.status"), p.status or "—"),
                (t("product.owner_name"), p.owner_name or "—"),
                (t("product.reviewer"), p.reviewer or "—"),
                (t("field.report_date"), self.as_of.isoformat()),
                (t("field.data_pulled"), meta.pulled_at.strftime("%Y-%m-%d %H:%M UTC")),
                (t("field.source"), meta.source_url or "—"),
            ]
        return {"logo": logo, "facts": facts}

    def document_control(self, s: DocumentControlSection) -> dict[str, Any]:
        return {"document": self.user_ctx["document"]}

    def toc(self, s: TocSection) -> dict[str, Any]:
        return {}  # filled in after all sections are known

    def text(self, s: TextSection) -> dict[str, Any]:
        return {"paragraphs": _paragraphs(render_user_string(s.body, **self.user_ctx))}

    def executive_summary(self, s: ExecutiveSummarySection) -> dict[str, Any]:
        threats = self.threats
        sev_counts: dict[str, tuple[int, int]] = {}
        for sev in ("critical", "high", "medium", "low", "unscored"):
            items = [t for t in threats if (t.severity or "unscored") == sev]
            if items or sev != "unscored":
                sev_counts[sev] = (sum(t.is_open for t in items), len(items))
        statuses = Counter(t.status for t in threats)
        mit_statuses = Counter(m.status for m in self.mitigations)
        scored = sum(t.risk_score is not None for t in threats)
        resolved = sum(t.status in ("mitigated", "accepted") for t in threats)
        accepted = [t for t in threats if t.status == "accepted"]
        open_high = [t for t in threats if t.is_open and t.severity in ("high", "critical")]
        overdue = [
            t
            for t in accepted
            if t.record.acceptance_review_date and t.record.acceptance_review_date.date() < self.as_of
        ]
        awaiting = [t for t in accepted if t.record.acceptance_review_status != "approved"]
        active_mits = [m for m in self.mitigations if m.status in ACTIVE_MITIGATION_STATUSES]
        top = sorted(
            (t for t in threats if t.is_open), key=lambda t: (-t.severity_rank, -(t.risk_score or 0))
        )[:5]

        def pct(n: int) -> str:
            return f"{round(100 * n / len(threats))}%" if threats else "—"

        counts = self.validation.counts()
        return {
            "kpis": [
                ("Threats", str(len(threats)), f"on {len(self.scoped.diagrams)} diagram(s)"),
                ("Open high/critical", str(len(open_high)), "must be mitigated or accepted"),
                ("Mitigated or accepted", pct(resolved), f"{resolved} of {len(threats)}"),
                ("Scored", pct(scored), f"{scored} of {len(threats)} have likelihood and impact"),
                (
                    "Accepted risks",
                    str(len(accepted)),
                    f"{len(awaiting)} awaiting approval, {len(overdue)} overdue",
                ),
                (
                    "Mitigations",
                    str(len(self.mitigations)),
                    f"{len(active_mits)} implemented or verified",
                ),
            ],
            "severity_chart": data_uri(
                charts.severity_bars(sev_counts, colors=self.colors, labels=self._severity_labels()),
                "image/svg+xml",
            ),
            "statuses": [(st, statuses.get(st, 0)) for st in ("identified", "accepted", "mitigated")],
            "mitigation_statuses": [
                (st, mit_statuses.get(st, 0)) for st in ("proposed", "implemented", "verified")
            ],
            "top_risks": top,
            "validation": {"failed": self.validation_failed, **counts},
            "filters": self._describe_filters(),
        }

    def _severity_labels(self) -> dict[str, str]:
        labels = {
            s: self.t(f"severity.{s}").capitalize() for s in ("critical", "high", "medium", "low", "unscored")
        }
        return {**labels, "open": self.t("text.open")}

    def _describe_filters(self) -> list[str]:
        f, sc = self.d.filters, self.d.scope
        notes = []
        if sc.diagrams != "all":
            notes.append("Diagrams: " + ", ".join(str(x) for x in sc.diagrams))
        if sc.frameworks:
            notes.append("Frameworks: " + ", ".join(sc.frameworks))
        if set(sc.model_status) != {"in_progress", "completed"}:
            notes.append("Threat model status: " + ", ".join(sc.model_status))
        if f.min_severity:
            notes.append(f"Severity {f.min_severity} and above")
        if f.statuses:
            notes.append("Threat status: " + ", ".join(f.statuses))
        if f.categories:
            notes.append("Categories: " + ", ".join(f.categories))
        return notes

    def product_info(self, s: ProductInfoSection) -> dict[str, Any]:
        p = self.view.product
        rows = []
        for name in s.fields:
            value = getattr(p, name, None)
            rows.append((self.t(f"product.{name}"), value if value not in (None, "") else "—"))
        frameworks = sorted({m.framework_name for d in self.scoped.diagrams for m in d.models})
        return {"rows": rows, "frameworks": frameworks, "diagram_count": len(self.scoped.diagrams)}

    def diagram(self, s: DiagramSection) -> dict[str, Any]:
        visible = {t.id for t in self.threats}
        diagrams = []
        for d in self.scoped.diagrams:
            svg = render_svg(d, annotate_threats=s.annotate_threats, visible=visible, colors=self.colors)
            elements = []
            for e in sorted(d.elements.values(), key=lambda e: (e.kind, e.label.casefold())):
                if not s.element_table:
                    break
                threats = [t for t in d.threats_on(e.id) if t.id in visible]
                if e.is_boundary and not threats:
                    continue
                elements.append(
                    {
                        "label": e.label,
                        "type": e.type,
                        "kind": e.kind,
                        "flow": (
                            f"{d.elements[e.source].label} → {d.elements[e.target].label}"
                            if e.kind == "edge" and e.source in d.elements and e.target in d.elements
                            else None
                        ),
                        "threats": threats,
                    }
                )
            diagrams.append(
                {
                    "view": d,
                    "svg": data_uri(svg, "image/svg+xml") if svg else None,
                    "wide": self._is_wide(svg),
                    "models": d.models,
                    "elements": elements,
                    "description": _paragraphs(d.diagram.description),
                }
            )
        return {
            "diagrams": diagrams,
            "legend": data_uri(legend_svg(self.colors), "image/svg+xml") if s.legend else None,
        }

    @staticmethod
    def _is_wide(svg: str | None) -> bool:
        if not svg:
            return False
        m = re.search(r'width="(\d+)" height="(\d+)"', svg)
        return bool(m and int(m.group(1)) > 1.6 * int(m.group(2)))

    def matrix_scale(self) -> RiskScale | None:
        """The custom scale to colour the risk matrix with: only when all threats share one."""
        scales = {id(t.scale): t.scale for t in self.threats}
        if len(scales) == 1:
            return next(iter(scales.values()))
        if not self.threats and len(self.view.scales.scales) == 1:
            return self.view.scales.scales[0]
        return None

    def risk_matrix(self, s: RiskMatrixSection) -> dict[str, Any]:
        scale = self.matrix_scale()
        band = scale.severity if scale else severity_for_score

        def matrix(pairs: list[tuple[int | None, int | None]]) -> list[list[dict[str, Any]]]:
            counts = Counter((li, im) for li, im in pairs if li and im)
            rows = []
            for likelihood in range(5, 0, -1):
                rows.append(
                    [
                        {
                            "count": counts.get((likelihood, impact), 0),
                            "severity": band(likelihood * impact),
                            "likelihood": likelihood,
                            "impact": impact,
                        }
                        for impact in range(1, 6)
                    ]
                )
            return rows

        inherent = matrix([(t.record.likelihood, t.record.impact) for t in self.threats])
        residual = (
            matrix([(t.record.residual_likelihood, t.record.residual_impact) for t in self.threats])
            if s.residual
            else None
        )
        unscored = sum(1 for t in self.threats if t.record.likelihood is None or t.record.impact is None)
        mixed = len({id(t.scale) for t in self.threats}) > 1
        return {
            "inherent": inherent,
            "residual": residual,
            "unscored": unscored,
            "likelihood_labels": {n: lvl.label for n, lvl in scale.likelihood.items()} if scale else {},
            "impact_labels": {n: lvl.label for n, lvl in scale.impact.items()} if scale else {},
            "bands": (scale.bands if scale else DEFAULT_BANDS),
            "scale_name": scale.name if scale else None,
            "mixed": mixed,
        }

    def risk_scale(self, s: RiskScaleSection) -> dict[str, Any]:
        used: dict[int, RiskScale] = {}
        for t in self.threats:
            if t.scale is not None:
                used.setdefault(id(t.scale), t.scale)
        for sc in self.view.scales.scales:
            used.setdefault(id(sc), sc)
        default_used = not self.view.scales or any(t.scale is None for t in self.threats)
        return {"scales": list(used.values()), "default_bands": DEFAULT_BANDS if default_used else None}

    def threat_table(self, s: ThreatTableSection) -> dict[str, Any]:
        threats = filter_threats(self.scoped.threats, s.filters) if s.filters else self.threats
        threats = sort_threats(threats, s.sort)
        return {
            "groups": group_threats(threats, s.group_by),
            "columns": s.columns,
            "count": len(threats),
            "details": s.details,
        }

    def mitigation_table(self, s: MitigationTableSection) -> dict[str, Any]:
        mitigations = [m for m in self.mitigations if s.statuses is None or m.status in s.statuses]
        mitigations.sort(key=lambda m: (m.diagram.name.casefold(), m.name.casefold(), m.id))
        return {
            "groups": group_mitigations(mitigations, s.group_by),
            "columns": s.columns,
            "count": len(mitigations),
        }

    def accepted_risks(self, s: AcceptedRisksSection) -> dict[str, Any]:
        rows = []
        for t in sorted(
            (t for t in self.threats if t.status == "accepted"), key=lambda t: (-t.severity_rank, t.ref)
        ):
            r = t.record
            due = r.acceptance_review_date
            rows.append(
                {
                    "threat": t,
                    "justification": r.acceptance_justification,
                    "approver": r.acceptance_approver_name
                    or ("ID " + str(r.acceptance_approver_id) if r.acceptance_approver_id else None),
                    "accepted_at": _fmt_date(r.accepted_at),
                    "review_date": _fmt_date(due),
                    "overdue": bool(due and due.date() < self.as_of),
                    "review_status": r.acceptance_review_status or "pending",
                    "review_note": r.acceptance_review_note,
                }
            )
        return {"rows": rows}

    def validation_findings(self, s: ValidationFindingsSection) -> dict[str, Any]:
        findings = [f for f in self.validation.findings if f.level.at_least(s.min_level)]
        return {
            "findings": findings,
            "counts": self.validation.counts(),
            "failed": self.validation_failed,
            "fail_level": self.d.validation.fail_level.value,
            "min_level": s.min_level.value,
            "hidden": len(self.validation.findings) - len(findings),
        }

    def appendix_catalog(self, s: AppendixCatalogSection) -> dict[str, Any]:
        threats: dict[int, Any] = {}
        for t in self.threats:
            threats.setdefault(t.record.threat.id, (t.record.threat, t.framework_name, []))[2].append(t.ref)
        mitigations: dict[int, Any] = {}
        for m in self.mitigations:
            mitigations.setdefault(m.record.mitigation.id, (m.record.mitigation, []))[1].append(m.ref)
        return {
            "threats": sorted(threats.values(), key=lambda x: x[0].name.casefold())
            if "threats" in s.include
            else [],
            "mitigations": (
                sorted(mitigations.values(), key=lambda x: x[0].name.casefold())
                if "mitigations" in s.include
                else []
            ),
        }


# ── top level ─────────────────────────────────────────────────────────────────────────


def scoped_validation_view(
    snapshot: Snapshot, view: ProductView, scoped: Scoped, definition: ReportDefinition
) -> ProductView:
    """The part of the product the report covers, for validation.

    Validation follows the report's *scope* (diagrams, frameworks, threat-model
    statuses), so threats a report deliberately leaves out (e.g. in archived threat
    models) can't fail or block it. Display *filters* (such as min_severity) are not
    applied: a report showing only high risks is still validated on everything in scope.
    Threat and mitigation references (T1, M1) are kept identical to the report's.
    """
    diagram_ids = {d.id for d in scoped.diagrams}
    frameworks = {f.casefold() for f in definition.scope.frameworks}
    statuses = set(definition.scope.model_status)
    models = [
        m
        for m in snapshot.models
        if m.diagram_id in diagram_ids
        and m.status in statuses
        and (not frameworks or m.framework_name.casefold() in frameworks)
    ]
    subset = snapshot.model_copy(
        update={
            "diagrams": [d.diagram for d in scoped.diagrams],
            "models": models,
            "diagram_threats": [t.record for t in scoped.threats],
            "diagram_mitigations": [m.record for m in scoped.mitigations],
        }
    )
    sub_view = build_view(subset, view.scales)
    refs = {t.id: t.ref for t in view.threats}
    for t in sub_view.threats:
        t.ref = refs.get(t.id, t.ref)
    mrefs = {m.id: m.ref for m in view.mitigations}
    for m in sub_view.mitigations:
        m.ref = mrefs.get(m.id, m.ref)
    return sub_view


def load_validation_config(definition: ReportDefinition, override: Path | None) -> ValidationConfig:
    if override is not None:
        return ValidationConfig.load(override)
    if definition.validation.rules:
        return ValidationConfig.load(definition.resolve(definition.validation.rules))
    return ValidationConfig()


def _render(template: Any, **ctx: Any) -> str:
    return str(template.render(**ctx))


def build_report(
    snapshot: Snapshot,
    definition: ReportDefinition,
    *,
    as_of: date | None = None,
    on_failure: OnFailure | None = None,
    rules: Path | None = None,
    theme: Path | None = None,
) -> ReportOutput:
    as_of = as_of or date.today()
    mode = on_failure or definition.validation.on_failure
    config = load_validation_config(definition, rules)
    scales = load_risk_scales(
        [*(definition.resolve(p) for p in definition.risk_scales), *config.scale_paths()]
    )
    view = build_view(snapshot, scales)
    scoped = apply_scope(view, definition.scope)
    validation = run(scoped_validation_view(snapshot, view, scoped, definition), config, as_of=as_of)
    failed = validation.fails(definition.validation.fail_level)
    if failed and mode is OnFailure.block:
        raise ReportBlocked(validation)

    sections = list(definition.sections)
    if mode is OnFailure.ignore:
        sections = [s for s in sections if not isinstance(s, ValidationFindingsSection)]
    elif failed and not any(isinstance(s, ValidationFindingsSection) for s in sections):
        sections.append(ValidationFindingsSection(type="validation_findings"))

    the_theme = load_theme(definition, theme)
    branding = effective_branding(definition, the_theme)
    builder = Builder(view, scoped, definition, validation, failed, as_of, the_theme, branding)

    def default_title(kind: str) -> str:
        return "" if kind in ("text", "cover") else the_theme.label(f"section.{kind}")

    rendered: list[RenderedSection] = []
    number = 0
    for i, s in enumerate(sections):
        if isinstance(s, CoverSection | TocSection):
            title, num = s.title or default_title(s.type), None
        else:
            title = render_user_string(s.title, **builder.user_ctx) if s.title else default_title(s.type)
            num = None
            if title:
                number += 1
                num = str(number) if the_theme.numbering else None
        data = getattr(builder, s.type)(s)
        rendered.append(RenderedSection(s.type, f"s{i}-{s.type}", title, num, s.page_break, data))
    for r in rendered:
        if r.type == "toc":
            r.data["entries"] = [x for x in rendered if x.type not in ("cover", "toc") and x.title]

    template_dirs: list[Path] = []
    if definition.template:
        custom = definition.resolve(definition.template)
        if not custom.is_dir():
            raise ReportDefinitionError(f"Template directory not found: {custom}")
        template_dirs.append(custom)
    builtin_dir = Path(str(TEMPLATES))
    # Sandboxed, so a custom template directory from a shared definition can format the
    # report but can't reach Python internals (and through them, the machine).
    env = SandboxedEnvironment(
        loader=ChoiceLoader([FileSystemLoader([str(p) for p in [*template_dirs, builtin_dir]])]),
        autoescape=select_autoescape(["html", "j2"], default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["date"] = _fmt_date
    env.filters["css_string"] = lambda v: Markup(css_string(str(v)))  # noqa: S704  (value is CSS-escaped)
    env.filters["paragraphs"] = _paragraphs
    env.globals["t"] = the_theme.label

    title = render_user_string(definition.title, **builder.user_ctx)
    subtitle = render_user_string(definition.subtitle, **builder.user_ctx)
    banner = failed and mode is OnFailure.annotate
    slots = render_slots(the_theme, {**builder.user_ctx, "title": title, "subtitle": subtitle})
    css = theme_css(the_theme, branding.primary_color, branding.accent_color, slots, banner)
    css = "\n".join(x for x in (css, cover_image_css(the_theme)) if x).replace("</", "<\\/")
    template = env.get_template("report.html.j2")
    try:
        html = _render(
            template,
            definition=definition,
            branding=branding,
            theme=the_theme,
            theme_css=Markup(css),  # noqa: S704  (built from validated and CSS-escaped values)
            extra_css=Markup(extra_css(the_theme)),  # noqa: S704  (theme author's own stylesheet)
            title=title,
            subtitle=subtitle,
            product=view.product,
            meta=snapshot.meta,
            sections=rendered,
            banner=banner,
            validation=validation,
            as_of=as_of,
            generated_at=datetime.now(UTC),
            tool_version=__version__,
            snapshot_hash=snapshot.content_hash()[:12],
            Level=Level,
        )
    except SecurityError as exc:
        raise ReportDefinitionError(
            f"A report template tried something the template sandbox doesn't allow: {exc}"
        ) from None
    return ReportOutput(
        html=html,
        validation=validation,
        validation_failed=failed,
        on_failure=mode,
        base_url=(template_dirs[0] if template_dirs else builtin_dir).as_uri() + "/",
        allowed_dirs=[*template_dirs, builtin_dir],
    )
