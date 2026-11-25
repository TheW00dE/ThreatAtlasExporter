"""Build the report: validate, select data per section, render HTML, write PDF."""

from __future__ import annotations

import base64
import mimetypes
import re
from collections import Counter
from dataclasses import dataclass, field
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any
from urllib.parse import unquote, urlparse

from jinja2 import ChoiceLoader, Environment, FileSystemLoader, StrictUndefined, select_autoescape
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
    ExecutiveSummarySection,
    MitigationTableSection,
    OnFailure,
    ProductInfoSection,
    ReportDefinition,
    ReportDefinitionError,
    RiskMatrixSection,
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
from tae.snapshot import Snapshot, build_view
from tae.snapshot.view import ACTIVE_MITIGATION_STATUSES, ProductView
from tae.validate import ValidationConfig, ValidationResult, run
from tae.validate.findings import Level

TEMPLATES = resources.files("tae.report") / "templates"

DEFAULT_TITLES = {
    "toc": "Contents",
    "executive_summary": "Executive summary",
    "product_info": "Product information",
    "diagram": "Data flow diagrams",
    "risk_matrix": "Risk matrix",
    "threat_table": "Threats",
    "mitigation_table": "Mitigations",
    "accepted_risks": "Accepted risks",
    "validation_findings": "Validation findings",
    "appendix_catalog": "Appendix: threat and mitigation catalogue",
    "text": "",
}

PRODUCT_FIELD_LABELS = {
    "name": "Name",
    "description": "Description",
    "status": "Lifecycle stage",
    "business_area": "Business area",
    "owner_name": "Owner",
    "owner_email": "Owner email",
    "reviewer": "Reviewer",
    "contributors": "Contributors",
    "repository_url": "Repository",
    "confluence_url": "Documentation",
    "application_url": "Application URL",
    "jira_project_key": "Jira project",
}


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


def css_string(value: str) -> str:
    """Quote a value for use as a CSS string literal."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    escaped = cleaned.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\3C ").replace(">", "\\3E ")
    return f'"{escaped}"'


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


_user_env = SandboxedEnvironment(autoescape=False, undefined=StrictUndefined)


def render_user_string(template: str | None, **ctx: Any) -> str:
    """Fill ``{{ product.name }}``-style placeholders in definition text, safely."""
    if not template:
        return ""
    try:
        return _user_env.from_string(template).render(**ctx)
    except Exception as exc:
        raise ReportDefinitionError(f"Cannot fill in {template!r}: {exc}") from exc


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
    ) -> None:
        self.view = view
        self.scoped = scoped
        self.d = definition
        self.validation = validation
        self.validation_failed = validation_failed
        self.as_of = as_of
        self.threats = filter_threats(scoped.threats, definition.filters)
        threat_ids = {t.id for t in self.threats}
        self.mitigations = [m for m in scoped.mitigations if m.threat is None or m.threat.id in threat_ids]
        self.user_ctx = {"product": view.product, "meta": view.snapshot.meta}

    # Each builder returns the template data for one section.

    def cover(self, s: CoverSection) -> dict[str, Any]:
        p = self.view.product
        meta = self.view.snapshot.meta
        logo = None
        if self.d.branding.logo:
            path = self.d.resolve(self.d.branding.logo)
            if not path.is_file():
                raise ReportDefinitionError(f"Logo not found: {path}")
            mime = mimetypes.guess_type(path.name)[0] or "application/octet-stream"
            if not mime.startswith("image/"):
                raise ReportDefinitionError(f"Logo must be an image, got {mime}: {path}")
            logo = data_uri(path.read_bytes(), mime)
        return {
            "logo": logo,
            "facts": [
                ("Product", p.name),
                ("Lifecycle stage", p.status or "—"),
                ("Owner", p.owner_name or "—"),
                ("Reviewer", p.reviewer or "—"),
                ("Report date", self.as_of.isoformat()),
                ("Data pulled", meta.pulled_at.strftime("%Y-%m-%d %H:%M UTC")),
                ("Source", meta.source_url or "—"),
            ],
        }

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
            "severity_chart": data_uri(charts.severity_bars(sev_counts), "image/svg+xml"),
            "statuses": [(st, statuses.get(st, 0)) for st in ("identified", "accepted", "mitigated")],
            "mitigation_statuses": [
                (st, mit_statuses.get(st, 0)) for st in ("proposed", "implemented", "verified")
            ],
            "top_risks": top,
            "validation": {"failed": self.validation_failed, **counts},
            "filters": self._describe_filters(),
        }

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
            rows.append((PRODUCT_FIELD_LABELS[name], value if value not in (None, "") else "—"))
        frameworks = sorted({m.framework_name for d in self.scoped.diagrams for m in d.models})
        return {"rows": rows, "frameworks": frameworks, "diagram_count": len(self.scoped.diagrams)}

    def diagram(self, s: DiagramSection) -> dict[str, Any]:
        visible = {t.id for t in self.threats}
        diagrams = []
        for d in self.scoped.diagrams:
            svg = render_svg(d, annotate_threats=s.annotate_threats)
            elements = []
            for e in sorted(d.elements.values(), key=lambda e: (e.kind, e.label.casefold())):
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
        return {"diagrams": diagrams, "legend": data_uri(legend_svg(), "image/svg+xml") if s.legend else None}

    @staticmethod
    def _is_wide(svg: str | None) -> bool:
        if not svg:
            return False
        m = re.search(r'width="(\d+)" height="(\d+)"', svg)
        return bool(m and int(m.group(1)) > 1.6 * int(m.group(2)))

    def risk_matrix(self, s: RiskMatrixSection) -> dict[str, Any]:
        def matrix(pairs: list[tuple[int | None, int | None]]) -> list[list[dict[str, Any]]]:
            counts = Counter((li, im) for li, im in pairs if li and im)
            rows = []
            for likelihood in range(5, 0, -1):
                rows.append(
                    [
                        {
                            "count": counts.get((likelihood, impact), 0),
                            "severity": severity_for_score(likelihood * impact),
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
        return {"inherent": inherent, "residual": residual, "unscored": unscored}

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


def load_validation_config(definition: ReportDefinition, override: Path | None) -> ValidationConfig:
    if override is not None:
        return ValidationConfig.load(override)
    if definition.validation.rules:
        return ValidationConfig.load(definition.resolve(definition.validation.rules))
    return ValidationConfig()


def build_report(
    snapshot: Snapshot,
    definition: ReportDefinition,
    *,
    as_of: date | None = None,
    on_failure: OnFailure | None = None,
    rules: Path | None = None,
) -> ReportOutput:
    as_of = as_of or date.today()
    mode = on_failure or definition.validation.on_failure
    view = build_view(snapshot)
    validation = run(view, load_validation_config(definition, rules), as_of=as_of)
    failed = validation.fails(definition.validation.fail_level)
    if failed and mode is OnFailure.block:
        raise ReportBlocked(validation)

    sections = list(definition.sections)
    if mode is OnFailure.ignore:
        sections = [s for s in sections if not isinstance(s, ValidationFindingsSection)]
    elif failed and not any(isinstance(s, ValidationFindingsSection) for s in sections):
        sections.append(ValidationFindingsSection(type="validation_findings"))

    builder = Builder(view, apply_scope(view, definition.scope), definition, validation, failed, as_of)
    rendered: list[RenderedSection] = []
    number = 0
    for i, s in enumerate(sections):
        if isinstance(s, CoverSection | TocSection):
            title, num = s.title or DEFAULT_TITLES.get(s.type, ""), None
        else:
            number += 1
            title = render_user_string(s.title, **builder.user_ctx) if s.title else DEFAULT_TITLES[s.type]
            num = str(number) if title else None
            if not title:
                number -= 1
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
    env = Environment(
        loader=ChoiceLoader([FileSystemLoader([str(p) for p in [*template_dirs, builtin_dir]])]),
        autoescape=select_autoescape(["html", "j2"], default_for_string=True, default=True),
        undefined=StrictUndefined,
        trim_blocks=True,
        lstrip_blocks=True,
    )
    env.filters["date"] = _fmt_date
    env.filters["css_string"] = lambda v: Markup(css_string(str(v)))  # noqa: S704  (value is CSS-escaped)
    env.filters["paragraphs"] = _paragraphs

    title = render_user_string(definition.title, **builder.user_ctx)
    subtitle = render_user_string(definition.subtitle, **builder.user_ctx)
    html = env.get_template("report.html.j2").render(
        definition=definition,
        branding=definition.branding,
        title=title,
        subtitle=subtitle,
        product=view.product,
        meta=snapshot.meta,
        sections=rendered,
        banner=failed and mode is OnFailure.annotate,
        validation=validation,
        as_of=as_of,
        generated_at=datetime.now(UTC),
        tool_version=__version__,
        snapshot_hash=snapshot.content_hash()[:12],
        Level=Level,
    )
    return ReportOutput(
        html=html,
        validation=validation,
        validation_failed=failed,
        on_failure=mode,
        base_url=(template_dirs[0] if template_dirs else builtin_dir).as_uri() + "/",
        allowed_dirs=[*template_dirs, builtin_dir],
    )
