"""Report themes: the look of a report, as YAML (``kind: report-theme``).

A theme sets fonts, colours, page size and margins, the running header and footer,
the cover layout, wording (headings, column names, status words), section numbering
and a watermark. Report definitions reference a theme file (``theme: corporate.yaml``)
or define one inline, so one corporate theme can serve many reports.

Every value that ends up in the page's CSS is validated or escaped here: colours must
be hex, lengths need a unit, font names are restricted to safe characters, free text
goes through the CSS string escaper, and font and image files are checked by content.
"""

from __future__ import annotations

import base64
import re
from pathlib import Path
from typing import Annotated, Any, Literal

import yaml
from pydantic import BaseModel, ConfigDict, Field, PrivateAttr, ValidationError, field_validator

from tae.errors import InputError

HexColor = Annotated[str, Field(pattern=r"^#[0-9a-fA-F]{6}$|^#[0-9a-fA-F]{3}$")]
Length = Annotated[str, Field(pattern=r"^\d+(\.\d+)?(mm|cm|in|pt|px)$")]
FontFamily = Annotated[str, Field(pattern=r"^[A-Za-z0-9 _-]{1,64}$")]

FONT_MAX_BYTES = 8 * 1024 * 1024
_FONT_SIGNATURES = (
    (b"\x00\x01\x00\x00", "font/ttf"),
    (b"true", "font/ttf"),
    (b"OTTO", "font/otf"),
    (b"wOFF", "font/woff"),
    (b"wOF2", "font/woff2"),
)
PAGE_SIZES_MM = {
    "A4": (210.0, 297.0),
    "A3": (297.0, 420.0),
    "A5": (148.0, 210.0),
    "Letter": (215.9, 279.4),
    "Legal": (215.9, 355.6),
}
_UNIT_MM = {"mm": 1.0, "cm": 10.0, "in": 25.4, "pt": 25.4 / 72, "px": 25.4 / 96}


class ThemeError(InputError):
    """A report theme is invalid."""


class Strict(BaseModel):
    model_config = ConfigDict(extra="forbid")


def length_mm(value: str) -> float:
    m = re.fullmatch(r"(\d+(?:\.\d+)?)(mm|cm|in|pt|px)", value)
    if not m:
        raise ValueError(f"{value!r} is not a length such as 20mm")
    return float(m.group(1)) * _UNIT_MM[m.group(2)]


# ── parts ───────────────────────────────────────────────────────────────────────


class FontFiles(Strict):
    regular: str
    bold: str | None = None
    italic: str | None = None
    bold_italic: str | None = None


class Font(Strict):
    family: FontFamily = Field(description="Name to use for the font, e.g. 'Source Sans 3'.")
    files: FontFiles | None = Field(None, description="Font files to embed (TTF, OTF, WOFF, WOFF2).")


class Fonts(Strict):
    body: Font = Field(default_factory=lambda: Font(family="DejaVu Sans"))
    headings: Font | None = Field(None, description="Defaults to the body font.")
    size: float = Field(9.5, ge=6, le=16, description="Base font size in points.")


class SeverityColors(Strict):
    critical: HexColor = "#b91c1c"
    high: HexColor = "#ea580c"
    medium: HexColor = "#facc15"
    low: HexColor = "#16a34a"


class Colors(Strict):
    primary: HexColor = "#1f3a5f"
    accent: HexColor = "#2f80ed"
    text: HexColor = "#111827"
    secondary_text: HexColor = "#374151"
    muted: HexColor = "#6b7280"
    headings: HexColor | None = Field(None, description="Defaults to primary.")
    table_header: HexColor | None = Field(None, description="Table header background; defaults to primary.")
    table_header_text: HexColor = "#ffffff"
    table_stripe: HexColor = "#f9fafb"
    border: HexColor = "#e5e7eb"
    cover_band: HexColor | None = Field(None, description="Defaults to primary.")
    cover_text: HexColor = "#ffffff"
    classification: HexColor = "#b91c1c"
    severity: SeverityColors = Field(default_factory=SeverityColors)
    matrix: SeverityColors | None = Field(
        None, description="Risk matrix cells; defaults to lighter severity colours."
    )


class Margins(Strict):
    top: Length = "20mm"
    right: Length = "16mm"
    bottom: Length = "18mm"
    left: Length = "16mm"


class Page(Strict):
    size: Literal["A4", "A3", "A5", "Letter", "Legal"] | tuple[Length, Length] = "A4"
    margins: Margins = Field(default_factory=lambda: Margins())

    @property
    def size_mm(self) -> tuple[float, float]:
        if isinstance(self.size, str):
            return PAGE_SIZES_MM[self.size]
        return length_mm(self.size[0]), length_mm(self.size[1])

    def css_size(self, landscape: bool = False) -> str:
        w, h = self.size_mm
        if landscape:
            w, h = h, w
        return f"{w:.1f}mm {h:.1f}mm"

    def css_margins(self) -> str:
        m = self.margins
        return f"{m.top} {m.right} {m.bottom} {m.left}"


DEFAULT_HEADER = {"left": "{{ product.name }} — {{ title }}", "center": "{{ classification }}", "right": ""}
DEFAULT_FOOTER = {"left": "{{ footer }}", "center": "", "right": "Page {page} of {pages}"}


class Slots(Strict):
    """Running header or footer: three slots of text with placeholders.

    Placeholders: {{ product.name }}, {{ title }}, {{ subtitle }}, {{ organisation }},
    {{ classification }}, {{ footer }}, {{ document.id }}, {{ document.version }},
    {{ report_date }}; and {page} / {pages} for page numbers.
    """

    left: str | None = None
    center: str | None = None
    right: str | None = None


class Cover(Strict):
    layout: Literal["band", "plain", "image"] = Field(
        "band",
        description="band: coloured band at the top; plain: white page; image: full-page background image.",
    )
    band_height: Length = "70mm"
    background_image: str | None = Field(None, description="Image for layout 'image' (PNG, JPEG, SVG).")
    logo_position: Literal["left", "center", "right"] = "left"
    facts: list[tuple[str, str]] | None = Field(
        None,
        description="Label/value pairs listed on the cover; values may use placeholders. "
        "Defaults to product, lifecycle, owner, reviewer, report date, data pulled, source.",
    )
    show_generated_by: bool = True


class Watermark(Strict):
    text: str = Field(min_length=1, max_length=40)
    color: HexColor = "#9ca3af"
    opacity: float = Field(0.12, ge=0.02, le=0.6)


class ThemeBranding(Strict):
    organisation: str | None = None
    logo: str | None = None
    classification: str | None = None
    footer: str | None = None


# Built-in wording. A theme's ``labels`` replaces any of these (and may add
# ``status.<value>`` for other status words). Longer explanatory sentences are not
# labels; change those with a template override.
DEFAULT_LABELS: dict[str, str] = {
    # section titles
    "section.toc": "Contents",
    "section.executive_summary": "Executive summary",
    "section.product_info": "Product information",
    "section.diagram": "Data flow diagrams",
    "section.risk_matrix": "Risk matrix",
    "section.risk_scale": "Risk scale",
    "section.threat_table": "Threats",
    "section.mitigation_table": "Mitigations",
    "section.accepted_risks": "Accepted risks",
    "section.validation_findings": "Validation findings",
    "section.appendix_catalog": "Appendix: threat and mitigation catalogue",
    "section.document_control": "Document control",
    # table columns
    "column.ref": "Ref",
    "column.threat": "Threat",
    "column.mitigation": "Mitigation",
    "column.category": "Category",
    "column.element": "Element",
    "column.diagram": "Diagram",
    "column.framework": "Framework",
    "column.likelihood": "L",
    "column.impact": "I",
    "column.score": "Score",
    "column.severity": "Severity",
    "column.residual": "Residual",
    "column.status": "Status",
    "column.mitigations": "Mitigations",
    "column.addresses": "Addresses",
    "column.description": "Description",
    "column.comments": "Comments",
    "column.type": "Type",
    "column.threats": "Threats",
    "column.level": "Level",
    "column.meaning": "Meaning",
    "column.rule": "Rule",
    "column.subject": "Subject",
    "column.finding": "Finding",
    "column.version": "Version",
    "column.date": "Date",
    "column.author": "Author",
    "column.changes": "Changes",
    "column.role": "Role",
    "column.name": "Name",
    "column.signature": "Signature",
    # field names (cover, product information, accepted risks, document control)
    "field.product": "Product",
    "field.report_date": "Report date",
    "field.data_pulled": "Data pulled",
    "field.source": "Source",
    "field.diagrams_in_scope": "Diagrams in scope",
    "field.frameworks_applied": "Frameworks applied",
    "field.justification": "Justification",
    "field.approver": "Approver",
    "field.accepted": "Accepted",
    "field.review_due": "Review due",
    "field.review_status": "Review status",
    "field.residual_risk": "Residual risk",
    "field.classification": "Classification",
    "field.document_id": "Document ID",
    "field.version": "Version",
    "field.document_status": "Status",
    "field.document_owner": "Owner",
    "product.name": "Name",
    "product.description": "Description",
    "product.status": "Lifecycle stage",
    "product.business_area": "Business area",
    "product.owner_name": "Owner",
    "product.owner_email": "Owner email",
    "product.reviewer": "Reviewer",
    "product.contributors": "Contributors",
    "product.repository_url": "Repository",
    "product.confluence_url": "Documentation",
    "product.application_url": "Application URL",
    "product.jira_project_key": "Jira project",
    # headings inside sections
    "heading.threats_by_severity": "Threats by severity",
    "heading.threat_status": "Threat status",
    "heading.mitigation_status": "Mitigation status",
    "heading.top_open_risks": "Top open risks",
    "heading.validation": "Validation",
    "heading.elements_and_threats": "Elements and threats",
    "heading.threats": "Threats",
    "heading.mitigations": "Mitigations",
    "heading.severity_bands": "Severity bands",
    "heading.inherent_risk": "Inherent risk",
    "heading.residual_risk": "Residual risk",
    "heading.revision_history": "Revision history",
    "heading.approvals": "Approvals",
    "axis.likelihood": "Likelihood",
    "axis.impact": "Impact",
    # severity and status words
    "severity.critical": "critical",
    "severity.high": "high",
    "severity.medium": "medium",
    "severity.low": "low",
    "severity.unscored": "unscored",
    "status.identified": "identified",
    "status.accepted": "accepted",
    "status.mitigated": "mitigated",
    "status.proposed": "proposed",
    "status.implemented": "implemented",
    "status.verified": "verified",
    "status.pending": "pending",
    "status.approved": "approved",
    "status.rejected": "rejected",
    # short phrases
    "text.none": "none",
    "text.open": "open",
    "text.overdue": "overdue",
    "text.custom": "custom",
    "text.element_level": "element-level",
    "text.threat_models": "Threat models",
    "text.no_open_threats": "No open threats.",
    "text.generated_by": "Generated by",
    "text.validation_failed_banner": "VALIDATION FAILED",
}


def _check_label_key(key: str) -> None:
    if key in DEFAULT_LABELS or re.fullmatch(r"status\.[a-z_]{1,40}", key):
        return
    raise ValueError(f"unknown label {key!r} (see 'tae report labels' for the list)")


class Theme(Strict):
    kind: Literal["report-theme"] = "report-theme"
    name: str | None = None
    branding: ThemeBranding = Field(default_factory=ThemeBranding)
    fonts: Fonts = Field(default_factory=Fonts)
    colors: Colors = Field(default_factory=Colors)
    page: Page = Field(default_factory=Page)
    header: Slots = Field(default_factory=Slots)
    footer: Slots = Field(default_factory=Slots)
    cover: Cover = Field(default_factory=Cover)
    numbering: bool = Field(True, description="Number sections (1, 2, 3...) in headings and contents.")
    watermark: Watermark | None = None
    labels: dict[str, str] = Field(
        default_factory=dict,
        description="Replace built-in wording: section titles, column names, severity and status words.",
    )
    extra_css: str | None = Field(None, description="Extra stylesheet appended after the built-in one.")

    _base_dir: Path = PrivateAttr(default_factory=Path.cwd)

    @field_validator("labels")
    @classmethod
    def _labels(cls, v: dict[str, str]) -> dict[str, str]:
        for key, value in v.items():
            _check_label_key(key)
            if not isinstance(value, str) or len(value) > 200:
                raise ValueError(f"label {key!r} must be text of at most 200 characters")
        return v

    def label(self, key: str, default: str | None = None) -> str:
        if key in self.labels:
            return self.labels[key]
        if key in DEFAULT_LABELS:
            return DEFAULT_LABELS[key]
        return default if default is not None else key.split(".", 1)[-1].replace("_", " ")

    @property
    def base_dir(self) -> Path:
        return self._base_dir

    def resolve(self, relative: str) -> Path:
        path = Path(relative).expanduser()
        return path if path.is_absolute() else self._base_dir / path

    @classmethod
    def load(cls, path: Path) -> Theme:
        try:
            raw = yaml.safe_load(path.read_text(encoding="utf-8"))
        except (OSError, yaml.YAMLError) as exc:
            raise ThemeError(f"Cannot read theme {path}: {exc}") from exc
        return cls.from_data(raw, path.resolve().parent, str(path))

    @classmethod
    def from_data(cls, raw: Any, base_dir: Path, source: str = "theme") -> Theme:
        if not isinstance(raw, dict):
            raise ThemeError(f"{source}: expected a mapping at the top level")
        try:
            theme = cls.model_validate(raw)
        except ValidationError as exc:
            raise ThemeError(f"{source}: {exc}") from exc
        theme._base_dir = base_dir
        return theme


# ── assets ──────────────────────────────────────────────────────────────────────


def load_font(path: Path) -> tuple[bytes, str]:
    """Read a font file, refusing anything that isn't really a font."""
    if not path.is_file():
        raise ThemeError(f"Font not found: {path}")
    if path.stat().st_size > FONT_MAX_BYTES:
        raise ThemeError(f"Font is larger than {FONT_MAX_BYTES // (1024 * 1024)} MB: {path}")
    data = path.read_bytes()
    for signature, mime in _FONT_SIGNATURES:
        if data.startswith(signature):
            return data, mime
    raise ThemeError(f"Not a TTF, OTF, WOFF or WOFF2 font: {path}")


def data_uri(data: bytes, mime: str) -> str:
    return f"data:{mime};base64,{base64.b64encode(data).decode()}"


# ── colour helpers ─────────────────────────────────────────────────────────────


def _rgb(hex_color: str) -> tuple[int, int, int]:
    h = hex_color.lstrip("#")
    if len(h) == 3:
        h = "".join(c * 2 for c in h)
    return int(h[0:2], 16), int(h[2:4], 16), int(h[4:6], 16)


def readable_text(background: str) -> str:
    """Black or white, whichever reads better on ``background`` (WCAG luminance)."""

    def channel(c: int) -> float:
        x = c / 255
        return x / 12.92 if x <= 0.03928 else ((x + 0.055) / 1.055) ** 2.4

    r, g, b = (channel(c) for c in _rgb(background))
    luminance = 0.2126 * r + 0.7152 * g + 0.0722 * b
    return "#111827" if luminance > 0.4 else "#ffffff"


def tint(hex_color: str, amount: float = 0.6) -> str:
    """Mix a colour with white (for risk-matrix cells)."""
    r, g, b = (round(c + (255 - c) * amount) for c in _rgb(hex_color))
    return f"#{r:02x}{g:02x}{b:02x}"


# ── CSS generation ──────────────────────────────────────────────────────────────


def css_string(value: str) -> str:
    """Quote a value for use as a CSS string literal (also safe inside a <style> element)."""
    cleaned = re.sub(r"[\x00-\x1f\x7f]", " ", value)
    escaped = cleaned.replace("\\", "\\\\").replace('"', '\\"').replace("<", "\\3C ").replace(">", "\\3E ")
    return f'"{escaped}"'


def css_content(text: str) -> str:
    """A margin-box ``content`` value: literal text with {page}/{pages} as counters."""
    if not text.strip():
        return "none"
    parts: list[str] = []
    for piece in re.split(r"(\{pages?\})", text):
        if piece == "{page}":
            parts.append("counter(page)")
        elif piece == "{pages}":
            parts.append("counter(pages)")
        elif piece:
            parts.append(css_string(piece))
    return " ".join(parts)


def _font_stack(font: Font, fallback: str) -> str:
    return f'"{font.family}", {fallback}'


def font_faces(theme: Theme) -> list[str]:
    faces: list[str] = []
    seen: set[tuple[str, str]] = set()
    for font in (theme.fonts.body, theme.fonts.headings):
        if font is None or font.files is None:
            continue
        for variant, weight, style in (
            ("regular", "normal", "normal"),
            ("bold", "bold", "normal"),
            ("italic", "normal", "italic"),
            ("bold_italic", "bold", "italic"),
        ):
            rel = getattr(font.files, variant)
            if rel is None or (font.family, variant) in seen:
                continue
            seen.add((font.family, variant))
            data, mime = load_font(theme.resolve(rel))
            faces.append(
                f'@font-face {{ font-family: "{font.family}"; src: url({data_uri(data, mime)}); '
                f"font-weight: {weight}; font-style: {style}; }}"
            )
    return faces


def theme_css(theme: Theme, primary: str, accent: str, slots: dict[str, str], banner: bool) -> str:
    """The CSS for a theme. ``slots`` holds the rendered header/footer texts by position."""
    c = theme.colors
    sev = c.severity
    matrix = c.matrix or SeverityColors(
        **{k: tint(getattr(sev, k)) for k in ("critical", "high", "medium", "low")}
    )
    heading_font = theme.fonts.headings or theme.fonts.body
    fallback = '"DejaVu Sans", "Liberation Sans", Arial, sans-serif'
    variables = {
        "--primary": primary,
        "--accent": accent,
        "--text": c.text,
        "--text-2": c.secondary_text,
        "--muted": c.muted,
        "--heading": c.headings or primary,
        "--th-bg": c.table_header or primary,
        "--th-text": c.table_header_text,
        "--stripe": c.table_stripe,
        "--border": c.border,
        "--cover-band": c.cover_band or primary,
        "--cover-text": c.cover_text,
        "--classification": c.classification,
        "--font-body": _font_stack(theme.fonts.body, fallback),
        "--font-heading": _font_stack(heading_font, fallback),
        "--font-size": f"{theme.fonts.size}pt",
        "--cover-band-height": theme.cover.band_height,
    }
    for level in ("critical", "high", "medium", "low"):
        variables[f"--sev-{level}"] = getattr(sev, level)
        variables[f"--sev-{level}-text"] = readable_text(getattr(sev, level))
        variables[f"--mx-{level}"] = getattr(matrix, level)

    def boxes(names: tuple[str, ...]) -> str:
        out = []
        for name in names:
            color = c.classification if name == "top-center" else c.muted
            weight = "bold" if name == "top-center" else "normal"
            content = css_content(slots.get(name, ""))
            if banner and name == "top-right":
                content, color, weight = (
                    css_string(theme.label("text.validation_failed_banner")),
                    "#b91c1c",
                    "bold",
                )
            out.append(
                f"@{name} {{ content: {content}; color: {color}; font-weight: {weight}; font-size: 8pt; }}"
            )
        return " ".join(out)

    margin_boxes = boxes(
        ("top-left", "top-center", "top-right", "bottom-left", "bottom-center", "bottom-right")
    )
    width_mm, height_mm = theme.page.size_mm
    lines = [
        *font_faces(theme),
        ":root { " + " ".join(f"{k}: {v};" for k, v in variables.items()) + " }",
        f"@page {{ size: {theme.page.css_size()}; margin: {theme.page.css_margins()}; {margin_boxes} }}",
        f"@page landscape {{ size: {theme.page.css_size(landscape=True)}; {margin_boxes} }}",
        f"@page cover {{ size: {theme.page.css_size()}; }}",
        f".section-cover {{ height: {height_mm:.1f}mm; width: {width_mm:.1f}mm; }}",
    ]
    if theme.watermark is not None:
        w = theme.watermark
        lines.append(f".watermark {{ color: {w.color}; opacity: {w.opacity}; }}")
    return "\n".join(lines)
