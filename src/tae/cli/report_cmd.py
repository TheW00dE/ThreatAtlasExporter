"""``tae report``: build PDF reports and manage report definitions."""

from __future__ import annotations

import json
from datetime import date
from importlib import resources
from pathlib import Path

import typer

from tae.cli.common import ExitCode, console, err_console, fail, get_state
from tae.cli.inputs import obtain_snapshot
from tae.cli.pull import slugify
from tae.report.definition import OnFailure, ReportDefinition, json_schema
from tae.report.pdf import PdfEngine, write_pdf
from tae.report.render import ReportBlocked, build_report
from tae.validate.output import render_table, summary_line

app = typer.Typer(help="Build PDF reports from snapshots.", no_args_is_help=True)

EXAMPLE = resources.files("tae.report") / "example-definition.yaml"


@app.command("build")
def build(
    ctx: typer.Context,
    snapshot: Path | None = typer.Argument(None, help="Snapshot file from `tae pull`.", show_default=False),
    product: str | None = typer.Option(None, "--product", "-P", help="Pull this product live instead."),
    definition: Path | None = typer.Option(
        None, "--definition", "-d", help="Report definition (YAML). [default: built-in full report]"
    ),
    output_file: Path | None = typer.Option(
        None, "--output-file", "-f", help="PDF to write. [default: <product>-threat-model-<date>.pdf]"
    ),
    html: Path | None = typer.Option(
        None, "--html", help="Also write the intermediate HTML (for template work)."
    ),
    rules: Path | None = typer.Option(
        None, "--rules", "-r", help="Validation config; overrides the definition's."
    ),
    on_failure: OnFailure | None = typer.Option(
        None, "--on-failure", help="What to do if validation fails; overrides the definition."
    ),
    findings_file: Path | None = typer.Option(
        None, "--findings-file", help="Also write validation findings (JSON)."
    ),
    as_of: str | None = typer.Option(None, "--as-of", help="Report date (YYYY-MM-DD). [default: today]"),
    pdf_engine: PdfEngine = typer.Option(
        PdfEngine.auto,
        "--pdf-engine",
        help="weasyprint, browser (Edge/Chrome headless), or auto: WeasyPrint if its libraries load, "
        "else a browser. [env: TAE_BROWSER sets the browser]",
    ),
) -> None:
    """Validate a product's threat model and render it as a PDF report.

    Exit codes: 0 report written; 10 validation failed and on_failure is `annotate`
    (PDF written with a warning banner) or `block` (no PDF); 3 bad input.
    """
    state = get_state(ctx)
    report_def = ReportDefinition.load(definition) if definition else ReportDefinition()
    snap = obtain_snapshot(state, snapshot, product)
    day = _parse_date(as_of) or date.today()

    try:
        out = build_report(snap, report_def, as_of=day, on_failure=on_failure, rules=rules)
    except ReportBlocked as blocked:
        render_table(err_console, blocked.result, report_def.validation.fail_level)
        if findings_file:
            findings_file.write_text(
                json.dumps(blocked.result.to_dict(report_def.validation.fail_level), indent=2)
            )
        fail("Validation failed, so no report was written (on_failure: block).", ExitCode.CHECKS_FAILED)

    if findings_file:
        findings_file.write_text(
            json.dumps(out.validation.to_dict(report_def.validation.fail_level), indent=2, ensure_ascii=False)
            + "\n",
            encoding="utf-8",
        )
    if html:
        html.write_text(out.html, encoding="utf-8")
    path = output_file or Path(f"{slugify(snap.product.name)}-threat-model-{day.isoformat()}.pdf")
    write_pdf(out, path, pdf_engine)

    err_console.print(
        summary_line(out.validation, report_def.validation.fail_level), markup=False, highlight=False
    )
    console.print(f"Wrote {path}", markup=False, highlight=False)
    if out.exit_with_failure:
        raise typer.Exit(int(ExitCode.CHECKS_FAILED))


def _parse_date(value: str | None) -> date | None:
    if value is None:
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        raise typer.BadParameter(
            f"{value!r} is not a date in YYYY-MM-DD form", param_hint="--as-of"
        ) from None


@app.command("init")
def init(
    path: Path = typer.Argument(Path("report.yaml"), help="Where to write the definition."),
    force: bool = typer.Option(False, "--force", help="Overwrite an existing file."),
) -> None:
    """Write a commented example report definition to start from."""
    if path.exists() and not force:
        fail(f"{path} already exists. Use --force to overwrite it.", ExitCode.USAGE)
    path.write_text(EXAMPLE.read_text(encoding="utf-8"), encoding="utf-8")
    console.print(f"Wrote {path}. Build with: tae report build SNAPSHOT --definition {path}", markup=False)


@app.command("schema")
def schema(
    output_file: Path | None = typer.Option(None, "--output-file", "-f", help="Write to this file."),
) -> None:
    """Print the JSON Schema for report definitions (for editor autocompletion)."""
    text = json.dumps(json_schema(), indent=2)
    if output_file:
        output_file.write_text(text + "\n", encoding="utf-8")
        console.print(f"Wrote {output_file}", markup=False)
    else:
        console.file.write(text + "\n")


@app.command("check")
def check(definition: Path = typer.Argument(..., help="Report definition to check.")) -> None:
    """Check a report definition for errors without building a report."""
    d = ReportDefinition.load(definition)
    types = ", ".join(s.type for s in d.sections)
    console.print(f"{definition} is valid: {len(d.sections)} sections ({types}).", markup=False)
