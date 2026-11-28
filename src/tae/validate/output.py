"""Render validation results: console table, JSON, JUnit XML, GitLab Code Quality."""

from __future__ import annotations

import json
from enum import StrEnum
from xml.etree import ElementTree as ET

from rich.console import Console
from rich.table import Table
from rich.text import Text

from tae.output import safe_text
from tae.validate.engine import ValidationResult
from tae.validate.findings import FailLevel, Finding, Level


class FindingsFormat(StrEnum):
    table = "table"
    json = "json"
    junit = "junit"
    codequality = "codequality"


LEVEL_STYLE = {Level.error: "bold red", Level.warning: "yellow", Level.info: "cyan"}


def summary_line(result: ValidationResult, fail_level: FailLevel) -> str:
    c = result.counts()
    verdict = "FAILED" if result.fails(fail_level) else "PASSED"
    threshold = "" if fail_level is FailLevel.never else f" (fails on {fail_level.value} or worse)"
    return (
        f"Validation {verdict}{threshold}: {c['error']} error(s), {c['warning']} warning(s), "
        f"{c['info']} info, {len(result.rules)} rules run"
    )


def render_table(console: Console, result: ValidationResult, fail_level: FailLevel) -> None:
    if result.findings:
        table = Table(header_style="bold", show_lines=False)
        table.add_column("Level")
        table.add_column("Rule")
        table.add_column("Diagram", max_width=24, overflow="fold")
        table.add_column("Subject", max_width=45, overflow="fold")
        table.add_column("Message", overflow="fold")
        for f in result.findings:
            subject = (f"{f.entity.ref} " if f.entity.ref else "") + f.entity.label
            table.add_row(
                Text(f.level.value, style=LEVEL_STYLE[f.level]),
                Text(f.rule_id),
                Text(safe_text(f.entity.diagram_name or "—")),
                Text(safe_text(subject)),
                Text(safe_text(f.message)),
            )
        console.print(table)
    style = "bold red" if result.fails(fail_level) else "bold green"
    console.print(Text(summary_line(result, fail_level), style=style))


def to_json(result: ValidationResult, fail_level: FailLevel) -> str:
    return json.dumps(result.to_dict(fail_level), indent=2, ensure_ascii=False)


def to_junit(
    result: ValidationResult, fail_level: FailLevel, suite_name: str = "threatatlas-validation"
) -> str:
    """One test case per finding, plus one passing case per rule with no findings.

    Findings at or above the fail level are failures; the rest pass with the
    finding in ``system-out`` so they're still visible.
    """
    by_rule: dict[str, list[Finding]] = {}
    for f in result.findings:
        by_rule.setdefault(f.rule_id, []).append(f)

    cases: list[ET.Element] = []
    failures = 0
    for r in result.rules:
        findings = by_rule.get(r.id, [])
        if not findings:
            cases.append(ET.Element("testcase", classname=f"{r.family}.{r.id}", name=r.title))
            continue
        for f in findings:
            case = ET.Element(
                "testcase", classname=f"{r.family}.{r.id}", name=f"{r.title}: {f.entity.describe()}"
            )
            text = f"[{f.level.value}] {f.message}\nSubject: {f.entity.describe()}"
            if fail_level.fails(f.level):
                failures += 1
                failure = ET.SubElement(case, "failure", message=f.message, type=f.level.value)
                failure.text = text
            else:
                ET.SubElement(case, "system-out").text = text
            cases.append(case)

    suite = ET.Element(
        "testsuite",
        name=suite_name,
        tests=str(len(cases)),
        failures=str(failures),
        errors="0",
        skipped="0",
        timestamp=result.as_of.isoformat(),
    )
    suite.extend(cases)
    root = ET.Element("testsuites", name=suite_name, tests=str(len(cases)), failures=str(failures))
    root.append(suite)
    ET.indent(root)
    return '<?xml version="1.0" encoding="UTF-8"?>\n' + ET.tostring(root, encoding="unicode")


CODEQUALITY_SEVERITY = {Level.error: "major", Level.warning: "minor", Level.info: "info"}


def to_codequality(result: ValidationResult, location_path: str) -> str:
    """GitLab Code Quality report (a JSON array), shown in the merge request widget."""
    issues = [
        {
            "description": f"{f.rule_id} {f.entity.describe()}: {f.message}",
            "check_name": f.rule_id,
            "fingerprint": f.fingerprint,
            "severity": CODEQUALITY_SEVERITY[f.level],
            "location": {"path": location_path, "lines": {"begin": 1}},
        }
        for f in result.findings
    ]
    return json.dumps(issues, indent=2, ensure_ascii=False)
