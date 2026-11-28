"""Report runs for the desktop app: presets, local storage, and background generation.

Every run gets its own folder, which is kept:

    <reports dir>/<product id>-<product slug>/<UTC timestamp>-<run id>/
        report.pdf       (absent when validation blocked the report or the run failed)
        snapshot.json    the data the report was built from
        findings.json    validation findings
        run.json         who, when, which report type, outcome
"""

from __future__ import annotations

import json
import logging
import re
import secrets
import threading
import time
from collections.abc import Callable
from dataclasses import asdict, dataclass, field
from datetime import UTC, date, datetime
from importlib import resources
from pathlib import Path
from typing import Any, TypeVar

from tae import __version__
from tae.cli.pull import slugify
from tae.client import ThreatAtlasClient
from tae.models.api import Product
from tae.report.definition import ReportDefinition
from tae.report.pdf import PdfEngine, write_pdf
from tae.report.render import ReportBlocked, build_report
from tae.snapshot.collector import collect

log = logging.getLogger(__name__)

PRESETS_DIR = resources.files("tae.desktop") / "presets"
RUN_ID = re.compile(r"^\d{8}T\d{6}Z-[0-9a-f]{8}$")
PRODUCT_DIR = re.compile(r"^(\d+)-[a-z0-9-]+$")
DOWNLOADABLE = {
    "report.pdf": "application/pdf",
    "snapshot.json": "application/json",
    "findings.json": "application/json",
}


# ── presets ─────────────────────────────────────────────────────────────────────


@dataclass(frozen=True)
class Preset:
    id: str
    label: str
    description: str
    path: Path


BUILTIN_PRESETS = (
    (
        "full-technical",
        "Full technical report",
        "Everything: summary, diagrams, all threats and mitigations, findings.",
    ),
    (
        "executive-summary",
        "Executive summary",
        "Short: summary, risk matrix, diagrams, high and critical threats.",
    ),
    (
        "audit-acceptance",
        "Risk acceptance review",
        "Accepted risks and their approvals. Not produced if validation fails.",
    ),
)


def load_presets(extra_dir: Path | None = None) -> list[Preset]:
    """Built-in report types, plus any ``*.yaml`` definitions in ``extra_dir``."""
    base = Path(str(PRESETS_DIR))
    presets = [Preset(pid, label, desc, base / f"{pid}.yaml") for pid, label, desc in BUILTIN_PRESETS]
    if extra_dir is not None and extra_dir.is_dir():
        for path in sorted(extra_dir.glob("*.yaml")):
            pid = "custom-" + slugify(path.stem)
            presets.append(Preset(pid, f"{path.stem} (custom)", f"From {path}", path))
    return presets


# ── storage ─────────────────────────────────────────────────────────────────────


@dataclass
class RunRecord:
    run_id: str
    product_id: int
    product_name: str
    preset_id: str
    preset_label: str
    started_at: str
    status: str = "running"  # running | done | blocked | failed | interrupted
    message: str = "Starting"
    finished_at: str | None = None
    user: str | None = None
    source_url: str | None = None
    engine: str | None = None
    tool_version: str = __version__
    snapshot_hash: str | None = None
    validation: dict[str, Any] = field(default_factory=dict)
    files: list[str] = field(default_factory=list)

    @property
    def finished(self) -> bool:
        return self.status != "running"

    @property
    def started(self) -> datetime:
        return datetime.fromisoformat(self.started_at)


class ReportStore:
    def __init__(self, root: Path) -> None:
        self.root = root

    def product_dir(self, product_id: int, product_name: str) -> Path:
        existing = self._find_product_dir(product_id)
        return existing or self.root / f"{product_id}-{slugify(product_name)}"

    def _find_product_dir(self, product_id: int) -> Path | None:
        if not self.root.is_dir():
            return None
        for d in self.root.iterdir():
            m = PRODUCT_DIR.match(d.name)
            if d.is_dir() and m and int(m.group(1)) == product_id:
                return d
        return None

    def run_dir(self, product_id: int, run_id: str) -> Path | None:
        if not RUN_ID.match(run_id):
            return None
        pdir = self._find_product_dir(product_id)
        if pdir is None:
            return None
        d = pdir / run_id
        return d if d.is_dir() else None

    def save(self, run_dir: Path, record: RunRecord) -> None:
        tmp = run_dir / f"run.json.{threading.get_ident()}.tmp"
        tmp.write_text(json.dumps(asdict(record), indent=2), encoding="utf-8")
        # On Windows, replacing a file fails while another thread has it open (the run
        # page reads run.json every few seconds), so retry briefly.
        _retry(lambda: tmp.replace(run_dir / "run.json"))

    def load(self, run_dir: Path) -> RunRecord | None:
        try:
            text = _retry(lambda: (run_dir / "run.json").read_text(encoding="utf-8"))
            return RunRecord(**json.loads(text))
        except (OSError, ValueError, TypeError):
            return None

    def runs(self, product_id: int) -> list[RunRecord]:
        pdir = self._find_product_dir(product_id)
        if pdir is None:
            return []
        records = [r for d in pdir.iterdir() if d.is_dir() and RUN_ID.match(d.name) and (r := self.load(d))]
        return sorted(records, key=lambda r: r.run_id, reverse=True)

    def counts(self) -> dict[int, int]:
        """Number of stored runs per product."""
        result: dict[int, int] = {}
        if self.root.is_dir():
            for d in self.root.iterdir():
                m = PRODUCT_DIR.match(d.name)
                if d.is_dir() and m:
                    result[int(m.group(1))] = sum(1 for r in d.iterdir() if RUN_ID.match(r.name))
        return result

    def file(self, product_id: int, run_id: str, name: str) -> Path | None:
        """Path of a downloadable file, or None. Only known file names are ever served."""
        if name not in DOWNLOADABLE:
            return None
        d = self.run_dir(product_id, run_id)
        if d is None:
            return None
        path = d / name
        return path if path.is_file() else None

    def mark_interrupted(self) -> int:
        """Runs left 'running' by a previous session can never finish."""
        n = 0
        if not self.root.is_dir():
            return 0
        for pdir in self.root.iterdir():
            if not (pdir.is_dir() and PRODUCT_DIR.match(pdir.name)):
                continue
            for d in pdir.iterdir():
                record = self.load(d) if d.is_dir() else None
                if record and record.status == "running":
                    record.status = "interrupted"
                    record.message = "The app was closed before this report finished."
                    self.save(d, record)
                    n += 1
        return n


T = TypeVar("T")


def _retry(action: Callable[[], T], attempts: int = 10, delay: float = 0.05) -> T:
    """Run ``action``, retrying on PermissionError (Windows sharing violations)."""
    for attempt in range(attempts):
        try:
            return action()
        except PermissionError:
            if attempt == attempts - 1:
                raise
            time.sleep(delay)
    raise AssertionError("unreachable")  # pragma: no cover


# ── generation ──────────────────────────────────────────────────────────────────


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


class RunManager:
    """Runs report generation in background threads; one run per product at a time."""

    def __init__(self, store: ReportStore, engine: PdfEngine) -> None:
        self.store = store
        self.engine = engine
        self._lock = threading.Lock()
        self._active: dict[int, str] = {}  # product id → run id
        self._threads: list[threading.Thread] = []

    def active_run(self, product_id: int) -> str | None:
        with self._lock:
            return self._active.get(product_id)

    def start(
        self,
        product: Product,
        preset: Preset,
        client_factory: Callable[[], ThreatAtlasClient],
        user: str | None,
        source_url: str,
    ) -> tuple[str, bool]:
        """Start a run. Returns (run id, started); if one is already running, returns it."""
        with self._lock:
            if product.id in self._active:
                return self._active[product.id], False
            run_id = f"{datetime.now(UTC).strftime('%Y%m%dT%H%M%SZ')}-{secrets.token_hex(4)}"
            run_dir = self.store.product_dir(product.id, product.name) / run_id
            run_dir.mkdir(parents=True)
            record = RunRecord(
                run_id=run_id,
                product_id=product.id,
                product_name=product.name,
                preset_id=preset.id,
                preset_label=preset.label,
                started_at=_now(),
                user=user,
                source_url=source_url,
            )
            self.store.save(run_dir, record)
            self._active[product.id] = run_id
        thread = threading.Thread(
            target=self._run,
            args=(run_dir, record, product, preset, client_factory),
            daemon=True,
            name=f"run-{run_id}",
        )
        self._threads.append(thread)
        thread.start()
        return run_id, True

    def wait(self, timeout: float = 60) -> None:
        """For tests: wait until all runs have finished."""
        for t in list(self._threads):
            t.join(timeout)

    def _run(
        self,
        run_dir: Path,
        record: RunRecord,
        product: Product,
        preset: Preset,
        client_factory: Callable[[], ThreatAtlasClient],
    ) -> None:
        def step(message: str) -> None:
            record.message = message
            try:
                self.store.save(run_dir, record)
            except OSError:  # a progress update isn't worth failing the report for
                log.warning("Could not save progress for run %s", record.run_id, exc_info=True)

        try:
            definition = ReportDefinition.load(preset.path)
            step("Pulling data from ThreatAtlas")
            with client_factory() as client:
                snapshot = collect(client, product, lambda msg: step(msg))
            snapshot.save(run_dir / "snapshot.json")
            record.snapshot_hash = snapshot.content_hash()
            record.files.append("snapshot.json")

            step("Validating")
            fail_level = definition.validation.fail_level
            try:
                out = build_report(snapshot, definition, as_of=date.today())
            except ReportBlocked as blocked:
                self._write_findings(run_dir, record, blocked.result.to_dict(fail_level))
                record.status = "blocked"
                record.message = "Validation failed, and this report type is not produced when it does."
                return
            self._write_findings(run_dir, record, out.validation.to_dict(fail_level))

            step("Rendering the PDF")
            used = write_pdf(out, run_dir / "report.pdf", self.engine)
            record.engine = used.value
            record.files.append("report.pdf")
            record.status = "done"
            record.message = (
                "Report ready. Validation failed: see the findings in the report."
                if out.validation_failed
                else "Report ready."
            )
        except Exception as exc:  # report any failure on the run page
            log.exception("Run %s failed", record.run_id)
            record.status = "failed"
            record.message = str(exc).splitlines()[0][:500] if str(exc) else exc.__class__.__name__
        finally:
            record.finished_at = _now()
            try:
                self.store.save(run_dir, record)
            except OSError:
                log.exception("Could not save the outcome of run %s", record.run_id)
            finally:
                # Always release the product, or it would stay "being generated" forever.
                with self._lock:
                    self._active.pop(product.id, None)

    def _write_findings(self, run_dir: Path, record: RunRecord, data: dict[str, Any]) -> None:
        (run_dir / "findings.json").write_text(
            json.dumps(data, indent=2, ensure_ascii=False), encoding="utf-8"
        )
        record.files.append("findings.json")
        record.validation = {"passed": data.get("passed"), **data.get("counts", {})}
