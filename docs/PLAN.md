# ThreatAtlasExporter — Structure & Implementation Plan

Status: **draft for review**. Open questions are collected in §9.

## 1. Goal

A command-line tool (`tae`) that:

1. **Pulls** data from an OWASP ThreatAtlas instance over its REST API.
2. **Validates** it against built-in and user-defined rules.
3. **Renders** a structured PDF report driven by a declarative report definition (which sections, which filters, ordering, branding).
4. Later: **creates and updates** products, diagrams, threat models, threats and mitigations.

## 2. What ThreatAtlas exposes (from the upstream source, v0.9.x)

Researched from `github.com/OWASP/www-project-threatatlas` (`threatatlas-app/backend`).

- **Stack:** FastAPI + Pydantic + SQLAlchemy. OpenAPI spec at `GET /openapi.json` (docs UI at `/docs` via Scalar).
- **Auth:** `Authorization: Bearer <token>`. Either a long-lived personal token (`ta_…`, created in *Settings → Integrations → API Tokens*) or a session JWT. Expired `ta_` tokens return 401. RBAC applies per user (admin / standard / read_only) and per product (owner / editor / viewer).
- **REST base:** `/api`. Relevant resources:

| Resource | Endpoints | Key fields |
|---|---|---|
| Product | `GET/POST /products`, `GET/PUT/DELETE /products/{id}`, `POST /products/{id}/duplicate` | name, description, status (design…production), is_public, owner_name/email, business_area, reviewer, contributors, repository/confluence/application URLs, jira_project_key, can_edit |
| Diagram | `GET /diagrams?product_id=`, `GET/POST/PUT/DELETE /diagrams/{id}` | name, description, product_id, `diagram_data` (ReactFlow `nodes`/`edges`; node `data.type` ∈ process, datastore, external, boundary), current_version |
| Diagram versions | `/diagram-versions/{diagram_id}/versions[...]`, compare, restore | |
| Framework | `GET/POST/PUT/DELETE /frameworks` | name (STRIDE, LINDDUN, OWASP…), is_custom |
| Model (threat model) | `GET/POST /models`, `GET /models/diagram/{diagram_id}`, `PUT/DELETE /models/{id}` | diagram_id, framework_id, name, status (in_progress / completed / archived), completed_at, threat_count, mitigation_count |
| Threat (catalog) | `GET/POST /threats`, `PUT/DELETE /threats/{id}`, `POST /threats/{id}/revert` | name, description, category, framework_id, is_custom, is_modified |
| Mitigation (catalog) | same shape under `/mitigations` | |
| Diagram threat (instance) | `GET/POST /diagram-threats`, `GET/PUT/DELETE /diagram-threats/{id}` | element_id, element_type, model_id, threat_id, status (identified / mitigated / accepted), likelihood & impact (1–5), risk_score, severity, residual_* fields, acceptance_* fields (justification, approver, review date, review status) |
| Diagram mitigation (instance) | `GET/POST /diagram-mitigations`, `PUT/DELETE /diagram-mitigations/{id}` | element_id, element_type, model_id, mitigation_id, threat_id (optional link), status (proposed / implemented / verified) |
| Exports (built in) | `/products/{id}/download/{diagrams,threats-mitigations,report,report.md,report.docx,bundle}`, `/products/{id}/security-status` | |

- **Risk model:** `risk_score = likelihood × impact`; severity bands: ≥20 critical, ≥12 high, ≥6 medium, else low. Residual risk is assessed separately, not derived.
- **Pagination:** list endpoints take `skip` / `limit` (default 100). The client must page through results.
- ThreatAtlas also ships an MCP server at `/mcp/`. That is not needed here; the REST API covers everything.

The built-in exports produce fixed HTML/MD/DOCX. They cannot be configured and they don't validate anything. That gap is what this tool fills.

## 3. Technology choices (recommended)

| Concern | Choice | Why |
|---|---|---|
| Language | **Python ≥ 3.11** | Same ecosystem as ThreatAtlas; Pydantic models map directly onto its schemas |
| CLI | **Typer** (+ Rich for tables and progress) | Typed subcommands, auto help, shell completion |
| HTTP | **httpx** | Sync and async, timeouts, retries via transport, easy to mock (`respx`) |
| Models | **Pydantic v2** | Parse and validate API payloads; can be generated from `/openapi.json` with `datamodel-code-generator`, then hand-curated |
| Config | TOML/YAML + env vars, **pydantic-settings** | Profiles per instance |
| Secrets | **keyring** (fallback: env `TAE_TOKEN`) | Keeps tokens out of config files |
| Report definition | **YAML**, checked by a Pydantic schema (JSON Schema exported for editor autocomplete) | Declarative and easy to review |
| PDF | **Jinja2 HTML/CSS templates → WeasyPrint** | Full layout control (cover, TOC, headers/footers, page numbers, branding) using CSS paged media. Charts as inline SVG |
| Diagrams in PDF | Render ReactFlow `nodes`/`edges` to **SVG** ourselves (boxes, cylinders, trust boundaries, labelled edges, threat-count badges) | No browser needed |
| Packaging | `pyproject.toml` (hatch or uv), `pipx install`, optional Docker image | WeasyPrint needs Pango; Docker avoids host setup |
| Quality | pytest, respx, ruff, mypy, pre-commit, GitHub Actions | |

Alternative if WeasyPrint's system dependencies are a problem: ReportLab (pure Python, more code per layout). See Q5.

## 4. Repository layout

```
ThreatAtlasExporter/
├── pyproject.toml
├── README.md
├── docs/
│   ├── PLAN.md
│   ├── report-definition.md        # reference for the YAML format
│   └── validation-rules.md
├── examples/
│   ├── tae.toml                    # sample config with profiles
│   ├── reports/
│   │   ├── executive-summary.yaml
│   │   ├── full-technical.yaml
│   │   └── audit-acceptance.yaml
│   └── rules/custom-rules.yaml
├── src/tae/
│   ├── __init__.py
│   ├── __main__.py                 # python -m tae
│   ├── cli/
│   │   ├── app.py                  # root Typer app, global options (--profile, --output, -v)
│   │   ├── auth.py                 # tae auth login|status|logout
│   │   ├── pull.py                 # tae pull
│   │   ├── validate.py             # tae validate
│   │   ├── report.py               # tae report build|init|schema|preview
│   │   └── resources/              # phase 2: CRUD command groups
│   │       ├── products.py
│   │       ├── diagrams.py
│   │       ├── models.py
│   │       ├── threats.py
│   │       ├── mitigations.py
│   │       └── apply.py            # declarative apply from YAML
│   ├── config.py                   # profiles, settings, keyring lookup
│   ├── client/
│   │   ├── http.py                 # base client: auth, retries, pagination, errors
│   │   ├── errors.py               # typed API errors (401/403/404/422)
│   │   └── endpoints/              # one module per resource, read and write methods
│   ├── models/
│   │   ├── api.py                  # Pydantic mirrors of ThreatAtlas schemas
│   │   └── snapshot.py             # normalized, linked object graph (see §5)
│   ├── pull/
│   │   ├── collector.py            # walks product → diagrams → models → threats/mitigations
│   │   └── store.py                # snapshot JSON read/write
│   ├── validate/
│   │   ├── engine.py               # runs rules, collects findings
│   │   ├── findings.py             # Finding(rule_id, level, entity ref, message)
│   │   ├── rules/                  # built-in rules (structural, integrity, completeness, governance)
│   │   └── custom.py               # YAML-defined rules (filter expression + condition)
│   ├── report/
│   │   ├── definition.py           # Pydantic schema for the report YAML
│   │   ├── query.py                # filters, sort, group over the snapshot
│   │   ├── context.py              # builds template context per section
│   │   ├── charts.py               # SVG charts (severity bars, risk heatmap)
│   │   ├── diagram_svg.py          # ReactFlow → SVG
│   │   ├── render.py               # Jinja2 → HTML → WeasyPrint PDF
│   │   └── templates/
│   │       ├── base.html.j2
│   │       ├── styles/default.css
│   │       └── sections/           # cover, toc, summary, product_info, diagram,
│   │                               # threat_table, mitigation_table, risk_matrix,
│   │                               # accepted_risks, validation_findings, appendix
│   └── output.py                   # table / json / yaml output for list commands
└── tests/
    ├── fixtures/                   # recorded API payloads, sample snapshots
    ├── unit/
    └── integration/                # optional: runs against docker-compose ThreatAtlas
```

## 5. Core design

### 5.1 Pipeline

```
 ThreatAtlas API ──pull──▶ snapshot.json ──validate──▶ findings.json
                                 │                         │
                                 └──────────report─────────┴──▶ report.pdf
```

Each stage is a separate command that reads and writes files, and there is also a combined command:

- `tae pull --product 12 -o snapshot.json`
- `tae validate snapshot.json [--rules custom.yaml] [--fail-on error]`
- `tae report build snapshot.json --definition exec.yaml -o report.pdf`
- `tae export --product 12 --definition exec.yaml -o report.pdf`, which runs pull, validate and report in memory.

Because snapshots are files, reports can be reproduced, tested offline, diffed over time, and kept as audit evidence.

### 5.2 Snapshot model

A normalized, linked graph. Each diagram threat is resolved to its catalog threat, its model and framework, and its diagram element (name and type from `diagram_data`). Mitigations are attached to threats through `threat_id`, or failing that through the shared `element_id`. A metadata block records the instance URL, the ThreatAtlas version if detectable, the pull timestamp, the tool version, and a content hash.

### 5.3 Validation

Each rule has an `id`, a default `level` (error / warning / info), a scope, and a check. The level can be overridden per run in config. Built-in rule families:

| Family | Examples |
|---|---|
| Structural | Payload matches schema; enums are valid (statuses, product status, node types); likelihood and impact are within 1–5 |
| Referential integrity | `element_id` exists in the diagram's nodes/edges; model belongs to the diagram; mitigation's `threat_id` exists on the same diagram; orphaned items |
| Consistency | Stored `risk_score`/`severity` match L×I and the bands; a "mitigated" threat has at least one implemented or verified mitigation |
| Completeness | Threat has no score; diagram has no threat model; model has no threats; element has no threats; product is missing owner or reviewer; descriptions are empty |
| Governance | An accepted threat lacks justification, approver or review date; a review date has passed; high or critical threats are still open; residual risk is higher than inherent risk; a model marked completed still has open items |

Custom rules are written in YAML using a small, safe expression syntax (no `eval`):

```yaml
rules:
  - id: CUSTOM-001
    level: error
    applies_to: diagram_threat
    when:  { severity: [high, critical] }
    require: { status: [mitigated, accepted] }
    message: "High/critical threats must be mitigated or formally accepted"
```

Output formats: Rich table, JSON, JUnit XML or SARIF (for CI), and an optional report section. The exit code is non-zero when findings at or above `--fail-on` exist.

### 5.4 Report definition (the "definable criteria")

```yaml
report:
  title: "Threat Model Report — {{ product.name }}"
  template: default            # or a path to a custom template dir
  branding: { logo: ./logo.png, primary_color: "#1f3a5f", classification: "CONFIDENTIAL" }
  scope:
    products: [12]              # or by name / tag
    diagrams: all
    frameworks: [STRIDE]
    model_status: [in_progress, completed]
  filters:                      # global; sections may override
    min_severity: medium
    statuses: [identified, accepted]
  validation:
    rules: ./rules/custom.yaml
    block_on: error             # refuse to build if errors (or: warn | never)
  sections:
    - type: cover
    - type: toc
    - type: executive_summary   # counts by severity/status, open high/critical, KPIs
    - type: product_info
    - type: diagram             # rendered SVG per diagram with element legend
      per: diagram
    - type: risk_matrix         # 5×5 likelihood × impact heatmap
      residual: true
    - type: threat_table
      group_by: element         # element | severity | category | model | status
      sort: [-risk_score, name]
      columns: [element, threat, category, likelihood, impact, severity, status, mitigations]
    - type: mitigation_table
      statuses: [proposed]
    - type: accepted_risks      # justification, approver, review date
    - type: validation_findings
      min_level: warning
    - type: appendix_catalog    # full threat/mitigation descriptions
```

The tool also provides `tae report init`, which scaffolds a definition, `tae report schema`, which emits JSON Schema for IDE autocomplete, and `--html` to output the intermediate HTML for fast template iteration.

### 5.5 Phase 2: write operations

Each resource gets a command group with `list`, `get`, `create`, `update` and `delete`, plus resource-specific verbs:

```
tae products  list|get|create|update|delete|duplicate
tae diagrams  list|get|create|update|delete|export-json|import-json|versions
tae models    list|create|update|complete|archive          # threat model = framework bound to a diagram
tae threats   catalog list|create|update|revert
              list --diagram|identify|update|accept|delete # diagram-threat instances
tae mitigations catalog …
              list --diagram|apply|update|delete
tae apply -f threatmodel.yaml [--dry-run] [--prune]        # declarative, idempotent sync
```

Design rules for write operations:

- Global `--dry-run` shows the planned HTTP calls or a diff.
- `--yes` is required for deletes in non-interactive mode.
- Input comes from flags, `--from-file` (JSON/YAML), or stdin.
- Entities can be referenced by ID or by name, e.g. `--product "Payments API"`.
- `tae apply` reconciles a YAML description of product, diagrams, models, threats and mitigations against the server, matching existing entities by name or element ID. This makes threat models as code possible in Git and CI.

The phase 1 client is built with write methods from the start so phase 2 is mostly CLI wiring.

## 6. Configuration

`~/.config/tae/config.toml` (overridable by `--config` / `TAE_CONFIG`):

```toml
default_profile = "prod"

[profiles.prod]
url = "https://threatatlas.example.com"
verify_tls = true            # or path to CA bundle
timeout = 30

[profiles.local]
url = "http://localhost:8000"
```

The token is resolved in this order: `--token`, then the `TAE_TOKEN` env var, then the keyring entry stored by `tae auth login`. `tae auth status` calls `/api/auth/me` to show the user and role.

## 7. Implementation phases

| # | Milestone | Deliverables |
|---|---|---|
| 0 | Scaffold | pyproject, package layout, Typer root, ruff/mypy/pytest, CI workflow, README |
| 1 | Client & auth | Config/profiles, keyring, HTTP client with pagination, retries and typed errors, Pydantic API models (generated from `/openapi.json` then curated), `tae auth`, read-only `list/get` commands for every resource |
| 2 | Pull | Collector, snapshot model and linker, `tae pull` with scopes (product, all products, diagram), progress output, fixtures |
| 3 | Validate | Rule engine, built-in rules, YAML custom rules, output formats (table/JSON/JUnit/SARIF), `--fail-on` exit codes |
| 4 | Report MVP | Definition schema, query layer, Jinja2/WeasyPrint renderer, sections: cover, TOC, summary, product info, threat table, mitigation table, findings |
| 5 | Report advanced | Diagram SVG rendering, risk heatmap and charts, accepted-risks section, branding, custom templates, `report init/schema`, `tae export` one-shot, Docker image |
| 6 | Write ops (imperative) | create/update/delete for products, diagrams, models, catalog threats and mitigations, diagram-threat and diagram-mitigation instances, dry-run, name resolution |
| 7 | Declarative apply | `tae apply` with diff, prune, idempotency; diagram JSON import/export |

Phases 0–5 deliver the reporting goal; phases 6–7 deliver the "future" CRUD goal.

## 8. Testing strategy

- **Unit:** snapshot linking, every validation rule (one passing and one failing fixture each), query/filter/sort, risk banding, and diagram SVG rendering (golden files).
- **HTTP:** `respx`-mocked client tests built from recorded real payloads, covering pagination, 401/403/404/422 handling, and retries.
- **Report:** build PDFs from fixture snapshots, then use `pypdf` to assert page count, section headings and key strings. HTML snapshot tests for templates.
- **Integration (optional, CI job):** start ThreatAtlas from its `docker-compose.yml`, seed it, then run pull → validate → report and phase 2 CRUD round-trips.

## 9. Open questions

See the summary in the conversation. Answers will be recorded here.
