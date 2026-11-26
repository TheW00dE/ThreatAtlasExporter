# ThreatAtlasExporter — Structure & Implementation Plan

Status: **phases 0–4 done** (scaffold, Docker image, GitLab CI, API client, pull/snapshots, validation, PDF reports). Everything is tested against fixtures modelled on ThreatAtlas v0.9.x; testing against a live instance is next. Then phase 5 (asset folders, multi-product export, Kubernetes manifests).

Notes from implementation:
- Typer ≥ 0.29 vendors click privately, so the code never imports `click` directly.
- Tokens can also come from a file (`TAE_TOKEN_FILE`, or `token_file` in a profile), which is how a Kubernetes Secret gets mounted. A token in the config file is rejected outright.
- In the container, config is read from `/config/tae/config.toml` (`XDG_CONFIG_HOME=/config`).
- A diagram mitigation's `threat_id` refers to the *diagram threat* (`diagram_threats.id`), not the catalog threat.
- Phase 2 (pull) was built ahead of phases 3–4 because both depend on the snapshot. Its fixtures should be re-recorded from a real instance.
- Validation exits with code 10 when checks fail, so CI can tell "checks failed" from "tool broke" (1–7). `annotate` mode writes the PDF and still exits 10.
- PDF rendering uses WeasyPrint ≥ 70 behind a URL fetcher that only allows `data:` URIs and template files, so server data can never make the renderer fetch remote URLs or read local files.
- The Docker runtime stage installs Pango and HarfBuzz from Debian over HTTPS. Its apt step could not be run in the development sandbox because deb.debian.org was blocked there; the Python build stage was verified.
- GitLab gets JUnit and Code Quality outputs; SARIF was dropped.

> **Desktop proof of concept (branch `claude/desktop-poc`):** a fork of the tool that runs on
> a user's own Windows or Linux computer: `tae desktop`, a local web page where the user
> signs in with their own ThreatAtlas token, generates reports on demand, and downloads
> them. Reports are kept in a local folder. PDFs use WeasyPrint or, on Windows, headless
> Microsoft Edge. It reuses the pull, validate and report code, and tries out the report
> portal's user flow (§5.8) before building the server version. See `docs/DESKTOP.md`.

## 1. Goal

A command-line tool (`tae`) that:

1. **Pulls** data from an OWASP ThreatAtlas instance over its REST API.
2. **Validates** it against built-in and user-defined rules.
3. **Renders** a structured PDF report driven by a declarative report definition (which sections, which filters, ordering, branding).
4. Later: **creates and updates** products, diagrams, threat models, threats, mitigations, custom frameworks, and risk acceptances and approvals.

Delivered as a Docker image, run in a Kubernetes namespace and from GitLab CI.

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
| Risk acceptance workflow | Done through `PUT /diagram-threats/{id}`; approver queue at `GET /approvals/my`, `GET /approvals/my/count` | Setting status=accepted stamps `accepted_at`. Setting `acceptance_review_status` to `approved` stamps `acceptance_reviewed_at`. Setting it to `rejected` resets the threat to `identified` and clears justification, approver and review date |
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
| Packaging | `pyproject.toml` (uv); **Docker image is the primary deliverable** (Debian slim with Pango and fonts baked in, non-root, read-only rootfs compatible) | Decided: Docker, run in Kubernetes |
| CI | **GitLab CI**: lint, type-check, test, build, push to the GitLab container registry, optional integration job | Decided |
| Quality | pytest, respx, ruff, mypy, pre-commit | |

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
│   ├── rules/custom-rules.yaml
│   └── assets/                     # per-product supplementary assets (see §5.6)
│       └── payments-api/
│           ├── assets.yaml
│           └── architecture-overview.svg
├── Dockerfile
├── .gitlab-ci.yml
├── deploy/k8s/                     # on-demand Job, ConfigMap, Secret template, PVC example
│   ├── report-job.yaml
│   ├── configmap.yaml
│   └── secret.example.yaml
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
│   │       ├── frameworks.py       # custom frameworks
│   │       ├── risks.py            # risk acceptance and approval
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
│   │   ├── assets.py               # load per-product asset folder (images, PDFs)
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

All three priority checks are **on by default with level `error`**: every threat scored, accepted risks fully documented (justification, approver, review date, approved review status, review date not passed), and no open high or critical threats.

Output formats: Rich table, JSON, **JUnit XML** (GitLab test report widget), **GitLab Code Quality JSON** (MR widget), and an optional report section. The exit code is non-zero when findings at or above `--fail-on` exist.

**What happens to the report when validation fails is configurable** (`validation.on_failure` in the report definition, overridable with `--on-failure`):

| Mode | Behaviour |
|---|---|
| `block` | Don't produce a PDF; exit non-zero |
| `annotate` | Produce the PDF with a findings section and a "VALIDATION FAILED" banner on the cover and in the footer; exit non-zero |
| `warn` | Produce the PDF with a findings section; exit 0 |
| `ignore` | Produce the PDF without findings; exit 0 |

Thresholds are set per mode (`fail_level: error|warning`).

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
    on_failure: annotate        # block | annotate | warn | ignore
    fail_level: error
  assets: ./assets/{{ product.slug }}   # per-product supplementary folder (§5.6)
  sections:
    - type: cover
    - type: toc
    - type: executive_summary   # counts by severity/status, open high/critical, KPIs
    - type: product_info
    - type: architecture        # supplied images from the asset folder (§5.6)
    - type: diagram             # DFD rendered from ThreatAtlas data, per diagram
      per: diagram
      source: auto              # rendered | asset | auto (asset if one is mapped, else rendered)
      annotate_threats: true    # numbered badges on elements, cross-referenced in the threat table
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

There is **one product per report**. A multi-product run (`tae export --products 12,14,…` or `--all`) produces one PDF per product in the output directory.

The tool also provides `tae report init`, which scaffolds a definition, `tae report schema`, which emits JSON Schema for IDE autocomplete, and `--html` to output the intermediate HTML for fast template iteration.

### 5.5 Phase 2: write operations

Each resource gets a command group with `list`, `get`, `create`, `update` and `delete`, plus resource-specific verbs:

```
tae products    list|get|create|update|delete|duplicate
tae diagrams    list|get|create|update|delete
                export-json|import-json                      # ReactFlow JSON round-trip
                versions list|show|create|compare|restore|delete
tae frameworks  list|get|create|update|delete                # custom frameworks
tae models      list|create|update|complete|archive          # threat model = framework bound to a diagram
tae threats     catalog list|create|update|revert|delete
                list --diagram|identify|update|delete        # diagram-threat instances
tae mitigations catalog list|create|update|revert|delete
                list --diagram|apply|update|delete
tae risks       accept <diagram-threat> --justification … --approver … --review-date …
                pending                                      # my approval queue (/approvals/my)
                approve|reject <diagram-threat> --note …
                list --product … [--expiring 30d]
tae apply -f threatmodel.yaml [--dry-run] [--prune]          # declarative, idempotent sync
```

Note that **reject** in ThreatAtlas clears the acceptance and sets the threat back to `identified`. The CLI asks for confirmation and prints what will be cleared.

`tae apply` covers frameworks, products, diagrams (with `diagram_data` from a file), models, threat and mitigation instances, and acceptance requests. Approvals stay imperative so that a sync can't approve anything.

Design rules for write operations:

- Global `--dry-run` shows the planned HTTP calls or a diff.
- `--yes` is required for deletes in non-interactive mode.
- Input comes from flags, `--from-file` (JSON/YAML), or stdin.
- Entities can be referenced by ID or by name, e.g. `--product "Payments API"`.
- `tae apply` reconciles a YAML description of product, diagrams, models, threats and mitigations against the server, matching existing entities by name or element ID. This makes threat models as code possible in Git and CI.

The phase 1 client is built with write methods from the start so phase 2 is mostly CLI wiring.

### 5.6 Diagrams and per-product asset folders

Data flow and architecture diagrams are required in every report. They come from two sources, which can be combined:

1. **Rendered from ThreatAtlas:** each diagram's `diagram_data` (ReactFlow) becomes vector SVG. Processes are drawn as rounded boxes, data stores as parallel-line stores, external entities as rectangles, trust boundaries as dashed groups. Edges carry their labels. Numbered threat badges link to the threat table. Layout uses the stored node positions, scaled to fit the page; large diagrams go on a landscape page.
2. **Supplied assets:** a per-product folder holding architecture and data flow drawings exported from other tools (SVG, PNG, JPG, or PDF pages), described by an optional manifest:

```yaml
# assets/payments-api/assets.yaml
product: "Payments API"          # or product_id: 12
images:
  - file: architecture-overview.svg
    title: "High-level architecture"
    section: architecture        # which report section it appears in
    caption: "Source: Confluence, rev 2026-11"
  - file: payment-flow-dfd.png
    title: "Payment authorisation DFD"
    replaces_diagram: "Payment flow"   # use instead of the rendered ThreatAtlas diagram
documents:
  - file: data-classification.pdf      # PDF pages appended as an appendix
    section: appendix
```

Without a manifest, every image in the folder is included in the architecture section, sorted by filename. In Kubernetes, the asset folder is mounted from a ConfigMap (small SVGs), a PVC, or a Git checkout through an init container.

Validation adds asset checks: missing files, unsupported formats, `replaces_diagram` naming a diagram that doesn't exist, and a diagram with neither rendered data nor an asset.

### 5.7 Deployment (Docker, Kubernetes, GitLab)

- **Image:** `python:3.12-slim` base plus Pango, HarfBuzz and fonts. Runs as non-root UID, entrypoint `tae`. Works with `readOnlyRootFilesystem` (writes only to `/out` and `/tmp`). Multi-stage build; image is scanned in CI.
- **Config in containers:** no keyring. Settings come from env vars (`TAE_URL`, `TAE_TOKEN`, `TAE_CA_BUNDLE`) or a mounted `tae.toml`. Report definitions and rules come from a ConfigMap, the token from a Secret, and the internal CA from a ConfigMap or Secret mount.
- **PDFs on manual runs only (decided):** nothing scheduled or automatic builds a PDF. Validation can still run automatically, since it produces no PDF.
- **Kubernetes:** the report portal (§5.8) runs as a `Deployment` in the namespace. Users generate reports from it by hand and download them there. An on-demand `Job` template (`kubectl create -f report-job.yaml`) is kept for admins and writes into the same storage. There is no `CronJob` for reports.
- **GitLab CI (this repo):** stages are `lint` → `test` → `build` → `integration` (ThreatAtlas started via docker-compose as a service) → `release`, which tags the image in the GitLab registry.
- **GitLab CI (consumers):** a reusable `.gitlab-ci` template that runs `tae validate` automatically (JUnit and Code Quality reports) and has a **manual** report job (`when: manual`, never on scheduled pipelines, doesn't block the pipeline) that builds the PDF as an artifact.

### 5.8 Report portal (`tae serve`)

Decided: generated PDFs are stored and offered for download through a small web app in the Kubernetes namespace. Every report is kept.

**What users can do**
- See the products they're allowed to see, each with its stored reports (newest first): date, who generated it, report definition, validation verdict, PDF size.
- Click **Generate report** for a product, choosing one of the configured report definitions. This is the manual run. The app pulls fresh data, validates, renders and stores the result, and the page shows progress until the download link appears.
- Download a PDF. Also available per report: the snapshot it was built from and the validation findings (JSON), as audit evidence.
- When a report definition says `on_failure: block` and validation fails, no PDF is stored. The run is listed as *blocked*, with its findings.

**How it is built**
- Same image and code base: a `tae serve` command. FastAPI with server-rendered Jinja pages and no JavaScript framework. It reuses the pull, validate and report code as it is.
- **Storage:** a PersistentVolume mounted at `/data`. One directory per run: `reports/<product-id>/<UTC timestamp>-<run-id>/` holding `report.pdf`, `snapshot.json`, `findings.json` and `run.json` (who, when, definition, tool version, snapshot hash, status). The directory listing is the index, with no database. Writes are atomic (temporary directory, then rename). Reports are kept forever; deleting is an admin action outside the app.
- **Runs:** an in-process queue with one worker and at most one run per product at a time. A run that is still in progress when the pod restarts is marked *interrupted*. Nothing runs on a schedule, and the app has no scheduler.
- **Configuration:** report definitions, rules files and templates from a ConfigMap (`/config/reports/*.yaml`, each offered by name in the UI). Connection settings come from the usual `TAE_*` env vars, and tokens from a Secret.
- **Security:**
  - Users sign in through single sign-on in front of the app.
  - Every generate and download is written to an audit log on stdout as JSON: who, what, when.
  - CSRF protection on the generate form, and strict security headers (CSP, no framing).
  - PDFs are served with `Content-Disposition: attachment`. Stored paths are validated to block path traversal.
  - The app runs as non-root with a read-only root filesystem; only `/data` and `/tmp` are writable.
  - A NetworkPolicy limits egress to ThreatAtlas.
- **Kubernetes manifests (`deploy/k8s/`):** Deployment (1 replica; the volume is ReadWriteOnce), Service, Ingress, PVC, ConfigMap, Secret template, NetworkPolicy, and the admin `report-job.yaml`. Health and readiness endpoints for probes.

**Permissions: each user's own ThreatAtlas token (decided)**
- The portal has no service token of its own. A user signs in by entering their personal ThreatAtlas API token (`ta_…`). The portal checks it with `GET /api/auth/me` and then acts exactly as that user, so ThreatAtlas's own roles and product sharing decide everything. An admin sees all products, and a viewer can't see products that aren't shared with them.
- **Generating** pulls data with the user's token, so a user can only generate reports for products they can read.
- **Listing and downloading stored reports** is re-checked against ThreatAtlas on every request (`GET /api/products/{id}` with the user's token, cached for a minute). A report stays visible only to people who can currently see that product. If someone loses access in ThreatAtlas, they lose access to its stored reports too.
- **Token handling:**
  - The token is held server-side in memory, never written to disk or logs.
  - The browser only gets a random session ID in a cookie (`HttpOnly`, `Secure`, `SameSite=Strict`).
  - Sessions expire after inactivity (8 hours, configurable), on sign-out, and when the pod restarts.
  - A token that ThreatAtlas rejects (401) ends the session immediately.
- The audit log records the ThreatAtlas username for every generate and download.

**Single sign-on (to be confirmed, so both modes are supported):** the ThreatAtlas token is what grants access to data. SSO in front is an extra gate on who can reach the portal at all. It can be set by configuration:
- `auth.sso: oidc`: the portal logs users in against an OIDC provider (issuer URL, client ID, client secret from a Secret).
- `auth.sso: proxy`: an oauth2-proxy or ingress OIDC in front passes the identity in a header. The header is trusted only from configured proxy addresses.
- `auth.sso: none`: token sign-in only, for testing or when network access is already restricted.

With SSO on, the SSO identity is logged alongside the ThreatAtlas user. Optionally, the portal refuses tokens whose email doesn't match the SSO email (`auth.require_matching_email`).

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

The token is resolved in this order: `--token`, then the `TAE_TOKEN` env var (the normal path in containers), then the keyring entry stored by `tae auth login` (workstations only). `tae auth status` calls `/api/auth/me` to show the user and role.

## 7. Implementation phases

| # | Milestone | Deliverables | Needs live instance? |
|---|---|---|---|
| 0 ✅ | Scaffold | pyproject (uv), package layout, Typer root, ruff/mypy/pytest, **Dockerfile**, **`.gitlab-ci.yml`** (lint/test/build), README | No |
| 1 ✅ | Client & auth | Config/profiles/env vars, keyring, HTTP client with pagination, retries, CA bundle and typed errors, Pydantic API models (from upstream `openapi.json`), `tae auth`, read-only `list/get` for every resource | Build with upstream fixtures; verify on instance |
| 2 ✅* | Pull | Collector, snapshot model and linker, `tae pull` (product / all / diagram), fixtures recorded from the test instance | Yes, to record fixtures |
| 3 ✅ | Validate | Rule engine, 21 built-in rules (the three priority checks as errors), YAML custom rules, table/JSON/JUnit/Code Quality output, `--fail-level`, configurable `on_failure` | No |
| 4 ✅ | Report MVP | Definition schema, query layer, Jinja2/WeasyPrint renderer, sections: cover, TOC, summary, product info, **rendered DFD diagrams**, threat table, mitigation table, accepted risks, findings | No |
| 5 | Report advanced | **Per-product asset folders** (images, PDF appendices, diagram replacement), threat badges on diagrams, risk heatmap and charts, branding, custom templates (corporate layout once approved), `report init/schema`, `tae export` one-shot and multi-product, **k8s manifests**, GitLab consumer template | No |
| 5b | Report portal | `tae serve`: sign-in with the user's ThreatAtlas token, product list, generate on demand, run status, download PDF, snapshot and findings with per-request access checks; PVC storage (keep all); optional OIDC or proxy SSO; audit log, CSRF and security headers; k8s Deployment/Service/Ingress/PVC/NetworkPolicy manifests | Yes, to test end to end |
| 6 | Write ops (imperative) | CRUD for products, diagrams (+ versions, JSON import/export), custom frameworks, models, catalog threats and mitigations, diagram-threat and diagram-mitigation instances; **`tae risks` accept/approve/reject/pending**; dry-run; name resolution | Yes |
| 7 (largely done via `tae import`) | Declarative apply | `tae apply` with diff, prune, idempotency, covering frameworks → products → diagrams → models → threats/mitigations → acceptance requests | Yes |

✅ done; * built and tested against fixtures, real fixtures still to be recorded.

Phases 0–5 deliver the reporting goal; phases 6–7 deliver the create/update goal. Phases 0, 1, 3 and 4 can be built before the test instance is ready, using fixtures derived from the upstream schemas and seed data.

## 8. Testing strategy

- **Unit:** snapshot linking, every validation rule (one passing and one failing fixture each), query/filter/sort, risk banding, and diagram SVG rendering (golden files).
- **HTTP:** `respx`-mocked client tests built from recorded real payloads, covering pagination, 401/403/404/422 handling, and retries.
- **Report:** build PDFs from fixture snapshots, then use `pypdf` to assert page count, section headings and key strings. HTML snapshot tests for templates.
- **Integration (optional, CI job):** start ThreatAtlas from its `docker-compose.yml`, seed it, then run pull → validate → report and phase 2 CRUD round-trips.

## 9. Decisions

| # | Topic | Decision |
|---|---|---|
| 1 | Language | Python |
| 2 | Report scope | One product per report; multi-product runs produce one PDF each |
| 3 | Corporate layout | Pending approval to share. The default template will be cleanly structured, and the corporate one gets added as a custom template later |
| 4 | Diagrams | Required. Rendered from ThreatAtlas data, plus supplied images and PDFs from a per-product asset folder (§5.6) |
| 5 | Distribution | Docker image, deployed in a Kubernetes namespace |
| 6 | On validation failure | Configurable: block / annotate / warn / ignore (§5.3) |
| 7 | Priority checks | All three: every threat scored, accepted risks fully documented, no open high/critical threats. On by default as errors |
| 8 | Test instance | User will set one up. Until then, development runs against fixtures built from upstream ThreatAtlas v0.9.x |
| 9 | Write ops | Both imperative commands and declarative `apply`. Also covers custom frameworks, diagrams (with versions) and risk acceptance/approval |
| 10 | CI / registry | GitLab CI, GitLab container registry |
| 11 | When PDFs are made | Manual runs only. Validation may run automatically; no scheduled or automatic job builds PDFs |
| 12 | Where PDFs are kept | Stored by a small web app in the Kubernetes namespace (`tae serve`, §5.8), which users also generate and download them from |
| 13 | Retention | Keep every report, with its snapshot and findings |
| 14 | Portal permissions | Each user signs in with their own ThreatAtlas API token; the portal acts as them, and access to stored reports is re-checked against ThreatAtlas on each request |
| 15 | Portal SSO | Not decided yet; build both built-in OIDC and trusted-proxy headers (plus none), chosen by configuration |
| 16 | YAML import | `tae import` takes a framework file (custom methodology, catalogue, own risk scale) or a threat-model file (product, diagrams, threat models, threats and mitigations) and syncs it into ThreatAtlas: match by name, plan first, `--dry-run`, deletes only with `--prune` (see docs/import.md). This brings forward much of phase 7 |
| 17 | Custom risk scale | Defined in YAML; ThreatAtlas keeps its own scoring, and `tae` uses the custom bands for that framework's threats in validation and reports |

### Still open

- The corporate report layout and required sections (waiting on approval).
- Report portal: which single sign-on setup fronts apps in the namespace (both options will be supported; this decides the example manifests).
- Whether the instance uses a public or internal CA (if internal, the CA bundle gets mounted).
- How the asset folders are sourced in Kubernetes: Git repo checkout, PVC, or ConfigMap.
- The GitLab repo. This GitHub repo is the working location for now; mirroring or migration can be set up later.
