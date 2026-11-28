---
title: ThreatAtlasExporter (tae) manual
tool: tae
applies_to: OWASP ThreatAtlas REST API (/api)
language: ASD-STE100 style (Simplified Technical English)
sections: [M1 Overview, M2 Install, M3 Configure, M4 Commands, M5 Snapshot, M6 Validate, M7 Report definition, M8 Theme, M9 Import, M10 Desktop app, M11 CI/CD, M12 Exit codes, M13 Security, M14 Troubleshoot, M15 Terms]
---

# ThreatAtlasExporter (tae) manual

This manual tells you how to use `tae`. Each section has an ID (M1, M2, …).
Keys, values and commands are in `code`. Copy them exactly.

Detail documents: [validation-rules.md](validation-rules.md), [report-definition.md](report-definition.md),
[theming.md](theming.md), [import.md](import.md), [DESKTOP.md](DESKTOP.md).

---

## M1 Overview

`tae` is a command-line tool for OWASP ThreatAtlas. It does these tasks:

| Task | Command | Result |
|---|---|---|
| Read data | `tae pull` | A snapshot file (JSON) of one product |
| Check data | `tae validate` | Findings, and an exit code |
| Make a report | `tae report build` | A PDF report |
| Write data | `tae import` | ThreatAtlas agrees with a YAML file |
| Look at data | `tae products`, `tae threats`, … | Tables, JSON or YAML |

Standard workflow:

```text
ThreatAtlas ──tae pull──> snapshot.json ──tae validate──> findings
                               │
                               └──tae report build──> report.pdf
```

Rules:

- One report is for one product.
- `tae` makes a PDF only when you start it. It does not make PDFs on a schedule.
- `tae` uses the permissions of your API token. You see only what ThreatAtlas lets you see.

---

## M2 Install

### M2.1 Docker (recommended)

```sh
docker build -t threatatlas-exporter .
docker run --rm -e TAE_URL -e TAE_TOKEN threatatlas-exporter products list
docker run --rm -e TAE_URL -e TAE_TOKEN -v "$PWD/out:/out" threatatlas-exporter \
  report build --product "Payments API" -f /out/payments.pdf
```

If a proxy intercepts TLS during the build, give its CA as a build secret:
`docker build --secret id=ca,src=proxy-ca.pem -t threatatlas-exporter .`

### M2.2 From source

Requirements: Python 3.11 or later, and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run tae --help
```

PDF output with WeasyPrint needs the Pango and HarfBuzz libraries:
`apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`.
All other functions work without them.

---

## M3 Configure

### M3.1 Get an API token

1. In ThreatAtlas, go to **Settings → Integrations → API Tokens**.
2. Create a token. The token starts with `ta_`.
3. Give the token to `tae` with one method from this table:

| Method | Use it for |
|---|---|
| `TAE_TOKEN=ta_…` | CI jobs and tests |
| `TAE_TOKEN_FILE=/path/to/token` | A Kubernetes Secret, mounted as a file |
| `token_file = "…"` in a profile | A workstation with more than one instance |
| `tae auth login` | A workstation. `tae` keeps the token in the OS keyring. |

To see the token and user in use, run `tae auth status`.

### M3.2 Order of settings

`tae` uses the first value that it finds:

1. Command-line option
2. Environment variable
3. Profile in the config file
4. Default value

### M3.3 Config file

Location: `~/.config/tae/config.toml`. Change it with `--config` or `TAE_CONFIG`.

```toml
default_profile = "prod"

[profiles.prod]
url = "https://threatatlas.example.com"
ca_bundle = "/etc/ssl/certs/internal-ca.pem"   # internal CA
timeout = 30                                   # seconds
retries = 3
# verify_tls = false                           # local tests only
# token_file = "/home/me/.ta-token"

[profiles.local]
url = "http://localhost:8000"
```

Do not put a token in the config file. `tae` refuses a file that has a token.

### M3.4 Environment variables

| Variable | Meaning |
|---|---|
| `TAE_URL` | Base URL of ThreatAtlas. `tae` adds `/api`. |
| `TAE_TOKEN` | API token |
| `TAE_TOKEN_FILE` | File that contains the API token |
| `TAE_PROFILE` | Profile name |
| `TAE_CONFIG` | Config file path |
| `TAE_CA_BUNDLE` | CA bundle for internal certificates |
| `TAE_VERIFY_TLS` | `false` stops TLS checks. Use only for local tests. |
| `TAE_TIMEOUT` | HTTP timeout in seconds |
| `TAE_BROWSER` | Path to Edge, Chrome or Chromium for the `browser` PDF engine |
| `TAE_REPORTS_DIR` | Report folder of the desktop app |

To see the settings in use, run `tae config show`.

---

## M4 Commands

### M4.1 Global options

Put global options before the command: `tae --profile prod products list`.

| Option | Meaning |
|---|---|
| `-p`, `--profile NAME` | Config profile |
| `--url URL` | ThreatAtlas URL |
| `--token TOKEN` | API token. Use `TAE_TOKEN` instead, to keep the token out of shell history. |
| `--config FILE` | Config file |
| `--ca-bundle FILE` | CA bundle |
| `--verify-tls` / `--no-verify-tls` | Check TLS certificates (default: check) |
| `--timeout SECONDS` | HTTP timeout |
| `-o`, `--output table\|json\|yaml` | Output format of list and get commands |
| `-v`, `-vv` | More log output |
| `--version` | Show the version |

### M4.2 Command reference

| Command | Function |
|---|---|
| `tae pull -P PRODUCT [-f FILE \| --stdout] [-q]` | Write a snapshot of one product (M5). PRODUCT is an ID or the exact name. |
| `tae validate [SNAPSHOT \| -P PRODUCT] [options]` | Check a product (M6) |
| `tae rules [-r CONFIG]` | List the validation rules |
| `tae report build [SNAPSHOT \| -P PRODUCT] [options]` | Make a PDF report (M7) |
| `tae report init [FILE] [--theme] [--force]` | Write an example report definition, or an example theme |
| `tae report check DEFINITION` | Check a report definition, its theme, fonts and images |
| `tae report schema [--theme] [-f FILE]` | Write the JSON Schema of report definitions or themes |
| `tae report labels [-t THEME]` | List the wording keys of a theme (M8.4) |
| `tae import FILE [-n] [--prune] [-y]` | Make ThreatAtlas agree with a YAML file (M9) |
| `tae import --schema framework\|threat-model` | Write the JSON Schema of import files |
| `tae desktop [options]` | Start the desktop app (M10) |
| `tae auth login [--token-stdin] \| status \| logout` | Manage the stored token |
| `tae config show \| path` | Show the settings, or the config file path |
| `tae products list \| get ID` | Show products |
| `tae products security-status ID [thresholds]` | Show the ThreatAtlas security check. Thresholds: `--fail-on-critical`, `--fail-on-unmitigated-high`, `--min-mitigation-ratio 0..1`. |
| `tae frameworks list \| get ID` | Show frameworks |
| `tae diagrams list [-P ID] \| get ID` | Show diagrams. `get -o json` includes nodes and edges. |
| `tae diagrams versions list ID \| show ID N` | Show the version history of a diagram |
| `tae models list [-d DIAGRAM] \| get ID` | Show threat models |
| `tae threats list [-d DIAGRAM] [-m MODEL] [-e ELEMENT] \| get ID` | Show threats on diagrams |
| `tae threats catalog list [-f FRAMEWORK] [--custom \| --builtin] \| get ID` | Show the threat catalog |
| `tae mitigations …` | Same subcommands as `tae threats` |
| `tae risks pending [--all]` | List accepted risks that wait for your approval |

### M4.3 Options of `tae validate`

| Option | Meaning |
|---|---|
| `-r`, `--rules FILE` | Validation config (M6.3) |
| `--fail-level info\|warning\|error\|never` | Exit with code 10 if a finding has this level or a higher level. Default: `error`. |
| `--format table\|json\|junit\|codequality` | Output format. Default: `table`. |
| `-f`, `--output-file FILE` | Write the output to a file |
| `--as-of YYYY-MM-DD` | Date for review-date checks. Use it for repeatable results. |
| `--risk-scale FILE` | Custom risk scale (M9.3). You can use it more than one time. |
| `--location PATH` | File path in Code Quality output |

### M4.4 Options of `tae report build`

| Option | Meaning |
|---|---|
| `-d`, `--definition FILE` | Report definition (M7). Default: the built-in full report. |
| `-f`, `--output-file FILE` | PDF file. Default: `<product>-threat-model-<date>.pdf`. |
| `-t`, `--theme FILE` | Theme (M8). It replaces the theme of the definition. |
| `-r`, `--rules FILE` | Validation config. It replaces the config of the definition. |
| `--on-failure block\|annotate\|warn\|ignore` | Action if validation fails (M7.5) |
| `--findings-file FILE` | Also write the findings as JSON |
| `--html FILE` | Also write the HTML (for template work) |
| `--as-of YYYY-MM-DD` | Report date. Default: today. |
| `--pdf-engine auto\|weasyprint\|browser` | PDF engine (branch `claude/desktop-poc`). `auto` uses WeasyPrint if its libraries load, else Edge, Chrome or Chromium. |

---

## M5 Snapshot

A snapshot is a JSON file. It has all data of one product:
the product, frameworks, diagrams, threat models, threats and mitigations,
and metadata (`source_url`, `pulled_at`, `pulled_by`).

- `tae validate` and `tae report build` read a snapshot.
- With `-P PRODUCT` instead of a file, these commands pull the data first.
- Keep the snapshot with the PDF. It shows which data the report used.
  You can make the same report again from it.

```sh
tae pull -P "Payments API" -f payments.snapshot.json
```

---

## M6 Validate

### M6.1 Risk calculation

- `score = likelihood × impact`. Likelihood and impact are 1 to 5.
- Severity bands (ThreatAtlas default): critical ≥ 20, high ≥ 12, medium ≥ 6, low < 6.
- A custom risk scale can change the bands and level names (M9.3).

### M6.2 Built-in rules

Families: STR (structure), REF (references), CON (consistency), CMP (completeness), GOV (governance).

| Rule | Level | Check |
|---|---|---|
| `STR001` | error | Status and type values use the ThreatAtlas vocabularies. |
| `STR002` | error | Likelihood and impact are 1 to 5. |
| `REF001` | error | Each threat and mitigation is on an element that exists. |
| `REF002` | error | Each threat and mitigation belongs to a threat model of the same diagram. |
| `REF003` | warning | A linked mitigation points to a threat on the same diagram. |
| `REF004` | warning | `element_type` agrees with node or edge. |
| `CON001` | error | Stored scores and severities agree with likelihood × impact. |
| `CON002` | warning | A mitigated threat has an implemented or verified mitigation. |
| `CON003` | warning | Residual risk is not higher than inherent risk. |
| `CON004` | warning | A completed threat model has no threats with status `identified`. |
| `CMP001` | error | Each threat has a likelihood and an impact. |
| `CMP002` | warning | Each diagram has a threat model. |
| `CMP003` | warning | Each threat model has threats. |
| `CMP004` | info | Each element has threats. |
| `CMP005` | warning | Required product fields have values. |
| `CMP006` | error | Each diagram has elements. |
| `GOV001` | error | An accepted risk has a justification, an approver and a review date. |
| `GOV002` | error | The approver approved the accepted risk. |
| `GOV003` | error | The review date of an accepted risk is not in the past. |
| `GOV004` | warning | The review date of an accepted risk is soon. |
| `GOV005` | error | No high or critical threat is open. |

### M6.3 Validation config file

Give it with `--rules`, or with `validation.rules` in a report definition. All keys are optional.

```yaml
disable: [CMP004]                 # do not run these rules
levels: {CON002: error, GOV004: info}
params:
  review_warning_days: 30                          # GOV004
  open_risk_severities: [high, critical]           # GOV005
  required_product_fields: [description, owner_name, owner_email, reviewer]  # CMP005
  uncovered_element_types: [process, datastore, external, flow]              # CMP004
risk_scales: [../models/payments-framework.yaml]   # M9.3
rules: []                                          # custom rules, M6.4
```

`tae` refuses unknown keys and unknown rule IDs (exit code 3).
Thus a typing error cannot stop a check without a message.

### M6.4 Custom rules

```yaml
rules:
  - id: CUSTOM-001
    title: High risks need a decision
    level: error                       # error | warning | info. Default: warning.
    applies_to: diagram_threat         # diagram_threat | diagram_mitigation | diagram | model | element | product
    when:    {severity: [high, critical]}       # optional: the entities to check
    require: {status: [mitigated, accepted]}    # the condition that each entity must meet
    message: "{ref} {name} on {element_label} is {severity} and {status}"
```

`tae` makes a finding for each entity that meets `when` and does not meet `require`.

| Condition | Meaning |
|---|---|
| `field: value` | Equal (text: not case-sensitive) |
| `field: [a, b]` | One of the values |
| `field: {op: value}` | All operators must be true |

Operators: `eq`, `ne`, `in`, `not_in`, `gt`, `gte`, `lt`, `lte`, `exists`, `empty`, `matches` (regular expression), `contains`.
Date values: `2027-01-31`, `today`, `today+30`, `today-7`.
The field list for each `applies_to` is in [validation-rules.md](validation-rules.md#fields).
Rules are data. `tae` does not run code from rules.

### M6.5 Output formats

| Format | Use |
|---|---|
| `table` | Terminal |
| `json` | Scripts |
| `junit` | GitLab test report |
| `codequality` | GitLab Code Quality widget |

---

## M7 Report definition

A report definition is a YAML file. It sets the content of a report.
To start, run `tae report init report.yaml`. To check it, run `tae report check report.yaml`.
Relative paths start at the folder of the definition file.

### M7.1 Top-level keys

| Key | Default | Meaning |
|---|---|---|
| `title` | `Threat Model Report` | Title on the cover and in the header |
| `subtitle` | `{{ product.name }}` | Subtitle on the cover |
| `theme` | built-in | Theme file or inline theme (M8) |
| `branding` | from theme | `organisation`, `logo`, `primary_color`, `accent_color`, `classification`, `footer`. A value here replaces the theme value. |
| `page_size` | from theme | `A4` or `Letter`. It replaces the theme value. |
| `language` | `en` | Language tag of the PDF |
| `document` | none | Document control data (M7.4) |
| `scope` | all | Which diagrams, frameworks and threat-model statuses to include |
| `filters` | none | Threat filters for all sections |
| `validation` | | `rules`, `on_failure`, `fail_level` (M7.5) |
| `risk_scales` | none | Files with custom risk scales (M9.3) |
| `sections` | full report | Sections, in sequence (M7.3) |
| `template` | built-in | Folder with template overrides (M7.6) |

### M7.2 Placeholders

Text values can contain placeholders, for example `{{ product.name }}`.

| Placeholder | Value |
|---|---|
| `product.*` | All product fields (`name`, `owner_name`, `jira_project_key`, …) |
| `meta.*` | `source_url`, `pulled_at`, `pulled_by`, `tool_version` |
| `title`, `subtitle` | Report title and subtitle (header and footer only) |
| `organisation`, `classification` | From branding |
| `footer` | Organisation and footer text, joined with ` · ` |
| `document.*` | `id`, `version`, `status`, `owner` |
| `report_date` | Report date (YYYY-MM-DD) |

A missing value shows as empty text. To show a default, write `{{ product.owner_name or "unassigned" }}`.
To show only the date part, write `{{ meta.pulled_at|date }}`.

### M7.3 Sections

All sections accept `title` and `page_break` (true or false).

| `type` | Options | Content |
|---|---|---|
| `cover` | | Title, classification, logo, facts, validation banner |
| `toc` | | Table of contents with page numbers |
| `document_control` | | Document data, revision history, approval table |
| `text` | `body` | Free text. A blank line starts a new paragraph. |
| `executive_summary` | | Key figures, chart, status counts, top open risks, validation result |
| `product_info` | `fields` | Product data |
| `diagram` | `annotate_threats`, `legend`, `element_table` | Each diagram, with threat badges and an element table |
| `risk_matrix` | `residual` | 5 × 5 likelihood × impact matrix |
| `risk_scale` | | Meaning of the levels and the severity bands |
| `threat_table` | `group_by`, `sort`, `columns`, `filters`, `details` | Threats and their mitigations |
| `mitigation_table` | `statuses`, `group_by`, `columns` | Mitigations and their threats |
| `accepted_risks` | | Accepted risks, approvers, review dates |
| `validation_findings` | `min_level` | Validation findings |
| `appendix_catalog` | `include` | Catalog descriptions of the threats and mitigations in use |

Options of `threat_table`:

- `group_by`: `none`, `diagram`, `element`, `severity`, `category`, `status`, `framework`
- `sort`: `ref`, `name`, `severity`, `risk_score`, `residual_score`, `status`, `element`, `category`, `diagram`. Put `-` before a key for descending sequence.
- `columns`: `ref`, `threat`, `category`, `element`, `diagram`, `framework`, `likelihood`, `impact`, `score`, `severity`, `residual`, `status`, `mitigations`, `description`, `comments`

Example:

```yaml
sections:
  - type: cover
  - type: toc
  - type: executive_summary
  - type: threat_table
    group_by: diagram
    sort: [-severity, ref]
    filters: {min_severity: high}
```

### M7.4 Document control

```yaml
document:
  id: "TM-{{ product.jira_project_key }}-001"
  version: "1.2"
  status: Draft
  owner: "{{ product.owner_name }}"
  revisions:
    - {version: "1.0", date: "2026-09-01", author: "A. Analyst", changes: "First issue"}
  approvals:
    - {role: "Product owner", name: "{{ product.owner_name }}"}
    - {role: "Security architect"}
```

The `document_control` section shows these data. The header, footer and cover can also use them.

### M7.5 Validation in reports

`tae report build` always runs the validation. Validation uses the `scope` of the report.
Display filters (for example `min_severity`) do not decrease the validation.

| `on_failure` | PDF | Findings section | Exit code |
|---|---|---|---|
| `block` | Not written | – | 10 |
| `annotate` (default) | Written, with a "validation failed" banner | Added if missing | 10 |
| `warn` | Written | Added if missing | 0 |
| `ignore` | Written | Removed | 0 |

### M7.6 Template overrides

Use a theme first (M8). If you must change the structure of the report:

1. Make a folder, for example `my-template/`.
2. Copy only the files that you change from `src/tae/report/templates/`.
3. Set `template: ./my-template` in the definition.
4. To see the result quickly, use `--html out.html` and open the file in a browser.

Templates run in a sandbox. They can read only files in the template folders and `data:` URIs.

---

## M8 Theme

A theme is a YAML file with `kind: report-theme`. It sets the appearance of a report.
Many report definitions can use one theme.

```sh
tae report init --theme corporate.yaml       # write an example theme
tae report build SNAPSHOT --theme corporate.yaml
```

In a definition: `theme: ./corporate.yaml`, or an inline mapping under `theme:`.

### M8.1 Keys

All keys are optional. Relative paths start at the folder of the theme file.

| Key | Values |
|---|---|
| `name` | Text |
| `branding` | `organisation`, `logo`, `classification`, `footer` |
| `fonts.body`, `fonts.headings` | `family`. Optional `files`: `regular`, `bold`, `italic`, `bold_italic` (TTF, OTF, WOFF, WOFF2). |
| `fonts.size` | Points, 6 to 16. Default: 9.5. |
| `colors` | `primary`, `accent`, `text`, `secondary_text`, `muted`, `headings`, `table_header`, `table_header_text`, `table_stripe`, `border`, `cover_band`, `cover_text`, `classification` |
| `colors.severity` | `critical`, `high`, `medium`, `low`. Used for badges, charts and diagrams. |
| `colors.matrix` | Risk-matrix cell colours. Default: lighter severity colours. |
| `page.size` | `A4`, `A3`, `A5`, `Letter`, `Legal`, or `[width, height]` |
| `page.margins` | `top`, `right`, `bottom`, `left` |
| `header`, `footer` | `left`, `center`, `right` (M8.2) |
| `cover.layout` | `band`, `plain`, `image` |
| `cover.band_height` | Length. Default: `70mm`. |
| `cover.background_image` | Image file for `layout: image` |
| `cover.logo_position` | `left`, `center`, `right` |
| `cover.facts` | List of `[label, value]`. Values can contain placeholders. |
| `cover.show_generated_by` | true or false |
| `numbering` | true or false. Section numbers. |
| `watermark` | `text`, `color`, `opacity` (0.02 to 0.6) |
| `labels` | Wording (M8.4) |
| `extra_css` | CSS text, added after the built-in CSS |

Value formats:

- Colour: hex, for example `#0f4c5c`.
- Length: number and unit (`mm`, `cm`, `in`, `pt`, `px`), for example `20mm`.

### M8.2 Header and footer

Each has three slots. A slot can contain placeholders (M7.2) and `{page}`, `{pages}`.
`""` makes a slot empty. If you do not set a slot, `tae` uses the default.

```yaml
header: {left: "{{ product.name }} — {{ title }}", center: "{{ classification }}", right: ""}
footer: {left: "{{ footer }}", center: "", right: "Page {page} of {pages}"}
```

If validation fails and `on_failure` is `annotate`, the right header slot shows "VALIDATION FAILED".

### M8.3 Precedence

1. `--theme` on the command line
2. `theme:` in the definition
3. Built-in theme

Values in the `branding:` and `page_size` of the definition replace the theme values.

### M8.4 Labels (wording)

`labels` replaces built-in words. Key groups:

| Group | Example key | Default text |
|---|---|---|
| Section titles | `section.threat_table` | Threats |
| Table columns | `column.mitigation` | Mitigation |
| Field names | `field.report_date` | Report date |
| Product fields | `product.owner_name` | Owner |
| Headings | `heading.top_open_risks` | Top open risks |
| Axes | `axis.likelihood` | Likelihood |
| Severity words | `severity.high` | high |
| Status words | `status.mitigated` | mitigated |
| Short text | `text.none` | none |

To see all keys, run `tae report labels`. `tae` refuses unknown keys.
You can add new `status.<value>` keys. Long sentences are not labels. To change them, use a template override (M7.6).

### M8.5 Example

```yaml
kind: report-theme
name: Example Corp
branding: {organisation: Example Corp, classification: INTERNAL}
colors: {primary: "#0f4c5c", accent: "#e36414"}
page: {size: A4, margins: {top: 22mm, bottom: 20mm}}
footer: {right: "Page {page} of {pages}"}
cover: {layout: band, logo_position: left}
watermark: {text: DRAFT}
labels: {section.mitigation_table: Controls}
```

Full example: [examples/themes/example-corp.yaml](../examples/themes/example-corp.yaml).
Use only fonts, logos and colours that you have permission to use.

---

## M9 Import

`tae import FILE` makes ThreatAtlas agree with a YAML file.

### M9.1 File types

| `kind` | Content |
|---|---|
| `framework` | Custom framework, its threat and mitigation catalog, and an optional risk scale |
| `threat-model` | Product, diagrams, threat models, threats and mitigations |
| `risk-scale` | A risk scale only. Use it with `tae`; it is not imported. |

Examples: [examples/models/](../examples/models/).

### M9.2 Procedure

1. Check the plan: `tae import FILE --dry-run`.
2. Apply the file: `tae import FILE`.
3. To also delete items that are not in the file: `tae import FILE --prune`. In CI, add `--yes`.

How the sync works:

- `tae` checks the full file before it sends data.
- `tae` always shows the plan first.
- `tae` finds items by name. It creates new items and updates changed items.
- `tae` deletes items only with `--prune`.
- If you do not set an optional field, `tae` does not change it in ThreatAtlas.
- A second import of the same file changes nothing.
- If an import stops, correct the problem and import again.
- An import can request a risk acceptance. An import cannot approve a risk.

> **CAUTION:** ThreatAtlas shows a custom framework only to the account that created it.
> Import a framework and its threat models with the same account.

### M9.3 Risk scale

```yaml
risk_scale:
  name: Payments risk scale
  likelihood: {1: {label: Rare}, 2: {label: Unlikely}, 3: {label: Possible}, 4: {label: Likely}, 5: {label: Almost certain}}
  impact:     {1: {label: Negligible}, 2: {label: Minor}, 3: {label: Moderate}, 4: {label: Major}, 5: {label: Severe}}
  bands: {critical: 16, high: 10, medium: 5}
```

- ThreatAtlas: `tae` writes the scale into the framework description. ThreatAtlas keeps its own bands.
- `tae`: give the file with `risk_scales:` or `--risk-scale`. Then validation and reports use your bands and level names.
- `CON001` always checks the stored values against the ThreatAtlas bands.

### M9.4 Threat-model diagrams

- Elements: `process`, `datastore`, `external`, `boundary`. Flows connect elements.
- Without `position`, `tae` arranges the elements. Each trust boundary gets its own area.
- `tae` keeps positions that a user changed in the ThreatAtlas editor.
- Keep element IDs stable. Threats are attached to them.
- Put quotes around values with a comma inside `{ … }`.

---

## M10 Desktop app

Branch `claude/desktop-poc` only. Proof of concept for Windows and Linux.

1. Start it: Windows `desktop\start-windows.cmd`; Linux `desktop/start-linux.sh`; or `tae desktop`.
2. The browser opens a local page. Sign in with the ThreatAtlas URL and your API token.
3. Select a product and a report type.
4. Click **Generate report**. Then open or download the PDF.

| Option | Meaning |
|---|---|
| `--reports-dir PATH` | Report folder. Default: `Documents/ThreatAtlas Reports`. |
| `--pdf-engine auto\|weasyprint\|browser` | PDF engine. Windows uses Edge. |
| `--port N` | Fixed local port. Default: a free port. |
| `--no-browser` | Do not open the browser. Show the link only. |

Each report folder has `report.pdf`, `snapshot.json`, `findings.json` and `run.json`.
To add report types, put definitions in `<reports folder>/definitions/`.
The app listens on `127.0.0.1` only. Details: [DESKTOP.md](DESKTOP.md).

---

## M11 CI/CD (GitLab)

```yaml
threat-model:
  image: $CI_REGISTRY/your-group/threatatlas-exporter:latest
  script:
    - tae pull --product "$PRODUCT" -f snapshot.json
    - tae validate snapshot.json --format junit -f report.xml
  artifacts:
    when: always
    reports: {junit: report.xml}
```

- Give the token as a masked CI variable `TAE_TOKEN`.
- Make PDF jobs manual (`when: manual`).
- Full template: [examples/gitlab/threat-model.gitlab-ci.yml](../examples/gitlab/threat-model.gitlab-ci.yml).

---

## M12 Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error |
| 2 | Incorrect command-line usage |
| 3 | Configuration or input problem (no URL or token; incorrect config, snapshot, rules, definition or theme; PDF libraries missing) |
| 4 | Authentication or permission error (HTTP 401 or 403) |
| 5 | Not found (HTTP 404) |
| 6 | No connection (DNS, TLS, timeout, redirect) |
| 7 | Other API error |
| 10 | Checks failed: validation findings at or above the fail level, or a report blocked or annotated by validation |

---

## M13 Security

- `tae` does not read tokens from the config file.
- `tae` does not write tokens to logs.
- `tae` checks TLS certificates with the OS certificate store. Add an internal CA with `ca_bundle`.
- Report templates run in a sandbox. They cannot get access to Python or the network.
- `tae` embeds logos, fonts and images only after it checks their file content and size.
- `tae` escapes all theme text and header text before it puts the text into CSS.
- Validation rules are data. `tae` does not run code from them.
- Terminal output removes control characters from ThreatAtlas data.

---

## M14 Troubleshoot

| Problem | Cause | Action |
|---|---|---|
| Exit code 3, "No ThreatAtlas URL" | URL not set | Set `TAE_URL` or a profile `url`. |
| Exit code 4 | Token incorrect or expired | Make a new token. Run `tae auth status`. |
| Exit code 6, TLS error | Internal CA not trusted | Set `ca_bundle` or `TAE_CA_BUNDLE`. |
| "WeasyPrint libraries missing" | No Pango or HarfBuzz | Install them (M2.2), or use `--pdf-engine browser`. |
| Exit code 10 after `report build` | Validation failed (`annotate`) | Read the findings section. Correct the data, or change `on_failure`. |
| Import: "unknown field" | Comma in an unquoted YAML value | Put quotes around the value. |
| Custom framework not found | Other account created it | Import with the same account. |
| Theme value refused | Value format incorrect | Use hex colours and lengths with units (M8.1). |

---

## M15 Terms

| Term | Meaning |
|---|---|
| Product | Top-level item in ThreatAtlas. It contains diagrams. |
| Diagram | Data flow diagram with elements (nodes) and flows (edges) |
| Element | Process, data store, external entity or trust boundary |
| Framework | Threat-modelling method, for example STRIDE |
| Threat model | A framework applied to a diagram |
| Catalog | List of threats and mitigations of a framework |
| Snapshot | JSON file with all data of one product at one time |
| Finding | Result of one validation rule for one item |
| Report definition | YAML file that sets the content of a report |
| Theme | YAML file that sets the appearance of a report |
| Inherent risk | Risk before mitigation |
| Residual risk | Risk after mitigation |
| Accepted risk | Risk that a person accepts, with a justification and an approver |
