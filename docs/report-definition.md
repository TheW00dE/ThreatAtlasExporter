# Report definition

A report definition is a YAML file that decides what goes into the PDF: scope, filters,
section order and options, branding, and what happens when validation fails.

```sh
tae report init report.yaml                     # commented starting point
tae report check report.yaml                    # validate the definition
tae report schema -f report.schema.json         # JSON Schema for editor autocompletion
tae report build snap.json -d report.yaml -f payments.pdf
tae report build --product "Payments API" -d report.yaml     # pull live, then build
```

PDFs are only produced on manual runs: by running this command, or by starting the
report job by hand in the GitLab template. Nothing scheduled or automatic builds them.

Without `--definition`, the built-in full report is used. Every report covers **one
product**. Relative paths in the definition (logo, rules, template) are resolved against
the definition file's directory.

To get schema-based autocompletion in VS Code, add this to `.vscode/settings.json`:

```json
{ "yaml.schemas": { "./report.schema.json": ["reports/*.yaml"] } }
```

## Top level

| Key | Default | Meaning |
|---|---|---|
| `title` | `Threat Model Report` | Cover and header title. May use `{{ product.name }}` etc. |
| `subtitle` | `{{ product.name }}` | Cover subtitle |
| `page_size` | `A4` | `A4` or `Letter`. Wide diagrams get landscape pages automatically. |
| `branding` | | See below |
| `scope` | everything | Which diagrams, frameworks and threat-model statuses are covered |
| `filters` | none | Report-wide threat filters |
| `validation` | | Rules file, failure handling |
| `sections` | full report | Ordered list of sections |
| `template` | built-in | Directory with template overrides |

Placeholders use a sandboxed template engine. Available values: `product.*` (every
product field) and `meta.*` (`source_url`, `pulled_at`, `pulled_by`, `tool_version`).

### `branding`

```yaml
branding:
  organisation: "Example Corp"   # cover and footer
  logo: ./logo.png               # PNG, JPG or SVG; embedded in the PDF
  primary_color: "#1f3a5f"       # headings, table headers, cover band
  accent_color: "#2f80ed"
  classification: "CONFIDENTIAL" # top of every page, and on the cover
  footer: "Security Architecture"
```

### `scope`

```yaml
scope:
  diagrams: all                         # or [ "Payment flow", 31 ]  (names or IDs)
  frameworks: [STRIDE]                  # empty list = all
  model_status: [in_progress, completed]  # leave out archived models
```

### `filters`

Applied to every section; a `threat_table` section can override them with its own `filters`.

```yaml
filters:
  min_severity: medium      # low | medium | high | critical
  include_unscored: true    # keep unscored threats when min_severity is set
  statuses: [identified, accepted]
  categories: [Spoofing, Tampering]
```

Mitigations linked to a filtered-out threat are left out too. The executive summary says
which filters are active.

### `validation`

```yaml
validation:
  rules: ./validation.yaml   # see validation-rules.md
  on_failure: annotate
  fail_level: error          # error | warning | info | never
```

| `on_failure` | PDF | Findings section | Exit code |
|---|---|---|---|
| `block` | not written | – | 10 |
| `annotate` (default) | written, with a "validation failed" banner on the cover and every page | added if missing | 10 |
| `warn` | written | added if missing | 0 |
| `ignore` | written | removed | 0 |

`--on-failure` and `--rules` on the command line override the definition.

## Sections

Every section accepts `title` (overrides the default heading) and `page_break` (start on a
new page; default `true` except for `cover` and `risk_matrix`). Sections are numbered
automatically and listed in the table of contents and PDF bookmarks.

| `type` | Options | Content |
|---|---|---|
| `cover` | | Title, classification, logo, key facts, validation banner, snapshot fingerprint |
| `toc` | | Contents with page numbers |
| `text` | `body` | Free text; paragraphs separated by blank lines; placeholders allowed |
| `executive_summary` | | KPIs, threats by severity chart, status breakdowns, top open risks, validation verdict |
| `product_info` | `fields` | Product metadata table |
| `diagram` | `annotate_threats`, `legend`, `element_table` | One rendered data flow diagram per diagram in scope, with threat badges, and a table of elements and their threats |
| `risk_matrix` | `residual` | 5×5 likelihood × impact heatmap(s) |
| `threat_table` | `group_by`, `sort`, `columns`, `filters`, `details` | Threats with their mitigations |
| `mitigation_table` | `statuses`, `group_by`, `columns` | Mitigations and the threats they address |
| `accepted_risks` | | Justification, approver, review date and status of each accepted risk; overdue ones highlighted |
| `validation_findings` | `min_level` | Findings at or above the level |
| `appendix_catalog` | `include` | Descriptions of every catalog threat and mitigation used |

### `threat_table`

```yaml
- type: threat_table
  group_by: diagram       # none | diagram | element | severity | category | status | framework
  sort: [-severity, -risk_score, ref]
  columns: [ref, threat, element, likelihood, impact, severity, status, mitigations]
  details: false          # descriptions and comments under each row
  filters: { min_severity: high }
```

Columns: `ref`, `threat`, `category`, `element`, `diagram`, `framework`, `likelihood`,
`impact`, `score`, `severity`, `residual`, `status`, `mitigations`, `description`, `comments`.

Sort keys (prefix `-` for descending): `ref`, `name`, `severity`, `risk_score`,
`residual_score`, `status`, `element`, `category`, `diagram`.

### `mitigation_table`

```yaml
- type: mitigation_table
  statuses: [proposed]    # e.g. only open work
  group_by: status        # none | diagram | status | element
  columns: [ref, mitigation, element, threat, status]
```

Columns: `ref`, `mitigation`, `category`, `element`, `diagram`, `threat`, `status`, `description`.

### References

Threats are numbered `T1, T2, …` per product (by diagram, most severe first) and
mitigations `M1, M2, …`. The same references appear in diagrams, tables, accepted risks
and findings, so readers can cross-reference.

## Diagrams

Diagrams are drawn from ThreatAtlas's own diagram data, using the same shapes as
ThreatAtlas: processes as circles, data stores as parallel lines, external entities as
rectangles, and trust boundaries as dashed areas. With `annotate_threats`, each element
shows a badge with its number of threats, coloured by the most severe one.

Supplying your own architecture drawings per product (and using them in place of rendered
diagrams) is planned for phase 5.

## Custom templates

The report is HTML and CSS rendered by WeasyPrint. To change the layout, point
`template:` at a directory containing only the files you want to override; everything
else comes from the built-in templates:

```
my-template/
├── styles/default.css            # whole stylesheet
├── report.html.j2                # page skeleton
├── macros.html.j2
└── sections/
    ├── cover.html.j2             # one file per section type
    └── ...
```

Copy the originals from `src/tae/report/templates/` as a starting point, and use
`tae report build ... --html out.html` to check changes quickly in a browser. All values
from ThreatAtlas are HTML-escaped automatically. For safety, templates can only load
files from the template directories and `data:` URIs; remote URLs are blocked.
