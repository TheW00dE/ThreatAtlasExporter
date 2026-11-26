# ThreatAtlasExporter (`tae`)

A command-line tool for [OWASP ThreatAtlas](https://github.com/OWASP/www-project-threatatlas). It:

- **pulls** a product's diagrams, threat models, threats and mitigations into a snapshot file,
- **validates** them against built-in and custom rules ([docs/validation-rules.md](docs/validation-rules.md)),
- **renders** a PDF report per product from a configurable report definition ([docs/report-definition.md](docs/report-definition.md)),
- **creates and updates** threat-model data from the command line or from YAML *(planned)*.

See [docs/PLAN.md](docs/PLAN.md) for the design and roadmap.

> **Status:** pull, validate and PDF reports work, tested against fixtures modelled on
> ThreatAtlas v0.9.x; not yet tested against a live instance. Write commands come in later phases.

## Desktop proof of concept (this branch)

This branch (`claude/desktop-poc`) adds a desktop app for Windows and Linux. You sign in
with your own ThreatAtlas token, pick a product and a report type, and download the PDF. It
is a local web page in your browser; start it with `desktop\start-windows.cmd` or
`desktop/start-linux.sh`. See **[docs/DESKTOP.md](docs/DESKTOP.md)**.

On Windows, PDFs are made with Microsoft Edge, so nothing extra needs installing. The main
tool can do the same: `tae report build --pdf-engine browser`.

## Quick start

```sh
export TAE_URL=https://threatatlas.example.com TAE_TOKEN=ta_...
tae products list
tae pull --product "Payments API" -f payments.snapshot.json
tae validate payments.snapshot.json
tae report init report.yaml          # then edit it
tae report build payments.snapshot.json -d report.yaml -f payments-threat-model.pdf
```

`tae report build --product "Payments API"` does all three steps in one go. The snapshot
file records exactly what a report was built from, so reports can be rebuilt and audited
later.

## Install

### Docker (recommended)

```sh
docker build -t threatatlas-exporter .
docker run --rm -e TAE_URL=https://threatatlas.example.com -e TAE_TOKEN threatatlas-exporter products list
docker run --rm -e TAE_URL -e TAE_TOKEN -v "$PWD/out:/out" threatatlas-exporter \
  report build --product "Payments API" -f /out/payments.pdf
```

Builds behind a TLS-intercepting proxy can pass its CA as a build secret:
`docker build --secret id=ca,src=proxy-ca.pem -t threatatlas-exporter .`

### From source

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/). PDF output also needs Pango and
HarfBuzz (`apt-get install libpango-1.0-0 libpangoft2-1.0-0 libharfbuzz-subset0`, or
`brew install pango`); everything else works without them.

```sh
uv sync
uv run tae --help
```

`tae auth login` stores a token in the OS keyring (Windows Credential Manager, macOS
Keychain, Secret Service). In containers there's usually no keyring; use `TAE_TOKEN` or
`TAE_TOKEN_FILE` there.

## Authenticate

Create a personal API token in ThreatAtlas under **Settings → Integrations → API Tokens**.
Tokens start with `ta_`. Then use **one** of these methods:

| Method | Use for |
|---|---|
| `TAE_TOKEN=ta_…` | CI jobs, quick tests |
| `TAE_TOKEN_FILE=/var/run/secrets/tae/token` | Kubernetes Secret mounted as a file |
| `token_file = "…"` in a profile | Workstations with several instances |
| `tae auth login` | Workstations, stored in the OS keyring |

`tae auth status` shows which token is in use and which user it belongs to.

## Configure

Settings come from, in order of precedence: command-line flags, environment variables, the
selected profile in the config file, then defaults.

Config file (`~/.config/tae/config.toml`, or `--config` / `TAE_CONFIG`):

```toml
default_profile = "prod"

[profiles.prod]
url = "https://threatatlas.example.com"
ca_bundle = "/etc/ssl/certs/internal-ca.pem"   # for an internal CA
timeout = 30
retries = 3

[profiles.local]
url = "http://localhost:8000"
```

| Env var | Meaning |
|---|---|
| `TAE_URL` | Instance base URL (the frontend origin, or the backend; `/api` is added) |
| `TAE_TOKEN`, `TAE_TOKEN_FILE` | API token, or a file containing it |
| `TAE_PROFILE` | Profile name |
| `TAE_CONFIG` | Config file path |
| `TAE_CA_BUNDLE` | CA bundle for internal certificates |
| `TAE_VERIFY_TLS` | `false` disables TLS verification (local testing only) |
| `TAE_TIMEOUT` | HTTP timeout in seconds |

Tokens are never read from the config file, so it can be committed or mounted from a ConfigMap.
`tae config show` prints the effective settings.

## Commands

```text
tae pull        --product ID|NAME [-f FILE | --stdout]
tae validate    [SNAPSHOT | --product ID|NAME] [--rules FILE] [--format table|json|junit|codequality]
                [--fail-level error|warning|info|never] [--as-of DATE] [-f FILE]
tae rules       [--rules FILE]
tae report      build [SNAPSHOT | --product ID|NAME] [-d DEFINITION] [-f PDF] [--html FILE]
                      [--rules FILE] [--on-failure block|annotate|warn|ignore] [--findings-file FILE]
                      [--pdf-engine auto|weasyprint|browser]
                init [FILE] | check FILE | schema [-f FILE]
tae desktop     [--reports-dir DIR] [--pdf-engine ...] [--port N] [--no-browser]
tae auth        login | status | logout
tae config      show | path
tae products    list | get ID | security-status ID
tae frameworks  list | get ID
tae diagrams    list [--product ID] | get ID | versions list ID | versions show ID N
tae models      list [--diagram ID] | get ID
tae threats     catalog list [--framework ID] [--custom|--builtin] | catalog get ID
                list [--diagram ID] [--model ID] [--element ID] | get ID
tae mitigations (same as threats)
tae risks       pending [--all]
```

Global options: `--profile`, `--url`, `--token`, `--ca-bundle`, `--no-verify-tls`, `--timeout`,
`-o table|json|yaml`, `-v`/`-vv`.

### Exit codes

| Code | Meaning |
|---|---|
| 0 | Success |
| 1 | Unexpected error |
| 2 | Invalid command-line usage |
| 3 | Configuration or input problem (no URL or token; invalid config, snapshot, rules or report definition; PDF libraries missing) |
| 4 | Authentication or permission error (401/403) |
| 5 | Not found (404) |
| 6 | Cannot connect (DNS, TLS, timeout, redirect) |
| 7 | Other API error |
| 10 | Checks failed: validation findings at or above the fail level, or a report blocked or annotated by validation |

## Development

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

CI runs on GitLab (`.gitlab-ci.yml`): lint, type-check, tests with coverage, then a container
image build pushed to the GitLab registry. For product repositories, a reusable pipeline that
validates automatically and builds the PDF only when the report job is started by hand is in
[examples/gitlab/threat-model.gitlab-ci.yml](examples/gitlab/threat-model.gitlab-ci.yml).

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
