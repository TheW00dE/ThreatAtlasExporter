# ThreatAtlasExporter (`tae`)

A command-line tool for [OWASP ThreatAtlas](https://github.com/OWASP/www-project-threatatlas). It:

- **pulls** products, diagrams, threat models, threats and mitigations from a ThreatAtlas instance,
- **validates** them against built-in and custom rules *(planned)*,
- **renders** a PDF report per product from a configurable report definition *(planned)*,
- **creates and updates** threat-model data from the command line or from YAML *(planned)*.

See [docs/PLAN.md](docs/PLAN.md) for the design and roadmap.

> **Status:** early development. The API client, configuration and read-only commands work today.
> Pull, validate, report and write commands come in later phases.

## Install

### Docker (recommended)

```sh
docker build -t threatatlas-exporter .
docker run --rm -e TAE_URL=https://threatatlas.example.com -e TAE_TOKEN threatatlas-exporter products list
```

### From source

Requires Python 3.11+ and [uv](https://docs.astral.sh/uv/).

```sh
uv sync
uv run tae --help
```

To store a token in the OS keyring on a workstation, install the `keyring` extra:
`uv sync --extra keyring`.

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
| 3 | Configuration problem (no URL, no token, bad config file) |
| 4 | Authentication or permission error (401/403) |
| 5 | Not found (404) |
| 6 | Cannot connect (DNS, TLS, timeout, redirect) |
| 7 | Other API error |

## Development

```sh
uv sync
uv run pytest
uv run ruff check . && uv run ruff format --check .
uv run mypy
```

CI runs on GitLab (`.gitlab-ci.yml`): lint, type-check, tests with coverage, then a container
image build pushed to the GitLab registry.

## License

GPL-3.0-or-later. See [LICENSE](LICENSE).
