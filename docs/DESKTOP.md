# Desktop proof of concept

A small app that runs on your own Windows or Linux computer. You sign in with your own
ThreatAtlas API token, pick a product and a report type, and get the PDF. It's a local web
page in your usual browser. Nothing is installed on a server, and nothing runs on a
schedule: a report is only created when you click **Generate report**.

> This is a proof of concept on the `claude/desktop-poc` branch. It shares all of its
> reporting code with the main tool (`tae`), and is a stepping stone towards the report
> portal planned for Kubernetes.

## What you need

- Access to the ThreatAtlas installation, and a personal API token: in ThreatAtlas go to
  **Settings → Integrations → API Tokens** and create one (it starts with `ta_`).
- [uv](https://docs.astral.sh/uv/), a small launcher that fetches the right Python for you.
  Install it once:
  - Windows: `winget install --id=astral-sh.uv -e`
  - Linux: `curl -LsSf https://astral.sh/uv/install.sh | sh`
- A copy of this repository's `claude/desktop-poc` branch (git clone, or download as ZIP
  and unpack).
- For PDFs:
  - **Windows:** nothing extra. The app uses Microsoft Edge, which every Windows machine has.
  - **Linux:** either the Pango libraries (`sudo apt install libpango-1.0-0 libpangoft2-1.0-0`)
    for the best output, or Chrome, Chromium or Edge.

The first start downloads Python and the dependencies, which takes a minute. Later starts
take a few seconds.

## Start it

- **Windows:** double-click `desktop\start-windows.cmd`.
- **Linux:** run `desktop/start-linux.sh`.

A console window opens and your browser shows the app. Keep the console window open while
you use it, and close it (or press Ctrl+C) to stop.

If the browser doesn't open by itself, copy the link from the console window. Only that
link works, and only on this computer.

## Use it

1. **Sign in**: enter the ThreatAtlas address (for example `https://threatatlas.example.com`)
   and your API token. You see exactly the products your ThreatAtlas account can see.
2. **Pick a product**, then a **report type**:
   - *Full technical report*: summary, risk matrix, diagrams, all threats and
     mitigations, accepted risks, validation findings, catalogue.
   - *Executive summary*: summary, risk matrix, diagrams, high and critical threats.
   - *Risk acceptance review*: accepted risks and their approvals. Not produced if
     validation finds errors, because it is meant as sign-off evidence.
3. Click **Generate report**. The page shows progress, then **Open PDF** / **Download PDF**.
4. Every report is kept. The product page lists earlier ones, and **Open reports folder**
   shows them in your file manager.

## Where reports are saved

`Documents\ThreatAtlas Reports` (Windows) or `~/Documents/ThreatAtlas Reports` (Linux),
one folder per product and per report:

```
ThreatAtlas Reports/
└── 12-payments-api/
    └── 20261125T153156Z-44f59622/
        ├── report.pdf        the report
        ├── snapshot.json     the ThreatAtlas data it was built from
        ├── findings.json     validation findings
        └── run.json          who generated it, when, which report type, outcome
```

The snapshot and findings are evidence of exactly what a report was based on. You can
rebuild or re-check a report later with the main tool:
`tae report build snapshot.json` or `tae validate snapshot.json`.

## Options

Pass these to the start script, for example `start-windows.cmd --reports-dir D:\Reports`:

| Option | Meaning |
|---|---|
| `--reports-dir PATH` | Save reports somewhere else (or set `TAE_REPORTS_DIR`) |
| `--pdf-engine auto\|weasyprint\|browser` | Choose how PDFs are made. Windows uses `browser` (Edge) |
| `--port N` | Use a fixed local port instead of a random free one |
| `--no-browser` | Don't open the browser; just print the link |

**Your own report types:** put report definitions (`*.yaml`, see
[report-definition.md](report-definition.md)) in `<reports folder>/definitions/` and they
appear as extra choices.

**Pre-filled address or automatic sign-in:** the app reads the same settings as `tae`. A
`~/.config/tae/config.toml` profile, or `TAE_URL`, fills in the address. If a token is
available too (`TAE_TOKEN`, or one remembered earlier), you're signed in automatically.

**Browser for PDFs:** set `TAE_BROWSER` to the full path of `msedge.exe` / `chrome.exe` if
it isn't found automatically.

## Security

- **Local only:** the app listens on `127.0.0.1` only, so other computers can't reach it.
- **Protected from other websites:** a website open in your browser can't use the app.
  Every page needs a secret that only the launch link carries, the `Host` header is
  checked, forms carry a CSRF token and an `Origin` check, and pages forbid scripts and
  framing.
- **Your token:** it stays in the app's memory and is never written to disk or logs. If you
  tick *Remember it*, it is stored in the operating system's credential store (Windows
  Credential Manager, or the Secret Service on Linux). *Sign out* forgets it again, if you
  choose.
- **Your permissions:** the app acts with your own ThreatAtlas permissions. It can't show
  you anything ThreatAtlas wouldn't.
- **TLS:** connections to ThreatAtlas are verified against your operating system's
  certificate store, so an internal company CA that Windows trusts works without extra
  setup.
- **PDF rendering:** a report is rendered from a self-contained page that is not allowed
  to run scripts or load anything from the network.

## Limits of the proof of concept

- One user per computer. Reports in the folder can be read by anyone with access to that
  folder.
- The report list shows everything in the local folder; it isn't re-checked against
  ThreatAtlas. The portal will re-check.
- With the Edge/Chrome PDF engine, the table of contents has no page numbers and the PDF
  outline is simpler. Everything else matches WeasyPrint.
- Not tested yet against a live ThreatAtlas instance (only against a faithful fake), and
  not yet on a real Windows machine.
