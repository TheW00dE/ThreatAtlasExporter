#!/usr/bin/env sh
# ThreatAtlas Reports - desktop proof of concept (Linux).
# Run from a terminal or your file manager. Your browser opens; keep the terminal open.
set -eu
cd "$(dirname "$0")/.."

if ! command -v uv >/dev/null 2>&1; then
  echo "This app needs 'uv' (a small Python launcher). Install it once, then run this script again:"
  echo
  echo "  curl -LsSf https://astral.sh/uv/install.sh | sh"
  echo
  echo "or see https://docs.astral.sh/uv/getting-started/installation/"
  exit 1
fi

# PDFs: WeasyPrint if Pango is installed (sudo apt install libpango-1.0-0 libpangoft2-1.0-0),
# otherwise Chrome, Chromium or Edge if one is installed.
exec uv run --no-dev --frozen tae-desktop "$@"
