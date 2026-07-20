#!/usr/bin/env bash
# Unified install for VulnScout's three pieces: core/ (Strix), recon/ (mailrecon), submit/ (h1-brain).
# Each piece keeps its own isolated environment — this script just drives all three from one command.
set -euo pipefail

ROOT="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

require() {
  command -v "$1" >/dev/null 2>&1 || {
    echo "Missing required tool: $1" >&2
    echo "  $2" >&2
    exit 1
  }
}

echo "==> Checking toolchain"
require uv "Install from https://docs.astral.sh/uv/getting-started/installation/"
require bun "Install from https://bun.sh"

echo "==> core/ (Strix) — Python 3.12 venv"
cd "$ROOT/core"
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -e .

echo "==> submit/ (h1-brain) — Python 3.12 venv"
cd "$ROOT/submit"
uv venv .venv --python 3.12
uv pip install --python .venv/bin/python -r requirements.txt

echo "==> recon/ (mailrecon) — bun install"
cd "$ROOT/recon"
bun install

echo "==> Environment file"
cd "$ROOT"
if [ ! -f .env ]; then
  cp .env.example .env
  echo "Created .env from .env.example — fill in your keys before running core/ or submit/."
else
  echo ".env already exists, leaving it alone."
fi

echo ""
echo "==> Done."
echo "  core/.venv/bin/strix --help"
echo "  submit/.venv/bin/python submit/server.py"
echo "  cd recon && bun run src/cli.ts --help"
