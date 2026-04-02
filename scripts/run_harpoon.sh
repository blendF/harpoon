#!/usr/bin/env bash
# Run Harpoon from repo root with common PATH fixes and optional .harpoon.env
# Usage:  bash scripts/run_harpoon.sh
set -euo pipefail

REPO_ROOT="$(cd "$(dirname "$0")/.." && pwd)"
cd "$REPO_ROOT"

# Repo .venv first so paramspider/arjun/rich from install_harpoon_tools.sh are on PATH (PEP 668 safe).
export PATH="${PATH}:${REPO_ROOT}/.venv/bin:${HOME}/go/bin:${HOME}/.local/bin:${HOME}/.cargo/bin"

if [[ -f "$REPO_ROOT/.harpoon.env" ]]; then
  set -a
  # shellcheck source=/dev/null
  source "$REPO_ROOT/.harpoon.env"
  set +a
fi

if [[ -x "$REPO_ROOT/.venv/bin/python3" ]]; then
  exec "$REPO_ROOT/.venv/bin/python3" main.py "$@"
fi
exec python3 main.py "$@"
