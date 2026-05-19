#!/usr/bin/env bash
# Bootstrap script for phish-triage on Linux/macOS.
# First run: creates a virtualenv, installs deps, runs the tool.
# Subsequent runs: just runs the tool. Idempotent.
#
# Usage:   ./run.sh tests/fixtures/sample-phish.eml --no-enrich
# Passes all arguments straight through to the phish-triage CLI.

set -euo pipefail

HERE="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$HERE"

VENV="$HERE/.venv"
SENTINEL="$VENV/.phish_triage_installed"

if ! command -v python3 >/dev/null 2>&1; then
    echo "error: python3 is required but not installed." >&2
    echo "  Debian/Ubuntu:  sudo apt install -y python3 python3-venv" >&2
    echo "  macOS:          brew install python" >&2
    exit 1
fi

if [ ! -d "$VENV" ]; then
    echo "[run.sh] creating virtualenv at .venv/ ..."
    if ! python3 -m venv "$VENV" 2>/dev/null; then
        echo "error: 'python3 -m venv' failed. On Debian/Ubuntu run:" >&2
        echo "  sudo apt install -y python3-venv" >&2
        exit 1
    fi
fi

# shellcheck source=/dev/null
source "$VENV/bin/activate"

if [ ! -f "$SENTINEL" ]; then
    echo "[run.sh] installing phish-triage and dependencies (one-time) ..."
    pip install --quiet --upgrade pip
    pip install --quiet -e .
    touch "$SENTINEL"
fi

exec python -m phish_triage "$@"
