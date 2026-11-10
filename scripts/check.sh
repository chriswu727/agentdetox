#!/usr/bin/env bash
# The checks every change must pass before it merges: lint, type checks on the hook
# path's contracts (listed in pyproject.toml), and the tests.
set -euo pipefail
cd "$(dirname "$0")/.."

python=.venv/bin/python
if [ -f .venv/Scripts/python.exe ]; then
  python=.venv/Scripts/python.exe
fi
exec "$python" scripts/check.py "$@"
