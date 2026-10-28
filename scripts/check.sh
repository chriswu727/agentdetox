#!/usr/bin/env bash
# The checks every change must pass before it merges: lint, type checks on the hook
# path's contracts (listed in pyproject.toml), and the tests.
set -euo pipefail
cd "$(dirname "$0")/.."

.venv/bin/ruff check src tests bench scripts
.venv/bin/mypy
.venv/bin/pytest -q -p no:warnings
