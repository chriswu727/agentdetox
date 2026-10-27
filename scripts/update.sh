#!/usr/bin/env bash
# Run the tests, then update the agentdetox that installed agent hooks call.
# Hooks pick up the new build on their next call; a broken build would make every
# agent tool call report a hook error, hence the tests first.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x .venv/bin/pytest ]; then
  echo "creating development environment in .venv"
  uv venv --quiet --python 3.12 .venv
  uv pip install --quiet --python .venv/bin/python -e ".[dev]"
fi

.venv/bin/pytest -q -p no:warnings
uv tool install --quiet --reinstall --python 3.12 .
"$(uv tool dir --bin)/agentdetox" doctor
