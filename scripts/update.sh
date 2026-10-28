#!/usr/bin/env bash
# Run the checks, then update the agentdetox that installed agent hooks call.
# Hooks pick up the new build on their next call; a broken build would make every
# agent tool call report a hook error, hence the tests first.
set -euo pipefail
cd "$(dirname "$0")/.."

if [ ! -x .venv/bin/pytest ]; then
  echo "creating development environment in .venv"
  uv venv --quiet --python 3.12 .venv
  uv pip install --quiet --python .venv/bin/python -e ".[dev,nli]"
fi

scripts/check.sh
uv tool install --quiet --reinstall --python 3.12 ".[nli]"
bin="$(uv tool dir --bin)/agentdetox"
# A model server still running the old build would otherwise serve until its next job.
"$bin" daemon stop >/dev/null || true
"$bin" doctor
