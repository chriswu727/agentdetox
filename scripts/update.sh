#!/usr/bin/env bash
# Run the checks, then update the agentdetox that installed agent hooks call.
# Hooks pick up the new build on their next call; a broken build would make every
# agent tool call report a hook error, hence the tests first.
set -euo pipefail
cd "$(dirname "$0")/.."

# uv supplies Python when the checkout has no development environment yet.
exec uv run --no-project --python 3.12 python scripts/update.py "$@"
