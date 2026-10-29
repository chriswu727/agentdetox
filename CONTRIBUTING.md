# Contributing

Code, documentation and release notes are in English. Detection rules cover English and Chinese.

## Setup and checks

Python 3.11 or newer; the development environment uses 3.12.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev,nli]"
./scripts/check.sh       # ruff, mypy, tests: every change must pass this
./scripts/update.sh      # the checks, then reinstall your own agentdetox and run doctor
```

`mypy` covers the hook path's contracts listed in `pyproject.toml`; the rest of the package is not
yet typed strictly. Tests never use your real `~/.agentdetox` or `~/.claude`: fixtures point
`AGENTDETOX_HOME` and `AGENTDETOX_USER_HOME` at temporary folders and unset `CLAUDE_CONFIG_DIR`.

A change to what an agent or user sees (a message, a notice, a decision) should also be tried in a
real agent session. `agentdetox demo` is the quick smoke test of the whole hook path.

## How changes land

- One change per pull request, with `scripts/check.sh` passing.
- A user-visible change gets a line in `CHANGELOG.md` under the unreleased version.
- A design choice someone might later want to undo gets an entry in
  [docs/decisions.md](docs/decisions.md).
- The package version (`src/agentdetox/__init__.py`), the plugin manifest and the version the
  plugin's hook script pins must match; `tests/test_plugin.py` enforces it.

## Continuous integration and releases

CI (`.github/workflows/ci.yml`) runs on every pull request and push to `main`: Ubuntu with Python
3.11 and 3.12, and macOS with 3.12, each installing the package, running `agentdetox demo`,
auditing dependencies, lint, types, the tests, and building and checking the distributions
(`scripts/check_dist.py`). A Windows job runs the demo and the tests without blocking, since
Windows support is still young.

To release:

1. Run the lab (`lab/README.md`) against the release candidate.
2. Set the version in `src/agentdetox/__init__.py`, `plugins/agentdetox/.claude-plugin/plugin.json`
   and `VERSION=` in `plugins/agentdetox/scripts/hook`.
3. Date the version's `CHANGELOG.md` heading (`## [0.3.0] - 2026-11-20`) and merge.
4. Publish a GitHub release tagged `v0.3.0`. The release workflow checks that the tag, the three
   versions and the dated changelog agree (`scripts/check_release.py`), runs the checks and tests,
   smoke-tests the built wheel in a clean environment, attaches the distributions to the release,
   and publishes to PyPI through trusted publishing. Nothing is uploaded if any step fails.

PyPI accepts the upload only from this repository's `release.yml`, running in the `pypi`
environment, as set in the project's trusted-publisher settings on PyPI.

## Where changes belong

See [docs/architecture.md](docs/architecture.md) for how the pieces fit.

- **A new agent**: an adapter in `adapters.py` for its hook protocol, and an `AgentProfile` in
  `context.py` for its files. The engine and policy must not learn agent names.
- **A new check**: `engine.py` returns a `Signal`; `policy.py` decides block, ask or record from
  the user's settings and what the agent can do. Keep the two apart: the engine finds, the policy
  decides.
- **A new rule**: `persistence.py` for what only makes sense as a foothold in an agent (with a
  severity: high blocks, medium asks), `hidden.py` for hidden text and injection phrasing. Every
  rule needs a test with benign text that must not match, and should be run against real memory
  before it ships.
- **Shell commands**: `shell.py` parses them. It does not follow `cd` or expand variables, by design.
- **Snapshots, restore, quarantine**: `integrity.py`. Never delete a user's file; move it to
  quarantine. Bump `SCHEMA_VERSION` and handle the old format when the store's layout changes.
- **The ledger**: `ledger.py`. Entries are only ever appended, recording a change must never raise
  in a hook, and store cleanup must keep every copy an entry refers to.
- **Session start**: `session.py`. Only high-severity findings may interrupt a session.
- **Messages**: say what changed, why it matters and what to do, in that order, with the id the
  user can allow and `~` paths.

## Rules that do not bend

- Hooks fail open, and the failure shows up in `doctor` and `status`.
- Nothing leaves the machine; see [PRIVACY.md](PRIVACY.md).
- The hook path stays fast: no model loading in a hook unless the user chose `ask` for
  contradictions, and no network.
