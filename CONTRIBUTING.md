# Contributing

English is the primary language for code, documentation, release notes and repository metadata.
Keep `README.zh-CN.md` aligned with the English README when installation, behavior, support or
limits change. Detailed references remain in English; attack fixtures retain their original text.
Detection rules cover English and Chinese.

## Setup and checks

Python 3.11 or newer; the development environment uses 3.12.

```bash
uv venv --python 3.12 .venv
uv pip install --python .venv/bin/python -e ".[dev]"
./scripts/check.sh       # ruff, mypy, tests: every change must pass this
./scripts/update.sh      # the checks, then reinstall your own agentdetox and run doctor
```

Native Windows (PowerShell), Python 3.12 and Git for Windows:

```powershell
uv venv --python 3.12 .venv
uv pip install --python .venv\Scripts\python.exe -e ".[dev]"
.\.venv\Scripts\python.exe scripts/check.py
.\.venv\Scripts\python.exe -m agentdetox demo
.\.venv\Scripts\python.exe -X utf8 bench/accuracy_eval.py
.\.venv\Scripts\python.exe -X utf8 -m bench.acceptance_eval
# Checks first, then replaces your uv-installed tool and runs doctor:
.\.venv\Scripts\python.exe scripts/update.py
```

`scripts/check.py` uses its invoking interpreter and stops at the first failed check. The Bash
wrappers remain supported on macOS, Linux and Git Bash. `update.py` creates `.venv` if needed;
without an existing environment, use `uv run --no-project --python 3.12 python scripts/update.py`.
Updates install core dependencies by default; pass `--nli` to retain/install optional NLI support.
That installs dependencies only, not model weights or an inference validation. Neither update
entry point registers or removes hooks. Install hooks separately after isolated verification.

PowerShell starts development commands; protected shell commands are interpreted by Git Bash.
Set `CLAUDE_CODE_GIT_BASH_PATH` if Git for Windows is not in its standard location. WSL tests
do not substitute for native Windows. Shell scripts and frozen fixtures retain LF through
`.gitattributes`. The deep-path test uses Windows extended paths even when `LongPathsEnabled`
is off; ordinary paths beyond MAX_PATH still depend on the host's long-path policy.

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
(`scripts/check_dist.py`). Each also runs `scripts/check_journey.py dist/*.whl`: a fresh wheel
installation outside the checkout, registration and maintenance, real hook subprocesses, review,
whole-version recovery, selective cleanup preserving later edits, a library scan with review,
exact-version dismissal, cleanup and undo, a walk of the shared client corpus (`tests/client_corpus.py`:
files of Claude Code, Codex, Cursor and OpenClaw in default, relocated and nested layouts, found,
cleaned and restored from the command line), and uninstall. `python scripts/client_matrix.py` prints
the whole corpus as a report. The script may download normal package dependencies; it makes no model
calls and does not validate real-client hook delivery. Windows now also gates CI on the demo,
lint, types, tests, both offline galleries, distributions and the installed-wheel lifecycle.
The Windows journey executes registered hooks through Git Bash in paths containing spaces and
Chinese characters and verifies preservation of mixed CRLF/LF content during cleanup.

Usability and detection are separate release gates. The offline gallery reports wrong blocks,
unnecessary questions, prevention and monitoring misses, exact restores and known gaps. Its
`regression_gate_passed` field means no new failure of its contract; acknowledged semantic misses
are included in the report and attack count. It is not a real-world accuracy estimate.

Run `python -m bench.acceptance_eval` for the separately authored frozen cases and cleanup/config
journeys. CI and releases require both galleries. Once a frozen case informs a fix, treat its later
result as regression evidence, not held-out accuracy. Do not change expected labels to pass a gate.
Before release, run `python -m bench.hook_latency --samples 100 --output bench/results/local.json`
on the reference machine. The suite includes post-write and concurrent-hook coverage; machine-specific
latency budgets are recorded separately from CI's deterministic concurrency and cache-reuse tests.

To release:

1. Run the lab (`lab/README.md`) against the release candidate.
2. Set the version in `src/agentdetox/__init__.py`, `plugins/agentdetox/.claude-plugin/plugin.json`
   and `VERSION=` in `plugins/agentdetox/scripts/hook`.
3. Date the version's `CHANGELOG.md` heading (`## [X.Y.Z] - YYYY-MM-DD`) and merge.
4. Publish a GitHub release tagged `vX.Y.Z` for that version. The release workflow checks that the tag, the three
   versions and the dated changelog agree (`scripts/check_release.py`), runs the checks and tests,
   runs the offline detection gallery and the built-wheel lifecycle, attaches the distributions to the release,
   and publishes to PyPI through trusted publishing. Nothing is uploaded if any step fails.

PyPI accepts the upload only from this repository's `release.yml`, running in the `pypi`
environment, as set in the project's trusted-publisher settings on PyPI.

Validate Claude manifests separately: `claude plugin validate .` for the marketplace, then
`claude plugin validate plugins/agentdetox` for the plugin. A root validation alone does not
validate both. Real-model lab runs consume subscription usage and require explicit authorization
and a session cap; local checks and the demo make no model calls.

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
- **Shell commands**: `shell.py` parses recognized writes, wrappers, literal working-directory
  changes and assignments conservatively; it never executes the command. Preserve uncertain paths
  and values as candidates. Post-tool observation covers scoped persistent changes the parser misses.
- **Snapshots, restore, quarantine**: `integrity.py`. Never delete a user's file; move it to
  quarantine. Bump `SCHEMA_VERSION` and handle the old format when the store's layout changes.
  Anything that reads a file and then writes it for the user goes through a `safefs` pin, never
  through the path twice.
- **Library inspection**: `library.py`, with its own `library.sqlite3`. When its layout changes,
  bump `VERSION` and add a step to `_UPGRADES`: additions only, never a rewrite of an existing
  table, because a scan worker of the previous version may still be writing. A scan must not
  take the store lock, store file content, record a checkpoint or report a file as clean, and
  hooks must not import the module. A dismissal must stay bound to one file, content hash and
  detector, and must never reach the allowlist.
- **The ledger**: `ledger.py`. Changes append transactionally; failures reach the fail-open hook boundary and become visible
  health events. Explicit retention may remove old resolved records. Cleanup must keep every
  referenced content object.
- **Session start**: `session.py`. Only high-severity findings may interrupt a session.
- **Messages**: say what changed, why it matters and what to do, in that order, with the id the
  user can allow and `~` paths.

## Rules that do not bend

- Hooks fail open, and the failure shows up in `doctor` and `status`. A write to agent context
  that could not be checked asks instead: never let an error in a check become an allow for the
  thing it checks.
- Nothing leaves the machine; see [PRIVACY.md](PRIVACY.md).
- No rule may cost more than its input's length. A rule is a pattern run over text someone else
  chose; `python -m bench.rule_cost` builds hostile inputs from the rules themselves and fails
  when one grows faster than linearly. Run it after adding or changing a rule.
- The hook path stays fast: no model loading in a hook unless the user chose `ask` for
  contradictions, and no network.
