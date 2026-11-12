# Native Windows validation

## Current status

For 0.6.0, on one real Windows machine: the full development check, which found that `clean`,
`restore` and quarantine failed for a file in a folder deep enough to pass 260 characters
(fixed in 0.6.0); the optional model check with real model calls; and the message for a
command-line client that is not logged in (on Windows the `claude` command has its own login,
apart from the desktop app's, and `doctor` says so). See the
[changelog](../CHANGELOG.md) and the user guide's
[model check section](user-guide.md#a-models-reading-of-each-write-optional).

What is still open on Windows:

- Hook latency is over budget in 7 of 12 cases, as last measured on 2026-11-09
  ([HOOK_LATENCY.md](../bench/HOOK_LATENCY.md#complete-follow-up-suite)).
- Applying a library cleanup (`clean M<ID>`) is refused, because the file's folder cannot be
  held open; the preview works.
- Shell analysis covers Git Bash (`/c/...` paths, `.exe` names), not PowerShell or cmd.exe.
- Contradiction checks use background workers, not a resident model server; no real NLI
  inference has been validated on Windows.
- Ordinary paths beyond 260 characters depend on the host's long-path setting.

## History: validation before 0.5.0

A dated log from 2026-11-09, on the development branch that led to 0.5.0. Failures are kept.

### Phase 1 CI follow-up

The [CI run for runtime 6339eef](https://github.com/chriswu727/agentdetox/actions/runs/42769544127)
passed both Linux jobs and macOS, but Windows reported `StoreLocked` in the existing
`test_concurrent_writers_do_not_lose_entries`: one failure, 983 passes and 39 skips.
The eight-process test, lock timeout, snapshot implementation and store implementation were
unchanged from `de3aefc`. This failed invocation remains evidence; no timeout or assertion was
relaxed.

A native reproduction attempt from an isolated source archive could not start: the existing
virtual environment's Python launcher reported a missing child interpreter, and `uv python
find` rejected a managed-runtime mount point. No native test result was obtained from it. The
earlier native measurements below are historical results.

### Earlier native run

This is a native Windows run, not WSL and not a reinterpretation of the November 5 macOS
results. The checkout was freshly cloned; fetch confirmed main at `f2165e6` before the changes
on `windows-development`. No model dependencies or weights were installed.

### Host and tools

- Windows 11 Pro x64, build 26200; PowerShell 7.6.5.
- AMD Ryzen 9 9900X3D, 12 cores / 24 threads; about 32 GiB installed RAM.
- Initial C: free space about 123 GiB; about 16 GiB RAM available.
- Git for Windows 2.55.0, Git Bash 5.3.15, uv 0.13.6, CPython 3.12.16 managed by uv.
- The candidate CLI was installed through `uv tool`. This package installation did not
  register real user hooks.
- Independent Claude CLI 2.1.317 installed through WinGet; the desktop app used 2.1.321. The
  separately launched CLI reported no login; the desktop app's login does not carry over.

### Completed offline checks

- `scripts/check.py`: ruff and mypy pass; **875 passed, 31 skipped** on native Windows.
  Existing OS-specific/NLI skips remain; no new skip or relaxed assertion was added.
  A first CI run then exposed the other platform's `msvcrt` type-stub restriction on Linux/macOS;
  both optional lock modules now use runtime imports. Native, `--platform linux` and
  `--platform darwin` mypy checks pass; the failed CI run remains in GitHub history.
- `agentdetox demo`, dependency audit, release-version consistency, and both Claude manifest
  validations pass. Claude's plugin-directory advisory reports a missing optional catalog icon;
  manifest validation itself succeeds.
- Wheel and sdist build, strict twine check, and distribution contents check pass. These were
  local candidate artifacts, not a publication.
- [45-case gallery](../bench/results/accuracy-windows-2026-11-09.json): gate passes, 45 exact
  restores, 16 benign/explicit-consent controls with no false block/question/finding. Two
  declared semantic misses remain.
- [Frozen 21-case gallery](../bench/results/acceptance-windows-2026-11-09.json): gate passes,
  21 exact restores, eight benign controls quiet, ten supported attacks meet prevention and
  monitoring expectations, three declared semantic misses remain. Cleanup/config journeys pass.
  Fixture SHA-256 remains `139150fbd834a3a6465fefc79575f51a0d41079d86826111ec42735e7fbfa2cc`,
  identical to the committed fixture and November 5 report. This is regression evidence,
  not real-world accuracy or comprehensive protection.
- [Built-wheel lifecycle after the final runtime fix](../bench/results/journey-windows-runtime-2026-11-09.json): new environment
  outside the checkout, spaces and Chinese characters in paths, preview/install/mixed-hook
  upgrade/reinstall/doctor, registered commands through Git Bash, plugin shell forwarding,
  quiet benign use, denied attack, external detection, review, stale refusal, byte-exact recovery,
  selective cleanup preserving mixed CRLF/LF and later edits, and uninstall preserving other hooks.
- [Update lifecycle](../bench/results/update-windows-2026-11-09.json): downloaded published
  0.4.1 through `uv tool install`, registered isolated hooks, ran the complete checks before
  reinstalling this checkout with `update.py`, verified unchanged registration and healthy doctor,
  then uninstalled without losing another user's hook/settings. Temporary homes/stores were used.

### Failures retained and what changed

The first test run had 870 passed, 31 skipped and one failure: the host has
`LongPathsEnabled=0`, so a >260-character fixture could not be created. The same deep path is
now tested using Windows' extended-path prefix, including actual recovery and quarantine
assertions. No system registry change was made. Ordinary long paths still depend on host policy.

The first gallery runs ([45 cases](../bench/results/accuracy-windows-initial-2026-11-09.json),
[21 cases](../bench/results/acceptance-windows-initial-2026-11-09.json)) failed exact-byte checks:
`write_text` converted LF fixtures to CRLF, while the oracles compared to LF bytes. The harness
now writes its intended exact baseline bytes. Frozen case content and labels were not changed.
Git's `core.autocrlf=true` had also converted the frozen JSON on checkout; `.gitattributes` now
preserves its original committed bytes/hash, as well as executable shell scripts' LF endings.

The [first wheel journey](../bench/results/journey-windows-initial-2026-11-09.json) failed its
import-location assertion because `python -I` ignores `PYTHONUTF8`, corrupting a Chinese path
on stdout. Explicit `-X utf8` fixes the probe. The [second journey](../bench/results/journey-windows-second-2026-11-09.json)
then exposed an LF-only cleanup oracle; it now checks removal of the original native newline
bytes while requiring every other byte to remain unchanged. Both failures remain published.

A newly added archive regression test caught same-timestamp collisions on Windows. Unique ids
now supplement UTC timestamps; earlier failed lab attempts cannot be overwritten by reruns.

### Performance follow-up

The first bounded optimization avoids repeatedly attempting to create existing store
directories, while still repairing their permissions; delays optional NLI transport imports;
and hashes/scans one captured read during checkpoint verification. Unchanged files are not
decoded or reopened by that comparison. Full content reads and commit-time version checks
remain in place; no daemon, metadata-only trust cache, budget change, or detector change was added.

Native checks after the runtime changes: ruff and mypy pass; **882 tests pass, 31 existing
skips**. Seven new cases cover deferred imports with actual hook decisions, same-size and
same-timestamp tampering with LF/CRLF/CR, and a file changing after the first verification read.
The last case fails against `647c081` for an existing checkpoint and passes with this fix:
the old second read can match the checkpoint after the first read already observed an attack.
Initial new hook tests omitted the temporary user-home override; review caught that isolation
error, the override was added, and all 14 entry-point/read-verification tests passed again.
Those initial runs are excluded from claims about isolated user-home validation.
The shared autouse fixture now also sets a temporary user home for every test by default;
the complete `scripts/check.py` rerun with that safeguard passes ruff, mypy and **882 tests,
31 existing skips**. Explicit per-test homes can still override this safe default.

The [paired performance report](../bench/results/hooks-windows-io-paired-2026-11-09.json)
records ordinary Bash pre P95 199.2 → 187.1 ms and the 1000-active-file Bash pair
778.8 → 645.8 ms. Both remain above their unchanged budgets. See
[measurement details](../bench/HOOK_LATENCY.md) for the comparison method and limits.

[CI for runtime commit 4ed9336](https://github.com/chriswu727/agentdetox/actions/runs/42738843259)
passes all four jobs: native Windows, macOS Python 3.12, Linux Python 3.11 and 3.12, including
offline galleries and installed-wheel lifecycle checks.

The complete local [100-sample rerun](../bench/results/hooks-windows-io-2026-11-09.json)
still passes 5/12 budgets and fails 7/12. Concurrent evidence/health assertions pass. The
full table and all 1,200 samples are retained; no thresholds or budgets were relaxed.

The same runtime also passes the local demo, the [45-case gallery](../bench/results/accuracy-windows-io-2026-11-09.json),
the [frozen 21-case gallery](../bench/results/acceptance-windows-io-2026-11-09.json),
and [installed-wheel lifecycle](../bench/results/journey-windows-io-2026-11-09.json), including
real registered Git Bash commands, plugin forwarding, recovery and selective cleanup.
Known semantic misses remain; all 45 and 21 restores are byte-exact and the frozen fixture
hash is unchanged. Wheel/sdist build, strict twine checks and distribution-content checks pass.
The wheel SHA-256 is `496a32254ef7c361b0db3879972190210fadcdfbc362f3762dcbd3e6c47dc41c`.
The host's installed candidate CLI was updated from this wheel with the existing NumPy
2.5.4 constraint; only AgentDetox was reinstalled. No real user hooks were registered.
The installed executable's demo passes, and all 38 installed Python source files match both
the checked wheel and this checkout byte-for-byte.

### Limits recorded then

The isolated wheel tests did not establish real-client delivery or sustained everyday
usability. Absolute macOS latency budgets are not Windows guarantees; native measurements are
recorded separately in [HOOK_LATENCY.md](../bench/HOOK_LATENCY.md). The initial native suite
passed 5/12 budgets and failed 7/12, with all concurrency evidence assertions passing. An
alternating 100-sample-per-version startup comparison also exceeded the 100 ms budget on both
old main and the candidate (P95 193.0 / 188.4 ms). All hook registration and uninstallation
checks used isolated homes and stores.
