# Native Windows development validation, 2026-11-09

This is a native Windows run, not WSL and not a reinterpretation of the November 5 macOS
results. The checkout was freshly cloned to `C:\src\agentdetox`; fetch confirmed main at
`f2165e6` before the changes on `windows-development`. No existing checkout or Mac `uv.lock`
was overwritten. No model dependencies or weights were installed.

## Host and tools

- Windows 11 Pro x64, build 26200; PowerShell 7.6.5.
- AMD Ryzen 9 9900X3D, 12 cores / 24 threads; about 32 GiB installed RAM.
- Initial C: free space about 123 GiB; about 16 GiB RAM available.
- Git for Windows 2.55.0 (`C:\Program Files\Git\cmd\git.exe`), Git Bash 5.3.15
  (`C:\Program Files\Git\bin\bash.exe`), uv 0.13.6, CPython 3.12.16 managed by uv.
- Development interpreter: `C:\src\agentdetox\.venv\Scripts\python.exe`.
- Independent Claude CLI 2.1.317 installed through WinGet; the existing desktop Code
  process uses 2.1.321. Both independently launched executables reported no CLI login.
  The running desktop session was separately confirmed as `entrypoint=claude-desktop`;
  its login/session was neither removed nor reused by extracting credentials.

## Completed offline checks

- `scripts/check.py`: ruff and mypy pass; **875 passed, 31 skipped** on native Windows.
  Existing OS-specific/NLI skips remain; no new skip or relaxed assertion was added.
  A first CI run then exposed the other platform's `msvcrt` type-stub restriction on Linux/macOS;
  both optional lock modules now use runtime imports. Native, `--platform linux` and
  `--platform darwin` mypy checks pass; the failed CI run remains in GitHub history.
- `agentdetox demo`, dependency audit, release-version consistency, and both Claude manifest
  validations pass. Claude's plugin-directory advisory reports a missing optional catalog icon;
  manifest validation itself succeeds.
- Wheel and sdist build, strict twine check, and distribution contents check pass. These are
  local candidate 0.4.1 artifacts, not a new publication or a replacement of published 0.4.1.
- [45-case gallery](../bench/results/accuracy-windows-2026-11-09.json): gate passes, 45 exact
  restores, 16 benign/explicit-consent controls with no false block/question/finding. Two
  declared semantic misses remain.
- [Frozen 21-case gallery](../bench/results/acceptance-windows-2026-11-09.json): gate passes,
  21 exact restores, eight benign controls quiet, ten supported attacks meet prevention and
  monitoring expectations, three declared semantic misses remain. Cleanup/config journeys pass.
  Fixture SHA-256 remains `139150fbd834a3a6465fefc79575f51a0d41079d86826111ec42735e7fbfa2cc`,
  identical to the committed fixture and November 5 report. This is regression evidence,
  not real-world accuracy or comprehensive protection.
- [Built-wheel lifecycle](../bench/results/journey-windows-final-2026-11-09.json): new environment
  outside the checkout, spaces and Chinese characters in paths, preview/install/mixed-hook
  upgrade/reinstall/doctor, registered commands through Git Bash, plugin shell forwarding,
  quiet benign use, denied attack, external detection, review, stale refusal, byte-exact recovery,
  selective cleanup preserving mixed CRLF/LF and later edits, and uninstall preserving other hooks.
- [Update lifecycle](../bench/results/update-windows-2026-11-09.json): downloaded published
  0.4.1 through `uv tool install`, registered isolated hooks, ran the complete checks before
  reinstalling this checkout with `update.py`, verified unchanged registration and healthy doctor,
  then uninstalled without losing another user's hook/settings. Temporary homes/stores were used.

## Failures retained and what changed

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

## Real Claude usage and remaining limits

The prior authorization was 20 real acceptance sessions, with 13 already used on November 5
according to the retained lab reports and their accounting in `lab/README.md`. This Windows
work has used **0 acceptance sessions**, leaving **7**. CLI version/help/auth/manifest commands
make no model calls. Independent Claude review has also used 0 sessions.

Real Windows acceptance and independent Claude review are pending a login usable by the
standalone CLI. A desktop login was confirmed, but does not by itself make the lab's independent
CLI authenticated. Once available, run the five selected scenarios with an explicit cap:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m lab.run remember edit-instructions safety-guidance postinstall-tamper long-context-write --arms agentdetox --jobs 1 --max-sessions 5 --keep
```

Reserve the remaining two sessions for diagnosed failures; do not silently reset the budget.
Guardrail results, hook errors, history and user task completion must be reported separately.
The isolated wheel tests do not establish real-client delivery or sustained everyday usability.

Windows shell analysis covers Git Bash, including `/c/...` paths and `.exe` names. PowerShell and
cmd.exe write syntax is not supported. Windows NLI still uses background workers rather than a
resident Unix-socket service; no real NLI inference was validated. Existing semantic gaps remain.
Absolute macOS latency budgets are not Windows guarantees; native measurements are recorded
separately in [HOOK_LATENCY.md](../bench/HOOK_LATENCY.md).
The initial native suite passes 5/12 budgets and fails 7/12, with all concurrency evidence
assertions passing. An alternating 100-sample-per-version startup comparison also exceeds the
100 ms budget on both old main and the candidate (P95 193.0 / 188.4 ms). Performance work remains;
these results do not turn the migration into a completed Windows performance acceptance.

## Delivery state

[PR #46](https://github.com/chriswu727/agentdetox/pull/46) is a draft while real-client
acceptance and the latency limits above remain unresolved. No release was made. The host's
existing real settings, login and AgentDetox history were not replaced with Mac data, and all
hook registration/uninstallation checks so far used isolated homes and stores.
