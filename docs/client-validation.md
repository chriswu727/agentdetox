# Cross-client disinfection validation, 2026-11-10

This validates the unreleased development change built on `928adad`, not the published
0.4.1 package. Claude Code (`claude-fable-5-2`, high effort) implemented it; Codex independently
reviewed it, added adversarial tests and ran the checks below. The
[user guide](user-guide.md#other-agents) describes the workflow and exact coverage.

The common contract is local-file discovery, version-bound review, selected-line cleanup,
residual checks, preservation of other edits, and exact undo. It does not promise that all
poisoning is recognized, or that every client delivers hooks.

| Check | Observed result |
|---|---|
| Full macOS suite, Python 3.12.13 | 1737 passed, 5 skipped, 6 strict expected failures |
| Independently authored disinfection and accuracy tests | 57 passed |
| Ruff / mypy | Passed; 19 source files checked by mypy |
| [Shared client matrix](../bench/results/clients-2026-11-10.json) | 157/157 file workflows passed across 16 default, relocated and nested layouts; no cleanup refused |
| [Installed wheel journey](../bench/results/journey-clients-2026-11-10.json) | 8/8 steps passed, including 14 cross-client layout/case pairs |
| Wheel and source distribution | Built; strict Twine and distribution-content checks passed |
| [Frozen regression gallery](../bench/results/accuracy-clients-2026-11-10.json) | 45 cases, same decisions as the previous baseline; 2 known misses; no wrong block; 45 exact restores |
| [Frozen acceptance gallery](../bench/results/acceptance-clients-2026-11-10.json) | 21 cases, unchanged fixture and decisions; 3 known misses; no wrong block; cleanup/config gates passed |

The six expected failures are four semantic misses and two false alarms in the new corpus,
not successful detections. The misses cover redirected push destinations, deception, following
remote instructions and invented facts. The false alarms are a list under one prohibition
and a prohibition wrapped across lines in a skill. These small authored fixtures are not an
estimate of real-world accuracy. Their labels and the older frozen fixtures were not relaxed.

## Native clients

- **Claude Code 2.1.318:** two real `claude-fable-5-2` sessions passed
  ([archived results](../lab/results/run-20261110T175656363758Z-9f311b9e.json)). External
  tampering was reported, the planted action did not execute, and the user task completed.
  A benign safety instruction was written without an alert or interruption. These used model
  inference and are a focused check, not a comprehensive attack evaluation.
- **Codex CLI 0.167.0-alpha.3.2:** seven native cases passed
  ([summary](../lab/results/codex-contract-2026-11-10.json),
  [harness](../lab/codex_contract.py)). They cover benign and hostile patches, moves, a Unicode
  context fallback, shell observation and cleanup, a benign model setting edit, and hook deletion.
  After cleanup, a fresh native session loaded the cleaned file; undo restored exact bytes.
  Responses came from a deterministic loopback server: **zero model inference calls**.
  The isolated fixture bypasses hook trust, and its two fixed config cases disable the native
  sandbox to test AgentDetox's own decision. Installer/trust UI and model behavior are untested.
- **Cursor:** file workflows and synthetic/documented event shapes only. No Cursor application
  or CLI was available for native execution; the hook integration remains experimental.
- **OpenClaw:** file workflows only. There is no native plugin to intercept its writes.

## Performance

On the development Mac, all **12 original budgets passed**, with 100 samples per case
([complete measurements](../bench/results/hooks-clients-2026-11-10.json)). No builds, test
suites or other benchmarks ran alongside the measurement.

| Case | P95 ms | Budget ms |
|---|---:|---:|
| Ordinary Bash before/after pair | 118.4 | 200 |
| Session start, 1000 unchanged files | 125.5 | 250 |
| Session start, 100 changed of 1000 files, 10k history entries | 180.2 | 1000 |
| Bash pair, 1000 active and 1000 unrelated memory files | 219.5 | 350 |
| Four protected writes plus Bash pair | 261.0 | 1000 |

These timings include hook subprocesses, not complete client startup or NLI inference. They
are not a paired comparison against an earlier build. The existing
[Windows latency failures](../bench/HOOK_LATENCY.md#windows-filesystem-and-import-follow-up-2026-11-09)
remain unresolved by these Mac measurements.

## Remaining boundaries

Cleanup removes selected lines; it does not reconstruct overwritten text or selectively edit
executable configuration. A file without earlier history can be cleaned, but cannot be restored
to a version AgentDetox never recorded. Start a new affected-client session after cleanup:
content already loaded into a running session is not removed from that session.

Codex SQLite memory state, Claude `@path` imports and `autoMemoryDirectory`, and OpenClaw
`$include` files remain outside this file-disinfection contract. Coverage output exposes
unresolved roots and unreadable files; those make the scan or inspection exit non-zero.
See the [integration matrix](user-guide.md#other-agents) for the full per-client boundaries.
