# Large memory stores: baseline and acceptance protocol

This is a development protocol, not a claim that AgentDetox already supports production
libraries of 100,000 files. The published release remains 0.4.1. A large existing library
needs inspection as well as change tracking: its first snapshot establishes an integrity
baseline, not a clean-content verdict.

## Reproducible baseline

```bash
.venv/bin/python -m bench.large_memory_eval --files 1000 --output /tmp/scale-1000.json
.venv/bin/python -m bench.large_memory_eval --files 10000 --minimum-bytes 4096 --output /tmp/scale-10000.json
.venv/bin/python -m bench.large_memory_eval --files 100000 --minimum-bytes 4096 --output /tmp/scale-100000.json
```

The generator creates temporary UTF-8 Markdown files in ten project scopes by default,
with one active project, English and Chinese notes, known rule attacks, benign near-matches,
and a plausible unsupported fact that remains an explicit known miss. It deletes only its
temporary corpus. The report retains corpus hashes, file counts, bytes, largest file,
active/unrelated counts, per-family outcomes, generation/scan time, per-file latency and
process peak RSS where available. RSS includes the interpreter and fixture generation.
Run tiers in separate processes without concurrent tests or other benchmarks. Repetition
of authored templates does not measure a real-world false-positive rate.

This baseline calls the existing rule scanner one file at a time. It does **not** exercise
hooks, source attribution, the dense NLI candidate matrix, a background scan scheduler,
checkpoint changes, resumability or large-store recovery. Passing it cannot establish those
capabilities. The existing hook budgets and frozen accuracy galleries remain separate gates.

## Product acceptance, before claiming scale support

The first Mac baseline on runtime `6339eef` is retained in the
[1k report](results/scale-1000-2026-11-09.json) and
[10k report](results/scale-10000-2026-11-09.json). Both regression gates pass; their 50 and 500
seeded unsupported-fact cases remain known misses. The 100k tier has not been measured.

| Files | Total bytes | Full rule scan | Process peak RSS |
|---|---:|---:|---:|
| 1,000 | 1,088,690 | 0.80 s | 22.5 MB |
| 10,000 | 41,880,640 | 29.67 s | 25.2 MB |

These are small-file, repeated-template fixtures on a shared development host, with no NLI or
cleanup. The reports record exact sizes, corpus hashes and family results. They establish a
reproducible starting point; production support still requires the following work.

- Test 1k, 10k and 100k files with byte distributions, long individual files, many statements,
  duplicate notes, many unrelated projects, and English/Chinese controls. Record disk usage,
  peak RSS, CPU time, throughput and cancellation latency, not just elapsed time.
- Initial inventory must report inspected, suspicious, uninspected and failed counts. Keep
  existing risky content reviewable. Do not convert an initial snapshot or scan failure into
  a clean verdict; do not flood the user with one startup interruption per historical file.
- Run full inspection in bounded background batches with progress and cancellation. Resume
  after interruption, distinguish queued/running/failed/stale results, and bind results to
  content hashes. Incremental work must rescan changed bytes and reconcile deletions; file
  timestamps alone are insufficient. Measure ordinary hooks while this work runs.
- Evaluate write prevention, existing-content detection and reviewed cleanup separately.
  Include split instructions, diluted and paraphrased copies, poisoned consolidation,
  delayed use, benign security guidance, and duplicates hiding contradiction candidates.
  Keep tuning data separate from frozen held-out cases and report semantic misses.
- Preview selected changes, preserve unrelated and newer edits, quarantine originals, verify
  exact results, and rescan residual content. Refuse stale or ambiguous selections. Keep the
  current cleanup size limit until a separately validated large-file strategy exists. Do not
  automatically delete inferred descendants or claim already-loaded agent context was erased.
- Database and vector-store adapters need their own stable IDs, version guards, permissions,
  pagination, deletion and recovery tests; file scanning does not establish adapter support.

## Maintainer observation

Start local observation after the candidate is installed and passes the fresh-wheel journey.
Use the existing local status, doctor, review and event records. Keep a private daily record
of the commit, qualifying active sessions, completed tasks, hook errors, reviewed wrong blocks
and unnecessary questions, recovery outcomes and noteworthy delays. Mark unreviewed alerts
as unknown rather than false positives. Do not publish file paths, source excerpts, transcripts,
credentials or raw event logs. Publish only manually reviewed aggregate counts.

Thirty qualifying active days is a proposed stability gate, not elapsed calendar time or an
achieved result. Installation-only and automated test days do not qualify. A reliable product
claim also needs retained failures and independent real-client acceptance; synthetic scale
measurements cannot substitute for daily use.
