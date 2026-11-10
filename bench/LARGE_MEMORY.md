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

## End-to-end library harness

On development `main`, `agentdetox library` implements the file inventory described below.
A second harness drives it through the library module, in one process and a temporary store:

```bash
.venv/bin/python -m bench.library_eval --files 1000 --output /tmp/library-1000.json
.venv/bin/python -m bench.library_eval --files 10000 --minimum-bytes 4096 --output /tmp/library-10000.json
.venv/bin/python -m bench.library_eval --files 100000 --minimum-bytes 4096 --output /tmp/library-100000.json
```

It reuses the generator above and adds files that must not be inspected (over 1 MB, not
UTF-8, another extension, symbolic links). It then runs, in order: a first full scan; an
unchanged incremental scan; an incremental scan after 1% of files were appended to; a scan
with unreadable and deleted files; a full scan cancelled half-way; and its resumption. Each
phase records elapsed and CPU seconds, rule scans actually run, coverage counts and peak RSS;
the report adds a hash of the corpus as first written (relative paths and content, independent
of location and time), the inventory size per file, the bytes of content copied into the store
(which must be zero), per-family outcomes and the retained unsupported-fact misses. Its checks are contracts,
not budgets: the unchanged run executes no rule scan, the changed run rescans exactly the
changed files, unreadable files are failed and deleted ones missing, and the cancelled run is
continued to full coverage rather than restarted.

It does **not** measure hooks while a scan runs, the detached worker, process kills (covered
by tests, not timed), cleanup, real libraries or any false-positive rate, and it runs on one
filesystem. The full 100k tier has not been run.

On 2026-11-10, runtime `eae840a` passed all seven harness contracts in separate processes on
the development Mac, without concurrent tests or benchmarks. Raw reports retain CPU time,
corpus hashes, coverage and known misses: [1k](results/library-1000-2026-11-10.json) and
[10k](results/library-10000-2026-11-10.json).

| Files | Note bytes | First inspection | Unchanged incremental | 1% changed | Peak RSS | Inventory |
|---|---:|---:|---:|---:|---:|---:|
| 1,000 | 1,088,690 | 0.829 s | 0.043 s | 0.050 s | 28.6 MB | 0.44 MB |
| 10,000 | 41,880,640 | 30.491 s | 0.909 s | 0.771 s | 39.0 MB | 3.81 MB |

These are single runs, not latency distributions; elapsed times vary with filesystem caching
and scheduling. The unchanged runs hash every candidate but execute zero rule scans; the
changed runs inspect exactly 10 and 100 changed files. Neither run copies content into the
store. Injected cancellation is acknowledged in 1.29 ms and 0.45 ms, respectively, and both
resume to complete coverage. Those cancellation times measure the harness callback, not CLI
startup or a user command round trip. The 50 and 500 seeded unsupported-fact cases remain
explicit known semantic misses. This is inventory evidence, not a real-world accuracy estimate.

### Hook latency during inspection

```bash
.venv/bin/python -m bench.hook_latency --samples 100 --output /tmp/hooks-library-idle.json
.venv/bin/python -m bench.library_hook_latency --samples 100 --files 100000 --minimum-bytes 4096 --output /tmp/hooks-library-active.json
```

The load harness calls the original hook benchmark with its original cases and budgets. It
starts a full library scan in a separate process using the same store as the hooks, then checks
that the same scan remains in inspection and makes progress throughout the measurement. It
stops its worker before deleting the temporary corpus. A completed or failed worker invalidates
the load measurement. NLI inference is excluded, as in the original hook benchmark.

Runtime `eae840a` passed all 12 original budgets with 100 samples per case both
[idle](results/hooks-library-idle-2026-11-10.json) and
[during a scan](results/hooks-library-active-2026-11-10.json). The single scan used 100,000
synthetic files (418,827,640 bytes), advancing from 0 to 48,600 verified files while the hooks
ran. It was then cancelled normally. This proves a continuously active inspection load for
this measurement; it is **not** a completed 100k inspection or a production-scale claim.

| Hook case | Idle P95 | During scan P95 | Original budget |
|---|---:|---:|---:|
| Bash pre + post, no context write | 110.1 ms | 112.6 ms | 200 ms |
| Four protected writes plus Bash pre/post | 258.9 ms | 306.4 ms | 1,000 ms |
| SessionStart, 1,000 unchanged files | 123.1 ms | 135.4 ms | 250 ms |
| Bash pre + post, 1,000 active plus 1,000 unrelated memory files | 217.0 ms | 227.2 ms | 350 ms |

The two conditions ran sequentially on one Mac; they are not a randomized multi-host trial.
All per-case samples, original budgets and worker-progress evidence are in the reports.

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
