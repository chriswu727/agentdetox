# Hook latency

Latest recorded suite: [0.4.1 release candidate, 2026-11-05](#041-release-candidate-2026-11-05). These are dated reference measurements, not timings of
every later commit or of a full Claude plugin launch. They exclude `uvx` startup and downloads.

Run `python -m bench.hook_latency --samples 100 --output bench/results/local.json`.
No model, network, or subscription calls are made. Each timing includes a fresh Python process,
CLI parsing and hook execution. Each case has one untimed warmup; P95 uses the nearest-rank
method. File changes are prepared outside timed sections. The 100-changed-file case begins with
10,000 entries and accumulates another 100 records per sample.

Measured on macOS 15.7.4 ARM64, Python 3.12.13, on 2026-10-30. Results are machine-specific,
not a cross-platform latency guarantee. The raw report is [results/hooks-2026-10-30.json](results/hooks-2026-10-30.json).

| Case | Samples | P50 | P95 | Budget |
|---|---:|---:|---:|---:|
| Ordinary Bash pre-check | 100 | 63.1 ms | 78.0 ms | 100 ms |
| Protected Edit, 50k history entries | 100 | 62.5 ms | 73.5 ms | 120 ms |
| Protected Write, 3,889,915-byte transcript | 100 | 145.8 ms | 155.8 ms | 200 ms |
| Session start, 1,000 unchanged files | 100 | 178.1 ms | 209.3 ms | 250 ms |
| Session start, 100 changed / 1,000 files, initially 10k entries | 100 | 229.5 ms | 260.5 ms | 1,000 ms |

All five measured P95 budgets passed. These cases exclude optional NLI inference and initial legacy
migration. Ordinary hooks no longer import NumPy; file history lookup uses SQLite's path index.

## Development baseline: shell observation, 2026-10-30

That development checkout measured Bash pre-checks with fresh agent tool-use ids and the
complete pre/post pair. The active-memory stress case has 1,000 files belonging to
the current project plus 1,000 unrelated files, exercising the scope boundary. Each case has 100
samples and one untimed warmup, with NLI disabled. Raw report:
[results/hooks-self-use-2026-10-30.json](results/hooks-self-use-2026-10-30.json).

| Case | P50 | P95 | Budget |
|---|---:|---:|---:|
| Ordinary Bash pre-check with observation capture | 59.1 ms | 63.8 ms | 100 ms |
| Ordinary Bash pre + post | 118.6 ms | 120.6 ms | 200 ms |
| Protected Edit, 50k history entries | 59.3 ms | 60.8 ms | 120 ms |
| Protected Write, 3,889,915-byte transcript | 143.0 ms | 146.9 ms | 200 ms |
| Session start, 1,000 unchanged files | 174.2 ms | 187.4 ms | 250 ms |
| Session start, 100 changed / 1,000 files, initially 10k entries | 219.7 ms | 227.5 ms | 1,000 ms |
| Bash pre + post, 1,000 active memory files and 1,000 unrelated | 223.5 ms | 237.9 ms | 350 ms |

All seven measured P95 budgets passed. The two full-pair budgets are new and include two Python
processes, durable start-state capture, scoped content reads and the end comparison. These are
reference-machine measurements; the older five-case 0.3.0 report remains a separate baseline.

## 0.4.0 release candidate, 2026-11-01

100 samples per case, same machine and method, NLI off. Raw report:
[results/hooks-2026-11-01.json](results/hooks-2026-11-01.json). Session start no longer re-stores
files whose trusted version is unchanged (their stored copies are verified in full by the daily
cleanup instead), so it is faster than in 0.3.0 despite watching more files and re-checking each
version before trusting it. The shell check parses more forms at no measurable cost.

| Case | P50 | P95 | Budget |
|---|---:|---:|---:|
| Bash pre-check | 58.5 ms | 61.9 ms | 100 ms |
| Bash pre + post | 117.6 ms | 126.3 ms | 200 ms |
| Protected Edit, 50k history entries | 58.5 ms | 60.0 ms | 120 ms |
| Protected Write, 3,889,915-byte transcript | 141.2 ms | 145.5 ms | 200 ms |
| Session start, 1,000 unchanged files | 133.9 ms | 139.2 ms | 250 ms |
| Session start, 100 changed / 1,000 files, initially 10k entries | 187.7 ms | 215.1 ms | 1,000 ms |
| Bash pre + post, 1,000 active memory files and 1,000 unrelated | 239.6 ms | 287.4 ms | 350 ms |

## 0.4.1 release candidate, 2026-11-05

100 samples per case on macOS 15.7.4 ARM64, Python 3.12.13, with one untimed warmup.
All twelve measured P95 budgets passed. Raw report:
[results/hooks-2026-11-05.json](results/hooks-2026-11-05.json).

| Case | P50 | P95 | Budget |
|---|---:|---:|---:|
| Bash pre, no context write | 61.7 ms | 77.1 ms | 100 ms |
| Bash pre + post, no context write | 122.7 ms | 145.6 ms | 200 ms |
| Protected Edit pre, 50k history entries | 63.3 ms | 80.8 ms | 120 ms |
| Protected Write pre, 3889915 byte transcript | 68.5 ms | 90.1 ms | 200 ms |
| Protected Write post, 100 added lines, 3889915 byte transcript | 86.6 ms | 95.3 ms | 500 ms |
| Protected Write pre, 29 distinct large source outputs | 106.7 ms | 115.9 ms | 200 ms |
| Protected Write post, 100 added lines, 29 distinct large source outputs | 159.0 ms | 170.8 ms | 500 ms |
| Four protected Write posts plus Bash pre/post, 100 lines per write | 305.5 ms | 491.0 ms | 1000 ms |
| SessionStart, 1000 unchanged files | 136.0 ms | 151.8 ms | 250 ms |
| SessionStart, 100 changed of 1000 files, initially 10k history entries | 186.8 ms | 200.1 ms | 1000 ms |
| Bash pre + post, 1000 active memory files plus 1000 unrelated files | 224.0 ms | 251.1 ms | 350 ms |
| NLI record frontend, 1000 active memory files, fake queue, no inference | 76.2 ms | 78.3 ms | 250 ms |

The large-transcript cases exercise both repeated logs and 29 distinct large source outputs.
The post-write cases add 100 lines, exercising attribution across the whole addition. The
concurrency case runs four post-write processes alongside a Bash pre/post pair and also requires
all four changes to be recorded, with no hook errors or lost shell observation. Unit tests separately
exercise concurrent file/ledger changes and refuse to trust bytes that were not scanned.

NLI inference is disabled. The NLI frontend case enables record mode with a fake queue, verifies
that observed bytes are queued and NumPy is not imported, and excludes worker processing and
model latency. It measures how quickly control returns to the agent, not contradiction accuracy.

Provenance indexes now reuse work across lines and repeated source text. Single pre-write queries
stream matching shingles instead of building unnecessary full source indexes. Attribution runs
outside the global store lock; the commit rechecks both file and ledger versions. Hook startup
also skips unrelated CLI modules. The earlier local audit found a 100-line post-write median of
[10,425 ms in three samples](results/hooks-post-audit-2026-11-05.json) and lock contention that lost shell observation. That diagnostic was
not a 100-sample baseline; the current table is the reproducible acceptance measurement. Ordinary
Bash latency is broadly unchanged, so these changes should not be read as a blanket speedup.

A later [full rerun under concurrent host activity](results/hooks-loaded-2026-11-05.json)
passed 10/12 budgets: the large-active-memory Bash pair reached P95 787.1 ms (350 ms budget),
and the NLI frontend reached 268.1 ms (250 ms budget). macOS metadata indexing and unrelated
Python/database workloads were active. This failed run is retained; shared-host timings are
not a latency guarantee under arbitrary contention.

An [alternating paired diagnostic](results/hooks-paired-2026-11-05.json) then ran the large-memory
Bash case 100 times per version in the same isolated fixture and interpreter, alternating which
version ran first. Subprocesses loaded either the pre-change source at
`b27a2eb4b02c61368d7a29ed30827c160ef3500c` or the final candidate source through `PYTHONPATH`.
The baseline measured P50/P95 462.4/766.6 ms; the candidate measured 436.2/649.9 ms. Both exceeded
the reference budget, supporting host contention as the main cause rather than a regression in
this change. This diagnostic does not turn either failed budget into a pass.
