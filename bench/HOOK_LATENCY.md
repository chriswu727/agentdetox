# Hook latency

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

## Unreleased shell observation, 2026-10-30

The main checkout now measures Bash pre-checks with fresh agent tool-use ids and additionally
measures the complete pre/post pair. The active-memory stress case has 1,000 files belonging to
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
files whose trusted version is unchanged, so it is faster than in 0.3.0 despite watching more files
and re-checking each version before trusting it. The shell check parses more forms at no measurable
cost.

| Case | P50 | P95 | Budget |
|---|---:|---:|---:|
| Bash pre-check | 58.2 ms | 59.9 ms | 100 ms |
| Bash pre + post | 121.2 ms | 135.0 ms | 200 ms |
| Protected Edit, 50k history entries | 60.3 ms | 61.9 ms | 120 ms |
| Protected Write, 3,889,915-byte transcript | 144.4 ms | 150.9 ms | 200 ms |
| Session start, 1,000 unchanged files | 130.3 ms | 138.2 ms | 250 ms |
| Session start, 100 changed / 1,000 files, initially 10k entries | 180.8 ms | 188.8 ms | 1,000 ms |
| Bash pre + post, 1,000 active memory files and 1,000 unrelated | 222.4 ms | 231.2 ms | 350 ms |
