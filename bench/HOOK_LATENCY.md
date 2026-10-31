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
