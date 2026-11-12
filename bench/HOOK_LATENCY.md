# Hook latency

## Current

The newest Mac suite ([complete report](results/hooks-0.6.0-2026-11-11.json)) passes all 12
cases within their budgets, with 100 samples per case on macOS 15.7.4 ARM64 and Python 3.13.13.
P95 figures: ordinary Bash pre/post 109.1 ms (budget 200 ms); startup with 1,000 unchanged files
121.7 ms (250 ms); four protected writes plus a Bash pair 235.5 ms (1,000 ms); the Bash pair with
1,000 active and 1,000 unrelated memory files 252.2 ms (350 ms). It was measured on the 0.6.0
branch at `f00eedc` with uncommitted changes, before that release's last commits; the file
records its commit as dirty, so it is not a measurement of the released build. The optional
model check was off: its call of two to four seconds per text is not in these figures.

On Windows the latest complete suite, recorded on 2026-11-09 (below), still fails 7 of 12
budgets.

Run `python -m bench.hook_latency --samples 100 --output bench/results/local.json`.
No model, network, or subscription calls are made. Each timing includes a fresh Python process,
CLI parsing and hook execution. Each case has one untimed warmup; P95 uses the nearest-rank
method. File changes are prepared outside timed sections. The 100-changed-file case begins with
10,000 entries and accumulates another 100 records per sample.

## History

Dated runs, newest first. Each describes the build it measured at the time.

### Hardening complete, 2026-11-10

The [complete report](results/hooks-hardening-final-2026-11-10.json) measures `7369419`, the
end of the hardening branch (store, install, other clients' shell paths, rule spellings, more
watched folders): **12/12 original budgets pass**, with 100 samples per case on the
development Mac. Ordinary Bash pre/post P95 is 126.7 ms; startup with 1,000 unchanged files is
132.6 ms; four protected writes plus a Bash pair is 293.6 ms. These are higher than the run
below, and most of that is the machine on the day: run back to back, 40 samples each and twice
over (not recorded here), the commit measured below, the commit before the rule changes and
this one had medians within 3 ms of each other in every case, with this one the slowest by
1 to 3 ms per hook. About 1 ms of that is importing the larger rules. Windows failures below
are not addressed by this run.

### Prevention hardening, 2026-11-10

The [complete report](results/hooks-hardening-2026-11-10.json) measures `d845926`, the branch
that rewrites the shell command reader, asks when a context write cannot be checked, compares
paths by file identity and bounds the work one hook does: **12/12 original budgets pass**, with
100 samples per case on the development Mac and nothing else running. Ordinary Bash pre/post
P95 is 114.9 ms; startup with 1,000 unchanged files is 123.8 ms; four protected writes plus a
Bash pair is 255.1 ms. Every case is within a few milliseconds of the run below, mostly under
it; this is not a paired comparison, so the difference is not a measured speed-up. The result
file names its commit and command, as every result recorded from here on does
(`scripts/check_evidence.py` checks that, and that the figures the READMEs quote are in a
recorded result). Windows failures below are not addressed by this run.

### Cross-client disinfection, 2026-11-10

The [complete report](results/hooks-clients-2026-11-10.json) measures the cross-client
change built on `928adad`, before its release in 0.5.0: **12/12 original budgets pass**, with 100 samples per case and no
concurrent builds or test runs. Ordinary Bash pre/post P95 is 118.4 ms; startup with 1,000
unchanged files is 125.5 ms; the many-file Bash pair is 219.5 ms. See
[validation and limits](../docs/client-validation.md). This is not a paired comparison and
does not resolve the Windows failures below or measure model inference or complete client startup.

### Scoped triage and dynamic trust guard, 2026-11-10

The [complete report](results/hooks-triage-2026-11-10.json) measures runtime `6d5a761` after
version-scoped library triage and the dynamic-argument trust guard: **12/12 original budgets
pass**, with 100 samples per case on the development Mac. Ordinary Bash pre/post P95 is
110.3 ms; startup with 1,000 unchanged files is 123.0 ms; four concurrent protected writes
plus Bash pre/post is 273.4 ms. No tests, builds or other benchmarks ran alongside it.
This is an idle-library gate, distinct from the earlier scan-load run below. It excludes
NLI inference and complete client startup, and does not resolve the Windows failures below.

### Library scan load on Mac, 2026-11-10

Runtime `eae840a` passed **12/12 original budgets** with 100 samples per case both
[idle](results/hooks-library-idle-2026-11-10.json) and
[during a continuously active library scan](results/hooks-library-active-2026-11-10.json).
The scan shared the hook store and progressed from 0 to 48,600 of 100,000 synthetic files,
then was cancelled normally. It did not complete the 100k corpus. The
[large-memory protocol](LARGE_MEMORY.md#hook-latency-during-inspection) records the method,
selected P95 timings and limits. These sequential Mac measurements do not establish Windows
performance, production-scale support, NLI inference latency or complete client startup time.
Earlier failures below remain part of the record.

### Phase 1 Mac gate, 2026-11-09

The [complete report](results/hooks-phase1-2026-11-09.json) measures runtime `6339eef`,
100 samples per case and the original budgets: **12/12 pass**. It includes interpreter startup,
durable shell observation, large transcripts and concurrent writes. No tests, builds or other
benchmarks were launched alongside this run; this is still a shared development Mac.

| Case | P95 ms | Budget ms |
|---|---:|---:|
| Ordinary Bash pre/post pair | 107.9 | 200 |
| Bash pair, 1000 active + 1000 unrelated files | 213.1 | 350 |
| Startup, 1000 unchanged files | 123.2 | 250 |
| Four 100-line writes plus Bash pair | 256.0 | 1000 |
| NLI queue frontend, 1000 files, fake submit | 81.4 | 250 |

The fake-submit case excludes durable queue filesystem I/O and model inference. These measurements
do not include the real Claude client's complete startup or the plugin's `uvx` fallback. They are
not a paired causal comparison against an earlier build. Windows latency failures below remain
unresolved; a Mac pass does not establish Windows performance.

### Windows filesystem and import follow-up, 2026-11-09

The [alternating comparison](results/hooks-windows-io-paired-2026-11-09.json) uses
`647c081` as the pre-optimization baseline, the same CPython 3.12.16 interpreter, separate
temporary stores, shared synthetic files, 100 samples per version/case, and one untimed
warmup. Every Bash event has a tool-use id, so it includes durable shell observation.
The order alternates each sample. Imported source locations and unchanged source hashes
are checked; the report retains every timing and the candidate source hash/diff hash.
No tests, builds, or other benchmarks were launched alongside this measurement, although
this remains a shared development host rather than a controlled reference machine.

| Case | Baseline P50/P95 ms | Candidate P50/P95 ms | P95 budget ms |
|---|---:|---:|---:|
| Ordinary Bash pre, one context file | 190.3 / 199.2 | 178.3 / 187.1 | 100: both fail |
| Bash pair, 1000 active + 1000 unrelated memory files | 743.6 / 778.8 | 616.3 / 645.8 | 350: both fail |

The measured P95 reductions are about 6% and 17%, respectively. Neither failure is a pass.
This comparison does not isolate the contribution of each change: directory creation now
checks whether the directory exists first, still repairing permissions on every call, and
ordinary hooks defer NLI transport imports. Checkpoint verification also hashes and scans
one captured byte sequence, skipping text decoding for unchanged files. It does not use
file size or timestamps as evidence that content is unchanged, cache trust across hooks,
relax commit-time version checks, or add a resident service.

Reproduce against a chosen baseline with:

```powershell
.\.venv\Scripts\python.exe -X utf8 -m bench.hook_revision_compare --baseline 647c081 --samples 100 --output bench/results/local-paired.json
```

The earlier Windows startup-only comparison below uses a different fixture and is not a
direct numerical baseline for this run. All earlier failures remain retained.

#### Complete follow-up suite

The [full rerun](results/hooks-windows-io-2026-11-09.json) uses the runtime in `4ed9336`,
100 samples per case and the original fixture/budgets. It still **passes 5/12 and fails 7/12**.
All 1,200 timings are retained. It ran after the paired comparison, without concurrent local
test/build runs. The older full suite was measured at a different time and load, so use the
alternating comparison above for the evidence of improvement, not differences between full runs.

| Case | P50 ms | P95 ms | Budget ms | Result |
|---|---:|---:|---:|---|
| Ordinary Bash pre | 183.1 | 190.2 | 100 | fail |
| Ordinary Bash pre + post | 367.7 | 400.7 | 200 | fail |
| Protected Edit pre, 50k history | 164.8 | 185.4 | 120 | fail |
| Protected Write pre, repeated large transcript | 177.1 | 185.1 | 200 | pass |
| Protected Write post, 100 lines, repeated transcript | 212.5 | 225.3 | 500 | pass |
| Protected Write pre, 29 distinct large sources | 215.3 | 229.0 | 200 | fail |
| Protected Write post, 100 lines, 29 sources | 295.0 | 317.8 | 500 | pass |
| Four concurrent Write posts plus Bash pre/post | 486.7 | 552.6 | 1000 | pass |
| SessionStart, 1000 unchanged files | 337.5 | 350.8 | 250 | fail |
| SessionStart, 100 changed / 1000 files | 1197.0 | 1264.7 | 1000 | fail |
| Bash pair, 1000 active + 1000 unrelated memory files | 613.8 | 675.6 | 350 | fail |
| NLI queue frontend, no inference | 210.5 | 221.6 | 250 | pass |

The concurrent case retained all four changes without `hook_error` or `shell_unobserved`.
NLI remains a fake frontend queue, not a model/inference measurement. Real-client overhead,
peak process memory, sustained CPU usage and long-term store growth remain unmeasured.
Startup and many-file checks still need work; these bounded changes do not establish a
completed native Windows performance acceptance.

### Native Windows development measurement, 2026-11-09

The [first native Windows suite](results/hooks-windows-2026-11-09.json) used Windows 11
build 26200, Ryzen 9 9900X3D, CPython 3.12.16, 100 samples per case and the same budgets.
**5/12 passed; 7/12 exceeded budget.** No budget was increased. These are development-host
measurements, with other applications and some migration checks active during the run;
they are not Windows performance guarantees. The fixture uses Windows native newlines,
so its repeated transcript is 3,889,974 bytes rather than the macOS fixture's 3,889,915.

| Case | P50 ms | P95 ms | Budget ms | Result |
|---|---:|---:|---:|---|
| Ordinary Bash pre | 207.5 | 237.6 | 100 | fail |
| Ordinary Bash pre + post | 377.5 | 447.6 | 200 | fail |
| Protected Edit pre, 50k history | 174.0 | 193.1 | 120 | fail |
| Protected Write pre, repeated large transcript | 181.2 | 188.2 | 200 | pass |
| Protected Write post, 100 lines, repeated transcript | 218.5 | 229.6 | 500 | pass |
| Protected Write pre, 29 distinct large sources | 225.0 | 249.5 | 200 | fail |
| Protected Write post, 100 lines, 29 sources | 303.7 | 339.8 | 500 | pass |
| Four concurrent Write posts plus Bash pre/post | 511.6 | 550.6 | 1000 | pass |
| SessionStart, 1000 unchanged files | 384.3 | 418.9 | 250 | fail |
| SessionStart, 100 changed / 1000 files | 1275.3 | 1673.1 | 1000 | fail |
| Bash pair, 1000 active + 1000 unrelated memory files | 752.8 | 801.7 | 350 | fail |
| NLI queue frontend, no inference | 213.5 | 234.8 | 250 | pass |

The concurrency case completed all evidence/health assertions: four recorded writes, no
`hook_error` or `shell_unobserved`. The NLI case uses a fake queue; no model was installed or run.
The suite overlapped development of the platform import/type fix; it is an initial migration
measurement, not an exact-final-commit release gate.

An [alternating startup comparison](results/hooks-windows-paired-2026-11-09.json) then used
the same interpreter and isolated empty project/store, importing either pristine `f2165e6`
source or candidate `a99c185` through `PYTHONPATH`. Import locations were checked, one untimed
call preceded 100 samples per version, and order alternated each iteration. Ordinary Bash pre
P50/P95 was **173.5/193.0 ms baseline**, **174.1/188.4 ms candidate**. Both exceed 100 ms; this
supports no corresponding startup regression from the migration, but does not clear the failed
budget or establish the cause of every slow case. All individual timings are retained.

An import-time diagnostic attributed about 135 ms to importing the hook module and its
dependencies on this host. Twenty empty interpreter launches had P50/P95 30.8/35.2 ms.
This points to startup/import work as a useful next investigation; it is not a validated
engine optimization or evidence that Windows antivirus should be disabled. Large-file-set I/O
also needs separate profiling. Real-client latency and `uvx` download/startup remain unmeasured.

### 0.4.1 release candidate, 2026-11-05

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

A [subsequent full rerun](results/hooks-release-rerun-2026-11-05.json) passed 11/12 budgets.
The previous two failures cleared (large-memory Bash P95 307.6 ms; NLI frontend 90.7 ms),
but unchanged-file SessionStart reached 348.8 ms against 250 ms while the macOS filesystem
event service was busy. The full rerun remains a failed suite, not a 12/12 pass.

After that activity subsided, [focused follow-up measurements](results/hooks-followup-2026-11-05.json)
ran 100 samples each for unchanged-file SessionStart and the NLI queue frontend, with the same
1,000-file fixtures and budgets, skipping the other timed cases. They measured P95 148.1 ms
and 79.1 ms respectively, both passing. This also covers the final newline-normalization fix in
the NLI frontend. Every scenario has a passing 100-sample measurement, while the failed full
reruns show why these shared-machine numbers cannot promise tail latency under contention.

### 0.4.0 release candidate, 2026-11-01

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

### Earlier macOS reference measurements

These are dated reference measurements, not timings of every later commit or of a full Claude
plugin launch. They exclude `uvx` startup and downloads.

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

### Development baseline: shell observation, 2026-10-30

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
