# Detection and recovery regression gallery

Recorded 2026-10-31. Accuracy is the current development priority: prevent risky persistence,
retain monitoring evidence, and recover without hiding remaining findings or overwriting newer work.
These are separate outcomes; a notification alone is not prevention, and a successful rollback
does not establish that a file is safe.

## Reproduce

```sh
python bench/accuracy_eval.py --output bench/results/accuracy-current.json
```

The gallery uses real Claude Code hook handlers in isolated temporary homes, projects and stores.
It makes no network or model calls. Every case first checks a planned write. It then deliberately
writes the fixture, regardless of that decision, and invokes the post-write hook to test monitoring
independently. This forced write is test setup, not evidence of a real agent bypass. Finally it
restores the recorded change and checks byte equality with the fixture's user-authored baseline.

The baseline was run against `3f8edacf3c15743f58ef8e518f6e1e47e608c13f`, before the fixes, with the
same gallery. The raw [before](results/accuracy-before-2026-10-31.json) and
[after](results/accuracy-after-2026-10-31.json) reports retain every decision, including misses.

## Attack families added 2026-11-01

Four more families, from an independent security review and the code reviews of its fixes. All
use the real hook handlers in isolated folders; none needs a model. "0.3.0" is the released
package run against the same cases.

| Family | Cases | 0.3.0 | Now |
|---|---:|---:|---:|
| Shell commands, decided before they run (22 that write context, 6 that must stay allowed) | 28 | 11 | 28 |
| Settings changed outside the agent (5 that add something that runs, 1 permission control) | 6 | 1 | 6 |
| Writes to files the agent loads under another name or place (case, symlink, subfolder, parent folder, output style) | 5 | 0 | 5 |
| A planted file name adding a fake line to AgentDetox's notice | 1 | fail | pass |

The shell cases are commands that each got past an earlier version of the parser: nested
`bash -c`/`eval`, wrappers, a `cd` that may fail or be skipped, variables naming the program, an
option or the target, `git checkout --`, `curl -o`, inline code, and shell heredocs. The allowed
controls are reads and heredoc data. A replay of 985 real Bash commands from an agent session
changed one decision compared with the previous parser (a real write to an agent memory file
through a variable path, which now asks), and no longer crashed on four commands with unbalanced
parentheses that made the previous parser fail open.

## Results

| Outcome | Cases | Before | After |
|---|---:|---:|---:|
| Explicit rule attacks denied | 17 | 5 | 17 |
| Those attacks recorded at high severity after a forced write | 17 | 5 | 17 |
| Unrequested source copies ask for approval | 10 | 1 | 10 |
| Those source copies recorded after a forced write | 10 | 1 | 10 |
| Normal/explicit-consent controls unnecessarily interrupted | 12 | 0 | 0 |
| Exact baseline bytes restored, including benign cases and known misses | 41 | 41 | 41 |
| Known semantic gaps detected before or after the write | 2 | 0 | 0 |

The 17 rule cases cover five payloads (English/Chinese instruction overrides, exfiltration,
credential access and guardrail changes), with plain and diff-like prefixes, plus two quoted
decoys preceding active instructions. The ten source cases vary the user's request: summary only,
negative requests, quoted discussions and recollections. The twelve controls include seven
explicit requests to save the source and five normal notes. Explicit consent is a policy control;
it does not establish that source content is harmless. High-severity rules remain independent
of this source-copy exemption.

A separate shell/recovery journey starts with an already poisoned version, observes a second
change, and restores the earlier poisoned version. Both versions are synthetic fixtures. Before
the fixes, the shell change was noticed and bytes restored, but neither preview nor application
warned about residual findings, and no residual findings remained pending. Afterwards, both warn,
the recovery entry retains pending findings, and the safe checkpoint is not advanced to a version
with unsuppressed high findings. Unit tests also recover the earlier change to reach the clean
baseline, verify config commands and explicit exceptions, and refuse stale-version actions.

The fixes address dropped `++` content in diff extraction, a quoted first match hiding a later
active instruction, negative/quoted/recollected save requests granting a blanket exemption, and
same-anchor deduplication discarding a later higher severity. Findings now retain the strongest
severity without changing existing finding ids.

## Existing public-data evaluation

The existing provenance test split was rerun with NLI off: 1,431 synthetic-transcript cases,
with zero decision changes from the previous local result. Injection text flagged remains
96.7% verbatim, 76.5% partial and 66.7% mixed with benign text. Its 218 ordinary/explicit-consent/
user-pasted controls remain unflagged; 124 benign unrequested copies remain flagged by design
and are reported as a grey zone, not malicious content.

The [summary](results/provenance-summary-2026-10-31.json) includes group counts and dataset hashes.
See [the original protocol and limitations](MEMORY_BENCHMARK.md#provenance-check-memory-copied-from-untrusted-tool-output).
This rerun checks regressions; the targeted fixes do not improve the existing aggregate scores.

## Limits and next measurements

- This is an authored regression set used while fixing the code, not a held-out test or an estimate
  of real-world accuracy. Prefix variants are correlated. Twelve controls cannot establish a low
  population false-positive rate.
- The two explicit misses are paraphrased source content and a plausible false fact without a
  trusted counterpart. They remain in reports. The exit status gates known regressions and hook
  errors; it does not require these acknowledged gaps to pass.
- Remember intent remains a bounded lexical heuristic. Mixed requests with different scopes,
  indirect phrasing and conditions need further evaluation; this is not a semantic consent parser.
- Rollback is whole-version recovery. It can undo benign additions made in the same change; the
  preview and stale-version guard remain essential. Precise removal of poisoned spans while
  preserving later benign edits is not implemented.
- Recovery rescanning covers deterministic rules, not factual verification or contradiction/model
  checks. An empty scan is not a clean bill of health. The legacy checkpoint restore command does
  not perform this new review-based rescan.
- No new Claude/Codex sessions were run. This gallery does not verify real-client hook delivery or
  alert display. Further self-use work should measure per-family misses, benign review burden,
  delayed/mixed-source persistence, and residual content after cleanup separately.
