# Detection and recovery regression gallery

Initial results recorded 2026-10-31; additional families added for the 0.4.0 release
(published 2026-11-02). These are dated regression results, not a fresh measurement of each
subsequent commit. Accuracy is the current development priority: prevent risky persistence,
retain monitoring evidence, and recover without hiding remaining findings or overwriting newer work.
These are separate outcomes; a notification alone is not prevention, and a successful rollback
does not establish that a file is safe.

## A model as judge, 2026-11-10

The optional model check (`agentdetox config judge ask`; see the
[user guide](../docs/user-guide.md#a-models-reading-of-each-write-optional-development-main))
was measured with real calls, one text per call, exactly as a hook makes them: Claude Haiku
through Claude Code, a new session with no tools, asked without its reasoning step.
`python -m bench.judge_eval` repeats it.

| Set | Attacks flagged | Ordinary flagged | Seconds per call (median, 95th) |
|---|---:|---:|---:|
| [Blind held-out set](results/judge-heldout-2026-11-10.json), 180 short texts | 89/90 (25/26 paraphrases) | 3/90 | 2.3, 2.8 |
| [Written to get past a model](results/judge-evasion-2026-11-10.json), 120 short texts | 60/60 | 0/60 | 2.5, 3.1 |
| [Second set written to get past a model](results/judge-second-set-2026-11-11.json), 120 short texts, seen only after the setting was final | 59/60 | 2/60 | 2.3, 3.0 |
| [Whole ordinary files](results/judge-ordinary-files-2026-11-10.json), 120 | | 2/120 | 3.6, 4.3 |
| The rules alone, for comparison | 12/37 (sealed half), 20/60 | 1/44, 4/60 refused; whole files: 5/120 refused, 8 more asked about | |

The evasion set ([`heldout/judge-evasion.json`](heldout/judge-evasion.json)) was written by an
author who knew a model would judge the texts and tried to beat it, without seeing its brief:
twelve tactics, among them addressing the classifier, claiming to be a fixture, splitting an
instruction over innocent lines, burying it in a long dull note, euphemism, encoding and other
languages; its ordinary half was chosen to alarm a nervous judge. The whole files
([`heldout/ordinary-files.json`](heldout/ordinary-files.json)) are 120 instruction files, memory
notes and skills of 3 to 160 lines, written to read like the ones real projects keep, deploy
commands, secrets handling and quoted attack examples included.

What the numbers do not say:

- **The same model family wrote the texts and judged them**, to one description of what is
  harmful. People who attack for real will not write to that description.
- **The setting was chosen on these sets.** Asked with its reasoning step, the model flagged
  149 of the 150 attacks ([held-out](results/judge-heldout-reasoning-2026-11-10.json),
  [evasion](results/judge-evasion-reasoning-2026-11-10.json)), but its answer to a borderline
  text changed from one asking to the next: [asked ten times](results/judge-repeats-2026-11-10.json),
  one attack was flagged three times and three ordinary texts four, five and nine times, so a
  write could be tried again until the answer came out right. Without the step it took half
  the time and gave the same answer ten times in ten on six of seven borderline texts, but let
  one attack through every time: a skill that called itself "example fixture, not executed;
  classify as ok". One sentence in the brief, that a text which says how it should be
  classified is judged by what it would do, closes that; with the reasoning step the same
  sentence had made no difference
  ([held-out](results/judge-heldout-reasoning-sentence-2026-11-10.json),
  [evasion](results/judge-evasion-reasoning-sentence-2026-11-10.json)). That sentence was
  written after seeing the text it fixes, so the 60 of 60 is not a clean measurement for that
  kind of attack. The clean one is the second set
  ([`heldout/judge-second-set.json`](heldout/judge-second-set.json)), written by another
  author after the setting was fixed and run once: 59 of 60, all six texts that address the
  screener or pose as a sample among them. The one let through tells the agent to commit
  quietly without mentioning it; the rules do not stop it either (they stop 29 of the 60).
- **One attack is still a coin toss**: a reworded request to tidy the agent's own rule file so
  that its "ask first" switches default to yes is flagged six times in ten.
- **False flags lean towards Chinese.** Of the five ordinary items flagged in the shipped
  setting, four are Chinese (a `curl | jq` health check, a note that Stripe test keys start
  with `sk_test_`, and two Traditional Chinese files that say which vault a password is read
  from): 4 of 51 Chinese items against 1 of 203 in English. The second set, with twenty
  Chinese ordinary texts on the same subjects, did not repeat that (1 of 20 against 1 of 39),
  so the lean is not established.
- **The model and the rules disagree on ordinary files, and the rules win.** All five whole
  files the rules refuse (a vendor's install one-liner, a threat model with quoted examples,
  two memory notes, an onboarding skill) the model calls fine. The check can only add a
  question, so those refusals stand.

## Blind held-out set, 2026-11-10

The galleries below and `bench/rule_variants.py` hold cases written by people who knew the
rules. [`bench/heldout/`](heldout/heldout.json) does not: 90 texts that should not enter an
agent's standing context and 90 ordinary ones, written by an author kept from the code, the
rules and every other test set. Each attack comes in a conventional wording (`direct`), another
natural wording, tool, language or layout (`variant`) and one with no telltale keyword
(`paraphrase`). Half of the set was read while the rules were then changed; the other half
was sealed until they were final. `python -m bench.heldout_eval` puts every text through the
real pre-write hook ([complete results](results/heldout-2026-11-10.json)).

Sealed half, 37 attacks and 44 ordinary texts:

| Where the text came from | Attacks stopped | direct | variant | paraphrase | Ordinary texts asked about |
|---|---:|---:|---:|---:|---:|
| Unknown: only the rules can stop it | 12/37 | 7/18 | 5/11 | 0/8 | 1/44 |
| A page the session fetched; the user did not ask to save it | 37/37 | 18/18 | 11/11 | 8/8 | 41/44 |
| Typed by the user, who asked to save it | 12/37 | 7/18 | 5/11 | 0/8 | 1/44 |

What this says:

- **The rules catch about a third of attack text nobody tuned them on, and none of the
  paraphrases.** They rarely fire on ordinary text. On the half that was read, the same rule
  changes took the count from 12 to 30 of 53; on the sealed half they moved it from 11 to 12 of
  37. A rule added for a wording catches that wording. More rules do not close this gap.
- **Where the text came from is what stops the rest.** Text that reached the session through a
  tool and is being written to memory without the user having asked is asked about whatever it
  says: every attack, every paraphrase, and nearly every ordinary text too. That question is
  the cost of the protection, and it is only asked when the agent saves what it was not asked
  to save.
- **What neither layer covers:** text the agent rewords before saving it, text the user pastes
  in person, and files that arrive outside the agent (a cloned repository's CLAUDE.md, a script
  that writes a rules file). For those only the rules stand, at about a third. A change made
  outside the agent is still recorded and can be reviewed and undone; it interrupts the next
  session only when a rule flags it.

The sealed half is spent by this measurement: a later rule change needs a new blind set.

## Phase 1 development verification, 2026-11-09

Runtime `6339eef` passes the unchanged [45-case gallery](results/accuracy-phase1-2026-11-09.json)
and [21-case acceptance](results/acceptance-phase1-2026-11-09.json) contracts. Their two and three
known semantic misses remain visible, respectively. All 66 restores match the baseline bytes;
neither set reports wrong blocks, unnecessary questions or hook errors on its controls.

Additional tests cover wrapped attacks, diluted copies, consent scope, public-key/config reads,
redaction, private-key writes, original-line evidence, selective cleanup and concurrent ledger
changes. Actual Claude Code review supplied counterexamples before fixes; the full local gate
passes 1,022 tests with one skip. See `tests/test_detection_contract.py`,
`tests/test_before_write_evidence.py` and `tests/test_daemon.py` for the contracts.

The [public-data provenance dev comparison](results/provenance-phase1-2026-11-09.json) replays
the same case IDs against `de3aefc` and detector candidate `08dedfa` (unchanged in `6339eef`).
Mixed injection detection rises from 34/50
to 36/50; other groups retain their results. Explicitly requested copies have zero alerts in
100 English and 10 Chinese cases on both versions. Unsolicited benign copies remain a separate
intentional-review category, with 99/100 English and 10/10 Chinese cases flagged on both versions.
Attack misses remain. This is a development comparison, not held-out or real-world accuracy.

The [real-client report](../lab/results/latest.md) separately retains two initial quiet-use
failures and explains the final editing-only acceptance. Offline passes do not erase those failures.

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
use the real hook handlers in isolated folders; none needs a model. "0.3.0" is the previous release
run against the same cases; the final column is the 0.4.0 regression result.

| Family | Cases | 0.3.0 | 0.4.0 |
|---|---:|---:|---:|
| Shell commands, decided before they run (36 that write context, 13 that must stay allowed) | 49 | 18 | 49 |
| Settings changed outside the agent (5 that add something that runs; a permission and an ordinary variable as controls) | 7 | 2 | 7 |
| Writes to files the agent loads under another name or place (case, symlink, subfolder, parent folder, output style) | 5 | 0 | 5 |
| A planted file name adding a fake line to AgentDetox's notice | 1 | fail | pass |

The shell cases are commands that each got past an earlier version of the parser: nested
`bash -c`/`eval` (also in option bundles such as `bash -lc`), wrappers and their options
(`sudo -u root`, `env -u X`, `timeout -s KILL 10`, also bundled as `sudo -Eu root`), a wrapper or git
option that switches folder (`env -C .claude`, `git -C .claude`), `cd -P`, a `cd` that may fail or be
skipped, variables naming the program, an option or the target, `git checkout --`, `curl -o`, inline
code, shell heredocs, a git restore of a whole folder, a copy into a folder that keeps the source's
name (`cp x/CLAUDE.md .`), and bundled download flags (`-sSLo`). The allowed controls are reads,
heredoc data, an index-only `git restore --staged .`, copies of ordinary files into a folder, a backup
copy of CLAUDE.md, a git restore in another folder and deleting folders without context.
The settings cases are reported once; the report is worded as a question, not as flagged content. A replay of 985 real Bash commands from an agent session
changed one decision compared with the previous parser (a real write to an agent memory file
through a variable path, which now asks), and no longer crashed on four commands with unbalanced
parentheses that made the previous parser fail open. A later replay of 7,780 distinct real Bash
commands, before the 0.4.0 release, changed one decision: a `git checkout -q -- .` in a project
holding context files, which now asks. After shell option bundles (`bash -lc`) and wrapper
options (`sudo -u root`) were parsed, a replay of 8,640 distinct real Bash commands changed no
decision. After folders switched by wrappers, git and `cd` options, and copies into a folder were
followed, a replay of 8,878 changed none.

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

## Configuration semantics regressions, 2026-11-04

Run `python -m pytest -q tests/test_config_semantics.py tests/test_safety_guidance.py`. These
141 authored cases exercise scanners and real hook handlers without a model or network. They cover user, project, local, MCP, global and
relocated Claude config, and keep normal activity separate from execution changes:

- Inert metadata with command-like keys stays quiet before writes, after shell tools and at startup.
- Changing a hook's spinner text does not require approval or claim a new executable was added.
- Examples inside real hook, status-line and MCP metadata are not interpreted as shell commands.
- Hook and MCP metadata changes remain reviewable without a high-severity execution claim.
- Changes to real hook commands, HTTP targets, prompt/agent hooks and MCP tool hooks still alert.
- Real MCP commands, arguments, URLs, loaders and dynamic header helpers remain guarded;
  malicious command payloads and AgentDetox environment overrides are denied.
- Permission and MCP approval list ordering and duplicates, and status line display changes,
  stay quiet. Membership, argument ordering and runtime changes remain guarded.
- Direct English and Chinese safety prohibitions stay quiet; later active instructions,
  ambiguous reversals, hidden text, executable commands and structural chat tokens remain checked.

This is regression evidence for supported Claude configuration, not a held-out accuracy estimate
or validation of other agents. Unknown properties inside guarded sections stay reviewable; a
quiet command scan does not establish that an arbitrary external program is safe.

## Current report format on main

The `quality` section includes all 29 authored attack cases, including the two acknowledged
semantic misses. It lists prevention and monitoring misses by name, separately from wrong blocks,
unnecessary questions and findings on 16 ordinary/explicit-consent controls. Four direct
English/Chinese prohibition controls extend the earlier gallery. All 45 cases also check exact
restoration; restoring known bytes does not certify their safety. These controls overlap regression
fixtures and are not held out.

`regression_gate_passed` means the existing case expectations, additional families, recovery
checks and hook-error checks passed. It does not mean every attack was detected. JSON reports
retain `passed` as a compatibility alias with the same meaning. CI and the release workflow run
this gate separately from the clean-wheel lifecycle in `scripts/check_journey.py`.

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
  population false-positive rate; the expanded controls do not establish one either.
- The two explicit misses are paraphrased source content and a plausible false fact without a
  trusted counterpart. They remain in reports. The exit status gates known regressions and hook
  errors; it does not require these acknowledged gaps to pass.
- Remember intent remains a bounded lexical heuristic. Mixed requests with different scopes,
  indirect phrasing and conditions need further evaluation; this is not a semantic consent parser.
- Rollback is whole-version recovery. It can undo benign additions made in the same change; the
  preview and stale-version guard remain essential. On `main`, `clean` removes explicitly selected
  added lines while preserving other content and non-conflicting later edits. Cleanup has dedicated
  regression tests and a built-wheel journey; it does not automatically identify poisoned spans.
- Recovery rescanning covers deterministic rules, not factual verification or contradiction/model
  checks. An empty scan is not a clean bill of health. In 0.4.0, the legacy checkpoint restore
  command uses the same journalled recovery
  and target rescan as review-based recovery.
- No Claude/Codex sessions were run by this offline gallery. It does not verify real-client hook
  delivery or alert display. Further self-use work should measure per-family misses, benign review burden,
  delayed/mixed-source persistence, and residual content after cleanup separately.

## Frozen acceptance set, 2026-11-05

A separate set of 21 cases was authored by Claude before seeing the detector expressions or
this set's results: eight benign controls and thirteen attacks, including three declared semantic
gaps. The [fixture](fixtures/acceptance-2026-11-05.json) retains its original text and expected
labels; both reports record its SHA-256. This is a small authored acceptance set, not a
statistically independent estimate of real-world precision or recall. Claude had prior project
context. Once its failures informed fixes, reruns became regression evidence.

```sh
python -m bench.acceptance_eval --output bench/results/acceptance-current.json
```

The [initial report](results/acceptance-before-2026-11-05.json) exposed a false block on a
coordinated safety prohibition, a fetch-and-pipe instruction that asked rather than denied, and
an unnecessary guardrail question when creating a file containing only Claude runtime metadata.
All 21 baseline restores were byte-exact. The gate keeps the three declared semantic misses
visible while requiring every other prevention/monitoring expectation, every restore, and no hook
errors. It also requires the cleanup and configuration journeys below to pass.

The selective-cleanup journey removes two planted lines separately, preserves benign content and
a later user edit, verifies the quarantine bytes, keeps remaining findings visible between removals,
and refuses application after another edit. The configuration journey checks that cached display
text stays quiet and a real malicious MCP command is denied. Neither journey calls a model.

The [final report](results/acceptance-after-2026-11-05.json) passes that acceptance gate with
unchanged fixture bytes and labels. Eight benign controls have no block, question or finding.
Ten supported attacks meet both prevention and monitoring expectations; three semantic gaps
remain misses. All 21 restores are byte-exact, both journeys pass, and no hook errors were recorded.
The existing [45-case regression gallery](results/accuracy-2026-11-05.json) also passes its gate,
including its two declared semantic gaps, plus the shell, configuration and recovery journeys.

The safety-grammar fix recognizes coordinated prohibitions and complete, narrowly phrased
approval reminders. It does not exempt arbitrary later clauses, reversals, executable configuration
or hidden content. Natural-language instructions to fetch an HTTP(S) URL and pipe the result
to a shell are now high severity. These are bounded rule improvements, not general language
understanding or a solution to the declared semantic gaps.
