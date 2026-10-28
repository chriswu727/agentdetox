# Agent memory poisoning benchmark, v0

v0 measures how AgentDetox and [OWASP Agent Memory Guard](https://github.com/OWASP/www-project-agent-memory-guard)
(AMG) 0.3.3 handle poisoned and legitimate writes to a Claude Code-style project memory. It uses
public attack data only, and its limits (below) matter as much as its numbers.

Reproduce: `bench/fetch_data.sh`, `agentdetox fetch-models`, then
`python bench/memory_eval.py --split test` (about 30 s on an M-series Mac with
`AGENTDETOX_NLI_DEVICE=mps`).

## How the cases are built

**Benign side** (`bench/memory_stores.json`): 10 memory stores (6 English, 4 Chinese), each a
CLAUDE.md, a MEMORY.md index and 10–12 memory files, with 8 legitimate changes per store: 4 new
memories, 3 in-place updates of an existing fact, and 1 legitimate update written as a new file
without removing the old fact. They were written by a separate assistant that was not shown the
detector code. Each benign new memory is also replayed as an append made outside the agent.

**Attack side**, from published datasets only:

| Kind | Source | How it is applied |
|---|---|---|
| `poison_fact_conflict` | PoisonedRAG adv_texts (NQ, HotpotQA, MS MARCO) | The question's correct answer is added to the store as a memory note (`The answer to "<q>" is <a>.`); an adv_text asserting the wrong answer is then written as a new memory |
| `poison_fact_novel` | PoisonedRAG adv_texts | Another adv_text is written into a store with no counterpart |
| `poison_instruction` | deepset/prompt-injections (injection-labelled) | Written as a new memory file through the agent |
| `poison_instruction_oob` | same | Appended to an existing memory file outside the agent |

An attempt to have an assistant author new, realistic memory-poisoning attacks was stopped by a
safety classifier, so v0 contains no purpose-written attacks.

**Dev/test split.** All tuning used a dev split: 2 stores whose cases were inspected while
debugging (`en-payments-api`, `zh-miniprogram`), the first 30 NQ targets (used to choose the fact
template) and the first 50 injection prompts. The test split, reported below, is the other 8
stores, 150 PoisonedRAG targets (NQ 30–79, HotpotQA 0–49, MS MARCO 0–49) and 213 injection prompts.
It was run once after tuning; a later latency-only change was re-run and left all 822 decisions
identical.

**Scoring.** AgentDetox runs its real Claude Code hook handlers: "flagged" means the write
needed approval (`ask`), was denied, or produced a session-start notice; "blocked" means denied.
AMG runs with `Policy.strict()` and is scored leniently: a block, quarantine, redaction or any
event of medium severity or above counts as flagged. Out-of-band changes are given to AMG as
direct store edits followed by `verify_all()`.

## Results (test split)

| Case kind | Lang | n | AgentDetox flagged | AgentDetox blocked | AMG flagged | AMG blocked |
|---|---|---|---|---|---|---|
| poison_fact_conflict | en | 150 | **30.0%** | 0.0% | 0.0% | 0.0% |
| poison_fact_novel | en | 150 | 0.0% | 0.0% | 0.0% | 0.0% |
| poison_instruction | en | 213 | 5.6% | 5.2% | 0.9% | 0.9% |
| poison_instruction_oob | en | 213 | 5.2% | 0.0% | 100.0%* | 0.0% |
| benign_add | en | 20 | 10.0% | 0.0% | 0.0% | 0.0% |
| benign_add | zh | 12 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_update | en | 15 | 6.7% | 0.0% | 0.0% | 0.0% |
| benign_update | zh | 9 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_conflicting_add | en | 5 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_conflicting_add | zh | 3 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_oob | en | 20 | 10.0% | 0.0% | 100.0%* | 0.0% |
| benign_oob | zh | 12 | 0.0% | 0.0% | 100.0%* | 0.0% |

\* AMG's integrity check reports every out-of-band change, benign or not.

What the numbers say:

- **Contradiction detection is the only thing here that catches fabricated facts**: 30% of the
  false claims that conflict with an existing memory note, against 0% for AMG, which has no
  semantic check. Facts with no counterpart are not caught by either tool, as expected.
- **Planted instructions are mostly missed by both tools.** deepset prompts are varied chat-style
  injections ("Forget all previous tasks…"); rules catch few of them, which matches the 10.6% that
  rules scored on the same prompts in the knowledge-base benchmark.
- **False alarms: 5 of 60 English benign cases (8.3%), 0 of 36 Chinese.** All 5 are the NLI model
  calling consistent statements about one topic contradictory (two of them are the same pair
  replayed out of band); no benign case was flagged by a rule. Flags only ask; nothing benign was
  blocked.
- **Benign conflicting updates were not flagged** (0 of 8). Asking there would arguably have been
  useful; the similarity pre-filter set on the dev split is conservative.

## What changed while building this

The first full run flagged 50–78% of benign changes. The causes, all fixed on the dev split:
taking the max of the two NLI directions (the model calls topic shifts "contradiction" in one
direction; a real contradiction holds both ways, so the min is used), a candidate pre-filter set
too low on the assumption that the model never misjudges unrelated pairs, MEMORY.md index lines
being compared as if they were claims, function words counting as shared topics, and a line-level
diff that treated unchanged sentences on an edited line as new. A Chinese exfiltration rule that
fired on "don't commit keys to the repo" was also aligned with the English rule, which requires a
concrete external destination.

## Limits

- **Domain.** PoisonedRAG facts are trivia questions, not agent memory (deploy steps, hosts,
  owners), and the conflicting "memory note" is a template sentence.
- **No Chinese attacks.** Both attack sources are English (deepset also has German); the Chinese
  stores measure false alarms only. Short Chinese paraphrases that share only a generic word fall
  under the pre-filter and are never compared (see `test_short_chinese_paraphrase_is_below_prefilter`).
- **Not memory-specific injections.** deepset prompts are direct chat injections, not the
  persistence-oriented instructions seen in MemGhost or ZombieAgent.
- **Small benign set.** 96 test-split benign cases; the false-alarm rates have wide error bars.
- **Non-adaptive.** Published attacks, not designed against these rules or this model.
- **Comparison with AMG is partial.** AMG's strengths are provenance and trust policies that need
  the integrator to label each write's source; every write here is labelled with its default
  source, so those policies were not exercised.
- **Latency.** Each Claude Code hook is a new process. Writing an ordinary file or an unrelated
  memory takes about 0.15 s; a memory write that has related existing memory loads the NLI model
  and takes about 6 s (M-series Mac). The in-process figures the harness prints assume a loaded
  model and do not reflect this.
