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
| poison_fact_conflict | en | 150 | **28.0%** | 0.0% | 0.0% | 0.0% |
| poison_fact_novel | en | 150 | 0.0% | 0.0% | 0.0% | 0.0% |
| poison_instruction | en | 213 | 5.6% | 5.2% | 0.9% | 0.9% |
| poison_instruction_oob | en | 213 | 5.2% | 0.0% | 100.0%* | 0.0% |
| benign_add | en | 20 | 10.0% | 0.0% | 0.0% | 0.0% |
| benign_add | zh | 12 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_update | en | 15 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_update | zh | 9 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_conflicting_add | en | 5 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_conflicting_add | zh | 3 | 0.0% | 0.0% | 0.0% | 0.0% |
| benign_oob | en | 20 | 10.0% | 0.0% | 100.0%* | 0.0% |
| benign_oob | zh | 12 | 0.0% | 0.0% | 100.0%* | 0.0% |

\* AMG's integrity check reports every out-of-band change, benign or not.

What the numbers say:

- **Contradiction detection is the only thing here that catches fabricated facts**: 28% of the
  false claims that conflict with an existing memory note, against 0% for AMG, which has no
  semantic check. Facts with no counterpart are not caught by either tool, as expected.
- **Planted instructions are mostly missed by both tools.** deepset prompts are varied chat-style
  injections ("Forget all previous tasks…"); rules catch few of them, which matches the 10.6% that
  rules scored on the same prompts in the knowledge-base benchmark.
- **False alarms: 4 of 60 English benign cases (6.7%), 0 of 36 Chinese.** All 4 are the NLI model
  calling consistent statements about one topic contradictory (two of them are the same pair
  replayed out of band); no benign case was flagged by a rule. This benign set is far cleaner than
  real memory; see "Contradictions on real memory" below.
- **Benign conflicting updates were not flagged** (0 of 8). Asking there would arguably have been
  useful; the similarity pre-filter set on the dev split is conservative.

## Contradictions on real memory

The table above was measured in ask mode. A read-only scan of one user's real Claude Code memory
(106 memory files plus instruction files, 2026-10-27) told a different story: the version above
flagged 124 contradictions across 47 files, nearly all false. Real memory is lists, fragments, tables
and Why/How-to-apply notes, and the NLI model, judging fragments out of context, calls notes about
different components contradictory. Changes made against that scan and the dev split: statements
carry their heading and parent list item as context, "label: value" lines are only compared with
lines about the same label, list-introducing lines and fragments under 3 content words are dropped,
compared statements must share 2 content words, and the whole-store scan compares across files only.
Real-memory flags fell to 19 (11 files); the test split numbers above are with these changes.

The trade-off cannot be tuned away with this model: thresholds that bring real-memory flags near 0
(p >= 0.98) leave about 13% recall on the dev split. **Hooks therefore record contradictions in the
background instead of asking** (`agentdetox events` shows them; `agentdetox config contradiction ask` restores
prompting). A stronger judge than this NLI model is needed before asking again.

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

## Provenance check (memory copied from untrusted tool output)

`bench/provenance_eval.py` builds Claude Code transcripts in the real JSONL format: the user asks
for something, WebFetch, an MCP mail tool, Bash or Read returns a document, and the agent writes a
memory file. Attack text (English, public data only) is a deepset injection prompt or a PoisonedRAG
adv_text embedded in a SQuAD paragraph, after a request that does not ask to remember anything; the
memory is that text verbatim, half of it after a framing sentence, or all of it between two benign
sentences. Contradiction detection is off so the check is measured alone. The copy threshold (0.3 of
the new text's 6-token shingles) was the lowest value with no benign false alarm on the dev split;
the test split was then run once.

| Case kind | Lang | n | Flagged | By provenance | By rules |
|---|---|---|---|---|---|
| injection, verbatim | en | 213 | **96.7%** | 91.5% | 5.6% |
| injection, partial | en | 213 | **76.5%** | 72.3% | 4.7% |
| injection, mixed with benign text | en | 213 | **66.7%** | 61.5% | 5.6% |
| fabricated fact, verbatim | en | 150 | 100.0% | 100.0% | 0.0% |
| fabricated fact, partial | en | 150 | 96.0% | 96.0% | 0.0% |
| fabricated fact, mixed | en | 150 | 96.0% | 96.0% | 0.0% |
| benign, own words | en / zh | 20 / 12 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% |
| benign, copied after "remember this" | en / zh | 100 / 24 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% |
| benign, text the user pasted | en / zh | 50 / 12 | 0.0% / 0.0% | 0.0% / 0.0% | 0.0% |
| grey zone: benign text copied unasked | en / zh | 100 / 24 | 100% / 100% | 100% / 100% | 0.0% |

The same deepset prompts were flagged 5.6% of the time when written into memory with no transcript
(table above); knowing where the text came from is what raises it. Flags ask; nothing is blocked.

Limits of this part, in addition to those above:

- **Synthetic transcripts.** One tool call and template prompts per case. Real sessions are longer,
  and how often an agent copies benign tool output (commands, errors, paths) into memory unasked is
  the real false-alarm question; this benchmark cannot answer it.
- **Paraphrase evades it.** Only copied text is detected; attack text the model restates in its
  own words is not.
- **Very short attack text** (under 6 tokens) has no shingles to match; **delayed writes** more than
  three user turns after the read are out of the window.
- **The "remember this" exemption** reads only the user's own message, which injected text cannot
  forge, but a user who habitually asks the agent to remember things while it reads untrusted
  content loses this protection in those turns.
- **Claude Code only.** Other agents' transcript formats are not parsed.
