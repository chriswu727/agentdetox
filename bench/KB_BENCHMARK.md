# Knowledge-base scanner benchmark

How `agentdetox scan` and `trace` do on published RAG poisoning and injection data. For agent memory,
see [MEMORY_BENCHMARK.md](MEMORY_BENCHMARK.md).

Clean background: 5,225 Wikipedia paragraphs from SQuAD v1.1 (`bench/fetch_squad.py`).
Poison: the adversarial texts released with PoisonedRAG (Zou et al., USENIX Security 2025),
100 target questions x 5 passages = 500 per dataset. `prefix` is the black-box attack as published
(target question prepended); `noprefix` drops the question, approximating an attacker who only
paraphrases. Reproduce with `bench/fetch_data.sh`, then `bench/compare.py bench/data`.

## Compared with per-document scanners

Detection rate on each attack set (`bench/compare.py`). Per-document tools are scored leniently:
any alert counts. Indirect-injection sets embed the 263 injection-labelled prompts of
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (English
and German) into clean passages, in four forms.

| Tool | NQ prefix | NQ noprefix | HotpotQA prefix | HotpotQA noprefix | MS MARCO prefix | MS MARCO noprefix | Injection plain | hidden HTML | Unicode tags | zero-width | Clean FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Veritensor 1.9.4 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 3.8% | 100.0% | 0.0% | 0.0% | 0.1% |
| ProtectAI deberta-v3 PI v2 | 0.4% | 1.2% | 0.0% | 0.0% | 0.2% | 0.4% | 11.4% | 33.8% | 0.0% | 10.6% | 0.1% |
| AgentDetox 0.1 (high) | 100.0% | 0.0% | 100.0% | 0.0% | 100.0% | 0.0% | 5.7% | 10.6% | 100.0% | 10.3% | 0.0% |
| AgentDetox 0.1 (medium+) | 100.0% | 89.2% | 100.0% | 98.0% | 100.0% | 92.0% | 10.6% | 96.6% | 100.0% | 99.6% | 2.6% |

What this shows:

- Neither per-document tool detects knowledge poisoning: PoisonedRAG passages contain no attack
  string, only a fluent false claim. Detecting them takes cross-document analysis.
- Plain-text injection phrased in ways no rule anticipates is hard for everyone, AgentDetox included.
  The ProtectAI classifier flags 41.4% of the same prompts on their own, so burying a prompt in a
  benign passage dilutes it (only 2 of 263 documents exceed its 512-token window).
- Veritensor flags any `display:none`, so it catches every hidden-HTML document; AgentDetox reports
  hidden text as `medium` unless the hidden text itself matches an injection rule.
- Llama Prompt Guard 2 is a gated model and was not evaluated; run
  `bench/compare.py DATA --tools promptguard2` after `huggingface-cli login`.

## False positives on a clean corpus

Scanning the 5,225 clean paragraphs alone gives no `high` findings and 2.6% `medium`
(`poison-cluster`) with MiniLM, 3.9% with `hashing`. 31 of the 35 clean clusters are paragraphs of
the same Wikipedia article. Per-run false-positive rates measured with poison present are lower
(0.3 to 0.9%) because the poison cliques raise the similarity threshold; the clean-only figure is
the one to expect in practice.

## `trace`

Averaged over the 100 target questions per dataset (MiniLM): precision 0.84 to 0.94, recall 0.94
to 1.00.

With the numpy-only `hashing` embedder, `prefix` recall is unchanged but `noprefix` recall drops
to 0.32 to 0.74. Install the `st` extra if paraphrased poisoning matters to you.

## Caveats

The clean corpus is SQuAD rather than each dataset's own BEIR corpus, so topic overlap between
poison and background is lower than in a real deployment; these are published, non-adaptive
attacks; and the `prefix` result relies on a template signal an adaptive attacker can drop, so the
`noprefix` columns are the more meaningful ones. Treat the numbers as a sanity check, not a
security guarantee.
