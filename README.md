# ragscan

Scan a RAG knowledge base for poisoned passages and planted prompt injections before
they reach your retriever, and trace a bad answer back to the passages that caused it.

```bash
pip install 'ragscan[st] @ git+https://github.com/chriswu727/ragscan'   # drop [st] for a numpy-only install
ragscan scan ./knowledge_base            # directory of .txt/.md/.html, or a .jsonl export
ragscan trace kb.jsonl -q "Who founded Acme?" -a "Bob Smith"
```

Try it on the bundled example: `ragscan scan examples/kb`.

## What it detects

| Detector | What it catches | How |
|---|---|---|
| `hidden-unicode` | ASCII smuggled in invisible Unicode tag characters (decoded and shown), zero-width characters splitting words, bidi controls | deterministic |
| `hidden-html` | Text hidden with `display:none`, `font-size:0`, white text or `hidden`, and HTML comments that carry instructions | deterministic |
| `injection-phrase` | Instruction overrides, "don't tell the user", chat-template tokens, exfiltration instructions with a destination, text addressed to the AI. English and Chinese | deterministic |
| `exfil-link` | Markdown images whose URL has a templated query, the zero-click exfiltration channel behind EchoLeak-style attacks | deterministic |
| `question-template` | Three or more different passages that open with the same question, which is how PoisonedRAG's black-box attack builds its passages | deterministic |
| `poison-cluster` | Groups of mutually similar passages written to push one false answer, even without the question prefix | CleanBase clique detection |
| `duplicate-text` | The exact same text repeated many times | deterministic |

`scan` exits with status 1 when any finding is at least `--fail-on` severity (default `high`),
so it can gate ingestion in CI. A similarity clique on its own is reported as `medium`, because
legitimately repetitive content (versioned docs, templated pages) also forms cliques; it becomes
`high` only for members that also open with a question or carry injection markers. Use
`--fail-on medium` if you want paraphrase-only poisoning to block ingestion too.

## Benchmark

Clean background: 5,225 Wikipedia paragraphs from SQuAD v1.1 (`bench/fetch_squad.py`).
Poison: the adversarial texts released with PoisonedRAG (Zou et al., USENIX Security 2025),
100 target questions x 5 passages = 500 per dataset. `prefix` is the black-box attack as published
(target question prepended); `noprefix` drops the question, approximating an attacker who only
paraphrases. Reproduce with `bench/poisonedrag_eval.py`.

### Compared with per-document scanners

Detection rate on each attack set (`bench/compare.py`). Per-document tools are scored leniently:
any alert counts. Indirect-injection sets embed the 263 injection-labelled prompts of
[deepset/prompt-injections](https://huggingface.co/datasets/deepset/prompt-injections) (English
and German) into clean passages, in four forms.

| Tool | NQ prefix | NQ noprefix | HotpotQA prefix | HotpotQA noprefix | MS MARCO prefix | MS MARCO noprefix | Injection plain | hidden HTML | Unicode tags | zero-width | Clean FPR |
|---|---|---|---|---|---|---|---|---|---|---|---|
| Veritensor 1.9.4 | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 0.0% | 3.8% | 100.0% | 0.0% | 0.0% | 0.1% |
| ProtectAI deberta-v3 PI v2 | 0.4% | 1.2% | 0.0% | 0.0% | 0.2% | 0.4% | 11.4% | 33.8% | 0.0% | 10.6% | 0.1% |
| ragscan 0.1 (high) | 100.0% | 0.0% | 100.0% | 0.0% | 100.0% | 0.0% | 5.7% | 10.6% | 100.0% | 10.3% | 0.0% |
| ragscan 0.1 (medium+) | 100.0% | 89.2% | 100.0% | 98.0% | 100.0% | 92.0% | 10.6% | 96.6% | 100.0% | 99.6% | 2.6% |

What this shows:

- Neither per-document tool detects knowledge poisoning: PoisonedRAG passages contain no attack
  string, only a fluent false claim. Detecting them takes cross-document analysis.
- Plain-text injection phrased in ways no rule anticipates is hard for everyone, ragscan included.
  The ProtectAI classifier flags 41.4% of the same prompts on their own, so burying a prompt in a
  benign passage dilutes it (only 2 of 263 documents exceed its 512-token window).
- Veritensor flags any `display:none`, so it catches every hidden-HTML document; ragscan reports
  hidden text as `medium` unless the hidden text itself matches an injection rule.
- Llama Prompt Guard 2 is a gated model and was not evaluated; run
  `bench/compare.py DATA --tools promptguard2` after `huggingface-cli login`.

### False positives on a clean corpus

Scanning the 5,225 clean paragraphs alone gives no `high` findings and 2.6% `medium`
(`poison-cluster`) with MiniLM, 3.9% with `hashing`. 31 of the 35 clean clusters are paragraphs of
the same Wikipedia article. Per-run false-positive rates measured with poison present are lower
(0.3 to 0.9%) because the poison cliques raise the similarity threshold; the clean-only figure is
the one to expect in practice.

### `trace`

Averaged over the 100 target questions per dataset (MiniLM): precision 0.84 to 0.94, recall 0.94
to 1.00.

With the numpy-only `hashing` embedder, `prefix` recall is unchanged but `noprefix` recall drops
to 0.32 to 0.74. Install the `st` extra if paraphrased poisoning matters to you.

Caveats: the clean corpus is SQuAD rather than each dataset's own BEIR corpus, so topic overlap
between poison and background is lower than in a real deployment; these are published,
non-adaptive attacks; and the `prefix` result relies on a template signal an adaptive attacker can
drop, so the `noprefix` columns are the more meaningful ones. Treat the numbers as a sanity check,
not a security guarantee.

## How `poison-cluster` works

It implements the CleanBase algorithm (Jin et al., arXiv 2605.00460): build a k-nearest-neighbour
cosine-similarity graph (k=10), keep edges above mu + 2.5 sigma of a 50% edge sample, and flag every
passage in a clique of 3 or more. Exact duplicates are collapsed first so repeated boilerplate does not
form trivial cliques.

## How `trace` works

`trace` takes a question and the wrong answer your system gave. It ranks an attribution scope
(the top `4 x top-k` passages by similarity to the question) by the mean z-score of three signals:
similarity to the question, similarity to the wrong answer, and whether the passage literally
contains the wrong answer. A 1-D 2-means split marks the likely responsible passages.

This is a cheap approximation of RAGOrigin (Zhang et al., IEEE S&P 2026), which uses an LLM's
log-probabilities for two of its signals. Treat its output as a ranked lead list for investigation.

## Limits

- Detection is not a security boundary. An adaptive attacker who knows these rules can evade them.
- `poison-cluster` cannot see an attacker who plants only one or two passages per target question,
  or who deliberately makes them dissimilar (both are limits stated by the CleanBase paper).
- `injection-phrase` patterns are a starting set and will flag security documentation that quotes
  attacks.
- The clique threshold is estimated from the corpus itself, so `poison-cluster` needs a few hundred
  passages to be meaningful; on tiny corpora only the deterministic detectors fire.
- Brute-force kNN is O(n^2); it is fine for tens of thousands of passages, not millions.

## License

Apache-2.0
