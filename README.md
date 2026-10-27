# ragscan

Scan a RAG knowledge base for poisoned passages and planted prompt injections before
they reach your retriever, and trace a bad answer back to the passages that caused it.

```bash
pip install 'ragscan[st]'                # or plain `ragscan` for a numpy-only install
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

Poison recall / clean false-positive rate, with the default `all-MiniLM-L6-v2` embedder:

| Dataset | Attack | Recall (high) | Recall (medium+) | FPR (high) | FPR (medium+) | `trace` precision / recall |
|---|---|---|---|---|---|---|
| NQ | prefix | 1.000 | 1.000 | 0.000 | 0.44% | 0.94 / 1.00 |
| NQ | noprefix | 0.000 | 0.892 | 0.000 | 0.86% | 0.94 / 1.00 |
| HotpotQA | prefix | 1.000 | 1.000 | 0.000 | 0.31% | 0.93 / 1.00 |
| HotpotQA | noprefix | 0.000 | 0.980 | 0.000 | 0.56% | 0.93 / 1.00 |
| MS MARCO | prefix | 1.000 | 1.000 | 0.000 | 0.38% | 0.84 / 0.97 |
| MS MARCO | noprefix | 0.000 | 0.920 | 0.000 | 0.78% | 0.83 / 0.94 |

With the numpy-only `hashing` embedder, `prefix` results are the same (recall 1.000, FPR up to
0.75%), but `noprefix` recall drops to 0.32 to 0.74. Install the `st` extra if paraphrased
poisoning matters to you.

Caveats: the clean corpus is SQuAD rather than each dataset's own BEIR corpus, so topic overlap
between poison and background is lower than in a real deployment; and these are the published,
non-adaptive attacks. Treat the numbers as a sanity check, not a security guarantee.

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
