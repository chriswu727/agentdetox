# AgentDetox

Poisoning protection for what AI agents know. AgentDetox detects, blocks and cleans planted
instructions and fabricated facts in the places agents trust and reload: memory files, rules and
instruction files, and knowledge bases.

> **Status: early development.** Claude Code protection and the knowledge-base scanner work
> today. Codex and Cursor hooks are experimental; OpenClaw and WorkBuddy get tamper detection only.

Agents learn from web pages, files, emails and tool output, and some of it is written into memory
or rules that every later session trusts. One poisoned write can steer an agent for weeks, as
[Cisco's persistent-memory compromise of Claude Code](https://blogs.cisco.com/ai/identifying-and-remediating-a-persistent-memory-compromise-in-claude-code)
(April 2026) and MemGhost (arXiv 2607.05189, July 2026) showed. Per-document scanners
look for attack strings; AgentDetox also compares entries against each other, because a fabricated
fact contains no attack string at all.

## Protect an agent

```bash
pip install 'agentdetox @ git+https://github.com/chriswu727/agentdetox'
agentdetox install claude-code            # prints the settings change; add --apply to write it
agentdetox agent scan                     # scan memory, rules, skills and config now
```

Once installed, three hooks run inside Claude Code:

- **Before a write** to memory, CLAUDE.md, rules, skills or config (via Write, Edit or a shell
  redirect), the new content is checked. Planted instructions are denied with the reason sent to
  the agent; an agent changing its own hooks, MCP servers or permissions needs your approval.
- **After a checked write**, the file is re-trusted, so the snapshot only lags behind writes that
  bypassed the agent.
- **At session start**, files changed outside the agent (an npm postinstall script, another
  process) are compared with the snapshot. Suspicious changes are reported to the agent, which is
  told not to follow them and to tell you; benign edits you made yourself are accepted silently.
  The first run scans everything before trusting it.

Clean up with `agentdetox agent verify` (what changed, and why it is suspicious) and
`agentdetox agent restore <file>` (put back the snapshot; the current file is quarantined under
`~/.agentdetox/quarantine`, never deleted). Snapshot copies that no longer back any file are
deleted once a day (`agentdetox agent gc` does it now); quarantined files are kept. If the snapshot
list itself is damaged, or deleted while its copies remain, AgentDetox says so at every session
instead of quietly trusting whatever is on disk, until you check and run
`agentdetox agent snapshot --reset`.

| Agent | Files watched | Write blocking | Tamper detection |
|---|---|---|---|
| Claude Code | CLAUDE.md, CLAUDE.local.md, `.claude/rules`, AGENTS.md, auto memory, skills, subagents, commands, settings, `.mcp.json`, `~/.claude.json` | yes | yes |
| Codex | AGENTS(.override).md, `~/.codex/memories`, `.agents/skills`, `config.toml`, `hooks.json`, `rules/*.rules` | experimental (`install codex` prints the hook) | yes |
| Cursor | `.cursor/rules`, `.cursorrules`, AGENTS.md, `.cursor/skills`, `mcp.json`, `hooks.json` | experimental; Tab edits cannot be blocked | yes |
| OpenClaw | AGENTS, SOUL, USER, IDENTITY, BOOT, MEMORY, daily memory, skills, `openclaw.json`, extensions | not yet (needs a plugin) | yes |
| WorkBuddy | `~/.workbuddy` memory and identity files (paths unverified) | no public hook API | yes |

**Contradiction detection** (optional, `pip install 'agentdetox[nli]'` then `agentdetox fetch-models`):
a memory write that contradicts what the agent already knows is a common sign of a fabricated fact.
It uses a multilingual NLI model (mDeBERTa-v3, about 560 MB). **By default it records instead of
asking**: after a write, the hook hands the check to a background model server and returns
(about 0.1 s), and conflicts are logged (`agentdetox events`). The server loads the model on first
use (about 1 GB of memory), keeps it while memory is being written, and exits after 30 minutes
without work; `agentdetox daemon status` shows it. Writes with nothing related in memory never wake
it. On the v0 benchmark it catches 28% of fabricated facts that conflict with existing memory, but on
real memory the model still misreads fragments, which is why it does not ask;
`agentdetox config contradiction ask` makes it ask (about 0.5 s per related write once the server
is up, 3 s for the first). See [bench/MEMORY_BENCHMARK.md](bench/MEMORY_BENCHMARK.md).

**Provenance check** (Claude Code): a memory write that is mostly copied from web pages, MCP data, command
output or files the agent just read asks for approval unless you asked it to remember. This is how
text planted in an email or page usually reaches memory. On the v0 benchmark it flags 67-97% of copied
injection prompts (5.6% without it) with no false alarm on benign writes in the agent's own words, after
"remember this", or from text you pasted; text the model paraphrases is not caught.

Detection rules target what a benign memory almost never asks for: running code fetched from the
network, reverse shells, loosening the agent's own approvals or sandbox, reading credentials,
acting silently, standing orders to fetch a URL every session, plus the hidden-text and
injection detectors below. English and Chinese.

### Day to day

```bash
agentdetox status                         # health, what is watched, how checks are set, recent activity
agentdetox events                         # everything blocked, asked, recorded or noticed
agentdetox allow 3f9c2a1b7e               # stop flagging something you reviewed
agentdetox config copied record           # change a check
agentdetox daemon status                  # the background contradiction model server
```

Every message from AgentDetox carries an id. If what it flagged is fine, `agentdetox allow <id>`
stops it being flagged again in write checks, session notices and scans alike. An id stands for the
flagged line, the pair of contradicting entries, or the source text was copied from (that file, page
or command), not for one occurrence; `agentdetox allow --list` and `--remove` review and undo.

Settings live in `~/.agentdetox/config.toml` (`agentdetox config` shows them). Each check is `ask`,
`record` (the write goes through and is logged) or `off`; agents without an ask prompt record
instead of asking. An `AGENTDETOX_<KEY>` environment variable overrides the file.

| Key | Default | Check |
|---|---|---|
| `suspicious` | ask | writes that look like planted instructions but are not clear-cut |
| `copied` | ask | memory copied from untrusted input the agent just read |
| `contradiction` | record | new memory that contradicts existing memory |

Clear-cut planted instructions are always blocked; allowing the id is the way past a false
positive. The settings, the allowlist and the snapshots are guarded like the agent's own config: an
agent writing under `~/.agentdetox`, deleting it, or running `agentdetox allow`, `config <key>
<value>`, `install`, `uninstall`, `agent snapshot` or `agent restore` needs your approval, or an
injected instruction could switch a check off or allow itself.

Hooks fail open: if AgentDetox itself errors, the agent's action proceeds. If an attacker deletes
the hooks, the session-start check cannot run; `agentdetox agent verify` (by hand or in CI) still
reports the removal.

## Scan a knowledge base

```bash
pip install 'agentdetox[st] @ git+https://github.com/chriswu727/agentdetox'   # drop [st] for a numpy-only install
agentdetox scan ./knowledge_base            # directory of .txt/.md/.html, or a .jsonl export
agentdetox trace kb.jsonl -q "Who founded Acme?" -a "Bob Smith"
```

Try it on the bundled example: `agentdetox scan examples/kb`.

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
paraphrases. Reproduce with `bench/fetch_data.sh`, then `bench/compare.py bench/data`.

### Compared with per-document scanners

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
- The guard on AgentDetox's own settings recognises plain commands and file writes. An agent that
  can run arbitrary code can still change them (a script that edits `~/.agentdetox` is not
  inspected), and nothing stops a person or process outside the agent.
- `poison-cluster` cannot see an attacker who plants only one or two passages per target question,
  or who deliberately makes them dissimilar (both are limits stated by the CleanBase paper).
- `injection-phrase` patterns are a starting set and will flag security documentation that quotes
  attacks.
- The clique threshold is estimated from the corpus itself, so `poison-cluster` needs a few hundred
  passages to be meaningful; on tiny corpora only the deterministic detectors fire.
- Brute-force kNN is O(n^2); it is fine for tens of thousands of passages, not millions.

## Development

```bash
./scripts/update.sh      # run the tests, update the installed agentdetox, then `agentdetox doctor`
```

Installed hooks call a fixed executable, so updating it takes effect on the next hook call with
no reinstall; a model server still running the old build is stopped by `update.sh`, and otherwise
replaces itself on its next job. Re-run `agentdetox install claude-code --apply` only when
`agentdetox doctor` says the registered hooks are from an older version. To remove everything:
`agentdetox uninstall claude-code`, `agentdetox daemon stop`, then `uv tool uninstall agentdetox`, then
delete `~/.agentdetox` (this also deletes quarantined files).

## License

Apache-2.0
