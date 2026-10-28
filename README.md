# AgentDetox

Protection for what AI coding agents remember and obey. AgentDetox watches an agent's memory,
instruction and rules files, skills and config: it checks what the agent writes there, notices what
changes behind its back, and puts things back.

> **Status: preview.** Claude Code is supported. Codex and Cursor hooks are experimental, and
> OpenClaw gets tamper detection only. Developed and tested on macOS; Windows support is new and
> so far tested only in simulation. Where it is going:
> [ROADMAP.md](https://github.com/chriswu727/agentdetox/blob/main/ROADMAP.md).

Agents learn from web pages, files, emails and tool output, and some of it is written into memory
or rules that every later session trusts. One poisoned write can steer an agent for weeks, as
[Cisco's persistent-memory compromise of Claude Code](https://blogs.cisco.com/ai/identifying-and-remediating-a-persistent-memory-compromise-in-claude-code)
(April 2026) and MemGhost (arXiv 2607.05189, July 2026) showed. Today's models refuse much of the
obvious injected text they read. What they cannot see is a file changed behind their back, by a
dependency's install script or another program, which they then load as your instructions; and
smaller models still save planted text when asked to remember "the setup steps".

## See it

```bash
agentdetox demo
```

In a throwaway folder, with nothing else read or changed, the demo shows an agent trying to save a
planted instruction to its memory (blocked), a dependency's install script slipping the same
instruction into CLAUDE.md (reported to the agent at the next session, with the command that undoes
it), and the file being restored. It runs the real hooks, so it doubles as a self-test.

## Install

```bash
uv tool install agentdetox                # or: pipx install agentdetox
```

Then install the Claude Code plugin, from inside Claude Code:

```text
/plugin install agentdetox --marketplace chriswu727/agentdetox
```

or add the same hooks to your settings directly:

```bash
agentdetox install claude-code --apply    # adds three hooks to ~/.claude/settings.json, backed up first
```

Restart Claude Code to load the hooks. Use one route, not both: `install` declines when the plugin
is enabled, and `agentdetox doctor` warns if the hooks are registered twice. The plugin runs the
`agentdetox` you installed; without one it runs its own release through `uvx`, and with neither it
says so at session start instead of failing on every tool call.

A tool install keeps AgentDetox in an environment of its own; `pip install agentdetox` works too.
If you move Claude Code's folder with `CLAUDE_CONFIG_DIR`, AgentDetox follows it. The first session
scans what is already there before trusting it; `agentdetox agent scan` does the same at any time.

## What it does in Claude Code

- **Before a write** to memory, CLAUDE.md, rules, skills or config (through Write, Edit or a shell
  command such as a redirect, `tee`, `sed -i`, `cp`, `mv` or `rm`), the new content is checked.
  Planted instructions are denied, with the reason sent to the agent. If the flagged text is
  something you typed or pasted yourself, you are asked instead (hidden text is still denied, since
  you could not see what you pasted). An agent changing its own hooks,
  MCP servers or permissions needs your approval, and the prompt says exactly what is added or
  removed.
- **After the write**, the file is trusted as it now is.
- **At session start**, files changed outside the agent since the last session are compared with
  the snapshot. Suspicious changes are reported to the agent, which is told not to follow them and
  to tell you, with the command that restores each file. Edits you made yourself that look benign
  are accepted silently.

**Where memory came from.** A memory write that is mostly copied from web pages, MCP data, command
output or files the agent just read asks for approval, unless you asked the agent to remember it.
This is how text planted in an email or page usually reaches memory. Text the model rewrites in its
own words is not caught this way.

**What the rules look for** is what a benign memory almost never asks for: running code fetched
from the network, reverse shells, loosening the agent's own approvals or sandbox, reading
credentials, acting silently, standing orders to fetch a URL every session, hidden text, and
injection phrasing. Memory that points package installs at a registry other than the default ones
and the big public mirrors asks rather than blocks, since teams do run private registries. English
and Chinese.

**Cleaning up.** `agentdetox agent verify` shows what changed and why it is suspicious;
`agentdetox agent restore <file>` puts back the last trusted version and moves the current one to
`~/.agentdetox/quarantine`, never deleting it. Snapshot copies that no longer back any file are
deleted once a day (`agentdetox agent gc` does it now); quarantined files are kept. If the snapshot
list itself is damaged, or deleted while its copies remain, AgentDetox says so at every session
instead of quietly trusting whatever is on disk, until you check and run
`agentdetox agent snapshot --reset`.

## Day to day

```bash
agentdetox status                         # health, what is watched, how checks are set, recent activity
agentdetox events                         # everything blocked, asked, recorded or noticed
agentdetox log                            # every change to memory, rules and config, and where it came from
agentdetox blame ~/.claude/CLAUDE.md      # where each line of a file came from
agentdetox allow 3f9c2a1b7e               # stop flagging something you reviewed
agentdetox config copied record           # change a check
agentdetox doctor                         # check the hooks are installed, current and runnable
```

Each change AgentDetox sees is recorded with its origin: your own words, the agent, a web page or
tool output the agent copied (named), or a change made outside the agent's edit tools.
`agentdetox blame <file>` shows that per line; lines from before AgentDetox was installed show as
"earlier".

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
| `contradiction` | record | new memory that contradicts existing memory (experimental, below) |

The settings, the allowlist and the snapshots are guarded like the agent's own config: an agent
writing under `~/.agentdetox`, deleting it, or running `agentdetox allow`, `config <key> <value>`,
`install`, `uninstall`, `agent snapshot` or `agent restore` needs your approval, or an injected
instruction could switch a check off or allow itself.

Hooks fail open: if AgentDetox itself errors, the agent's action proceeds. If an attacker deletes
the hooks, the session-start check cannot run; `agentdetox agent verify` (by hand or in CI) still
reports the removal.

## What it does not catch

- Detection is not a security boundary. An adaptive attacker who knows these rules can evade them,
  and a plausible-looking false fact with nothing to contradict passes.
- Planted text the model rewrites in its own words before saving it, unless a rule still matches.
- A change made outside the agent is reported at the next session, not the moment it happens.
- The guard on AgentDetox's own settings recognises plain commands and file writes. An agent that
  can run arbitrary code can still change them (a script that edits `~/.agentdetox` is not
  inspected), and nothing stops a person or process outside the agent.
- On Windows the shell checks understand Git Bash commands (`/c/...` paths, `agentdetox.exe`), not
  PowerShell or cmd.exe syntax.

## Other agents

| Agent | Files watched | Write checks | Tamper detection |
|---|---|---|---|
| Claude Code | CLAUDE.md, CLAUDE.local.md, `.claude/rules`, AGENTS.md, auto memory, skills, subagents, commands, settings, `.mcp.json`, `~/.claude.json` | yes | yes |
| Codex | AGENTS(.override).md, `~/.codex/memories`, `.agents/skills`, `config.toml`, `hooks.json`, `rules/*.rules` | experimental (`install codex` prints the hook) | yes |
| Cursor | `.cursor/rules`, `.cursorrules`, AGENTS.md, `.cursor/skills`, `mcp.json`, `hooks.json` | experimental; Tab edits cannot be checked | yes |
| OpenClaw | AGENTS, SOUL, USER, IDENTITY, BOOT, MEMORY, daily memory, skills, `openclaw.json`, extensions | not yet (needs a plugin) | yes |

Codex and Cursor cannot ask mid-task: checks set to `ask` record instead, and changes to the
agent's own hooks, MCP servers or permissions are blocked. The provenance check needs Claude Code's
session transcript.

## Contradiction detection (experimental)

Optional: `uv tool install 'agentdetox[nli]'`, then `agentdetox fetch-models`. A memory write that
contradicts what the agent already knows is a common sign of a fabricated fact. This uses a
multilingual NLI model (mDeBERTa-v3, about 560 MB) and **records instead of asking**: after a
write, the hook hands the check to a background model server and returns (about 0.1 s), and
conflicts are logged (`agentdetox events`). The server loads the model on first use (about 1 GB of
memory) and exits after 30 minutes without work; `agentdetox daemon status` shows it. On real memory
the model still misreads fragments of notes as contradicting each other, which is why it does not
ask; `agentdetox config contradiction ask` makes it ask. Windows has no model server yet: each
related write starts a background worker that loads the model (about 6 s). The
[roadmap](https://github.com/chriswu727/agentdetox/blob/main/ROADMAP.md) replaces this model with
an LLM judge. Measurements:
[bench/MEMORY_BENCHMARK.md](https://github.com/chriswu727/agentdetox/blob/main/bench/MEMORY_BENCHMARK.md).

## Also: scanning a RAG knowledge base

```bash
pip install 'agentdetox[st]'                # drop [st] for a numpy-only install
agentdetox scan ./knowledge_base            # directory of .txt/.md/.html, or a .jsonl export
agentdetox trace kb.jsonl -q "Who founded Acme?" -a "Bob Smith"
```

Try it on the bundled example: `agentdetox scan examples/kb`.

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

`poison-cluster` implements CleanBase (Jin et al., arXiv 2605.00460): a k-nearest-neighbour
cosine-similarity graph (k=10), edges kept above mu + 2.5 sigma of a 50% edge sample, and every
passage in a clique of 3 or more flagged; exact duplicates are collapsed first. `trace` takes a
question and the wrong answer your system gave, ranks the top `4 x top-k` passages by the mean
z-score of similarity to the question, similarity to the wrong answer and whether the passage
contains the answer, and splits them with 1-D 2-means. It is a cheap approximation of RAGOrigin
(Zhang et al., IEEE S&P 2026); treat its output as a ranked lead list.

Limits: `poison-cluster` cannot see an attacker who plants only one or two passages per target
question or makes them deliberately dissimilar, and needs a few hundred passages to estimate its
threshold; `injection-phrase` will flag security documentation that quotes attacks; brute-force kNN
is fine for tens of thousands of passages, not millions. Measurements against PoisonedRAG and
other scanners:
[bench/KB_BENCHMARK.md](https://github.com/chriswu727/agentdetox/blob/main/bench/KB_BENCHMARK.md).

## Development

```bash
./scripts/check.sh       # lint, type checks and tests: what every change must pass
./scripts/update.sh      # the checks, then update the installed agentdetox, then `agentdetox doctor`
```

[CONTRIBUTING.md](https://github.com/chriswu727/agentdetox/blob/main/CONTRIBUTING.md) says where
each kind of change belongs, [docs/architecture.md](https://github.com/chriswu727/agentdetox/blob/main/docs/architecture.md)
how the pieces fit, and [docs/decisions.md](https://github.com/chriswu727/agentdetox/blob/main/docs/decisions.md)
why. [SECURITY.md](https://github.com/chriswu727/agentdetox/blob/main/SECURITY.md) covers reporting
and the threat model, [PRIVACY.md](https://github.com/chriswu727/agentdetox/blob/main/PRIVACY.md)
what is stored and read.

`lab/` replays attacks and everyday use against real Claude Code sessions, with and without
AgentDetox ([lab/README.md](https://github.com/chriswu727/agentdetox/blob/main/lab/README.md));
its latest results are in `lab/results/latest.md`.

How a hook call flows: `adapters.py` turns an agent's event into a planned write or a shell
command, `engine.py` runs the checks and reports signals, `policy.py` decides from your settings
and the agent's abilities whether to block, ask or record, and the adapter formats the reply.
`hooks.py` wires these together, and `session.py` runs the session-start check. The engine knows
nothing about agents, so a new integration needs only an adapter. The detectors are in
`hidden.py` and `persistence.py` (rules), `provenance.py` and `consistency.py` (contradictions).
The snapshot store is in `integrity.py`, and the model server in `daemon.py`.

Installed hooks call a fixed executable, so updating it takes effect on the next hook call with
no reinstall; a model server still running the old build is stopped by `update.sh`, and otherwise
replaces itself on its next job. Re-run `agentdetox install claude-code --apply` only when
`agentdetox doctor` says the registered hooks are from an older version. To remove everything:
`/plugin uninstall agentdetox` or `agentdetox uninstall claude-code`, `agentdetox daemon stop`,
then `uv tool uninstall agentdetox`, then delete `~/.agentdetox` (this also deletes quarantined
files).

The Claude Code plugin lives in `plugins/agentdetox` and the marketplace entry in
`.claude-plugin/marketplace.json`; `claude plugin validate .` checks both. Its version, the version
its hook script pins, and the package version must match (`tests/test_plugin.py`).

## License

Apache-2.0
