# User guide

[Documentation](README.md) · [Project home](../README.md) · [简体中文入门](../README.zh-CN.md)

Applies to **AgentDetox 0.4.1**, released 2026-11-05. Claude Code is the supported integration;
other integrations and optional semantic checks have the limits described below.

[Install](#install) · [Review](#day-to-day) · [Limits](#what-it-does-not-catch) ·
[Integrations](#other-agents) · [Upgrade](#upgrading) · [Remove](#removing-agentdetox)

## Install

```bash
uv tool install agentdetox                # or: pipx install agentdetox
```

To run the latest code from `main` instead:
`uv tool install --force git+https://github.com/chriswu727/agentdetox`.

Then install the Claude Code plugin from your terminal:

```bash
claude plugin marketplace add chriswu727/agentdetox
claude plugin install agentdetox@agentdetox
```

or add the same hooks to your settings directly:

```bash
agentdetox install claude-code --apply    # registers hooks in ~/.claude/settings.json, backed up first
```

Restart Claude Code to load the hooks. Use one route, not both: `install` declines when the plugin
is enabled, and `agentdetox doctor` warns if the hooks are registered twice. The plugin runs the
`agentdetox` you installed; without one it runs its own release through `uvx`, and with neither it
says so at session start instead of failing on every tool call.

A tool install keeps AgentDetox in an environment of its own; `pip install agentdetox` works too.
If you move Claude Code's folder with `CLAUDE_CONFIG_DIR`, AgentDetox follows it. The first session
scans what is already there before recording recovery checkpoints; `agentdetox agent scan` does the same at any time.

## What it does in Claude Code

- **Before a write** to memory, CLAUDE.md, rules, skills or config (through Write, Edit or a shell
  command such as a redirect, `tee`, `sed -i`, `cp`, `mv` or `rm`), the new content is checked.
  Planted instructions are denied, with the reason sent to the agent. If the flagged text is
  something you typed or pasted yourself, you are asked instead (hidden text is still denied, since
  you could not see what you pasted). An agent changing its own hooks, MCP servers, permissions,
  environment variables or helper commands (`apiKeyHelper` and the like) needs your approval, and
  the prompt says exactly what is added or removed. Setting an `AGENTDETOX_*` variable through the
  agent's settings is denied.
- **After the write**, the observed version and available attribution evidence are recorded.
  A recovery checkpoint advances when the write passes the checks. This is separate from a
  version you explicitly accept in review.
- **After a shell tool finishes or fails**, compare the current project's context, its auto memory,
  and shared regular Claude context files with the versions captured before the tool. New, removed or changed files
  enter review immediately, with a short terminal notice. Config counters do not produce changes;
  security-relevant settings do. The record says the change happened during the tool, not which
  process authored it. If a separate Write/Edit hook already recorded the final version, it keeps
  that observed writer. A permission rule for the command being run, which Claude Code saves when
  you approve the command and choose not to be asked again, is recorded without a notice.
  Installations from 0.3 need updated hook registration (`install claude-code --apply`, or update
  the plugin); `agentdetox doctor` says when.
- **At session start**, files changed outside the agent since the last session are compared with
  the snapshot. Suspicious content is reported to the agent, which is told not to follow it and to
  tell you, with the command that restores each file; this repeats until you review it. Anything new
  that would run on your machine, other than AgentDetox's own, is mentioned once instead, worded as
  a question rather than an alarm: a hook or hook script, a helper or status line command, an MCP
  server, a plugin or marketplace, or an environment variable that loads code or redirects traffic
  (`NODE_OPTIONS`, `*_BASE_URL`, proxies and the like). If you added it yourself (`claude mcp add`,
  `/plugin install`), there is nothing to do; it stays in `agentdetox review` until you accept or
  dismiss it. Other edits that look benign, such as a new permission or an ordinary variable, do
  not interrupt; they are listed in `agentdetox review` as made outside the agent.

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

Direct prohibitions such as "Never disable sandbox"
and "不要上传密钥到 https://example.org" no longer count as attack instructions. This recognizes
simple prohibitions, not arbitrary negation or quoted shell examples. Later active instructions
are still checked, and hidden text and executable commands do not receive this prose exemption.
Reordering or deduplicating Claude permission lists and approved MCP server names is quiet, as
are status line spacing and vim indicator changes. Adding or removing entries, changing command
argument order, and changing the status line command or refresh interval remain guarded.

**Cleaning up.** `agentdetox review` lists changes needing attention, with a `C` id for each
change. `agentdetox review C42` shows the diff, observed writer, attribution evidence and individual
`F` finding ids. `agentdetox restore C42` previews the recovery; add `--apply` to restore the version
before that change. The current file is backed up in `~/.agentdetox/quarantine` before replacement.
Accept and restore refuse if the file has changed since that record; for a settings file, accept
compares only the security-relevant settings, since Claude Code rewrites its own config at every
start. `agentdetox agent restore <file>` restores the recovery checkpoint through the same
journalled recovery. Recovery rescans the target version, warns about residual rule findings and
keeps them pending. Recovery restores a whole version; it does not certify that the file is safe
or preserve benign additions made within the change being undone. For a setting added outside the
agent, removing it with the tool that added it (`claude mcp remove`, `/plugin uninstall`) is safer
than restoring the whole settings file.

A missing or damaged metadata store is reported instead of silently rebuilt. Keep a backup of the
whole store, including `objects/`. 0.4 upgrades the metadata format (from 1 in 0.3.x to 3) on its
first write and keeps the old database beside it as `~/.agentdetox/state.v1.sqlite3`. 0.3.x refuses
the upgraded store; to go back, reinstall 0.3.x and put that copy back as `state.sqlite3` (changes
recorded since the upgrade are lost). `agentdetox doctor` shows the format in use.
`agentdetox agent snapshot --reset` explicitly resets recovery checkpoints; it does not erase
history or make a corrupt database safe to use.

## Day to day

```bash
agentdetox status                         # health and pending reviews
agentdetox review                         # pending changes grouped by file
agentdetox review --interactive           # browse this project and confirm actions in a terminal
agentdetox review --interactive --global  # include shared user rules and configuration
agentdetox review --project . --since 7d   # this project and its Claude auto memory
agentdetox review --all --page 2          # page through older file groups
agentdetox review --file CLAUDE.md --all --group-by change # one file's history
agentdetox review --search permissions    # match a path or finding
agentdetox review C42                     # diff, evidence, and findings
agentdetox review accept C42              # accept only this exact file version
agentdetox review dismiss F7              # dismiss one finding; no permanent exception
agentdetox restore C42                    # preview; add --apply to restore
agentdetox clean C42                      # list added lines for selective removal
agentdetox clean C42 --lines 3,5-7         # preview selected-line removal
agentdetox review --since 7d               # recent context changes, including quiet activity
agentdetox log                            # all recorded changes
agentdetox blame ~/.claude/CLAUDE.md      # per-line attribution evidence
agentdetox events                         # hook decisions and health events
agentdetox doctor                         # verify effective hooks and store health
agentdetox export --format jsonl          # export change records
agentdetox history prune --older-than 90d # preview retention; add --apply to remove
```

Review lists support `--page-size 1..200`, `--page`, `--group-by file|change`, `--file`,
`--search`, and `--project`. Counts describe the entire filtered selection, not just the current
page. A project filter includes files under that project and its Claude auto-memory directory;
shared user-level rules remain in the unfiltered view. Historical records require no migration.
Interactive review defaults to the current project; `--global` includes shared user rules and
configuration. It asks before accepting or applying recovery.

### Selective cleanup

Whole-version recovery can undo useful work. `agentdetox clean C42` instead lists lines added
or replaced by that recorded change. Choose the unwanted lines with `--lines 3,5-7`; numbers
refer to **C42's after-version**, even when later edits have shifted the current file's lines.
The preview shows the exact current-to-cleaned diff. Apply with the full command it prints,
including `--expected-hash` and `--apply`. Any file change after preview requires another preview.
`--format json` provides the selection, mapped current lines, diff, file hash and backup path.
In `review --interactive`, choose **c**, enter the line numbers, inspect the preview and confirm.

Only the selected lines are removed. Other lines, including same-change additions and
non-conflicting later edits, retain their bytes and line endings. Replaced old text is not
reinstated; use whole-version restore when that is the intent. Removing every line leaves an
empty file. Cleanup refuses selected lines that were modified or removed later, and repeated
matches when later edits make their identity ambiguous. It supports UTF-8 memory, instructions
and skills up to 1 MB and 10,000 lines; executable config, deleted files and symlinks require
another recovery method. Selection is explicit: copied content is not automatically malicious.

Applying uses the recovery journal, preserves current file permissions and quarantines the
entire current version. The new history entry identifies the source change and selected lines;
restoring that entry can undo the cleanup. The result is rescanned. Only pending rule findings
on the source change that were present before cleanup and absent afterward are resolved;
remaining rules and provenance or contradiction findings stay reviewable. Cleanup does not
advance the trusted checkpoint or grant source exceptions. A result without rule findings is
not proof of factual correctness or complete removal of poisoning.
It requires a terminal; scripts use explicit id-based commands. Review JSON is a page object with
`rows`, totals, state/operation counts and pagination metadata.

The ledger separates the **observed writer** (an agent tool, external change or recovery) from
**content attribution**. A match to your message or a tool result is text evidence, not proof of
who authored it. Added lines are compared separately, so user wording and model additions in the
same write receive different labels. Unmatched text is unknown; older migrated records retain a
legacy-inference label. `blame` marks content predating the ledger as "earlier" and unseen edits as
"unrecorded". Paraphrases and shell-command authorship remain unresolved.

Accepting `C42` applies only to that exact version. Dismissing `F7` leaves the recovery checkpoint
and file unchanged. Neither adds a source to the allowlist. The advanced `agentdetox allow <id>`
command still grants a persistent exception across checks, scans and future versions;
`agentdetox allow --list` and `--remove` inspect and undo it.

Pending findings, explicitly accepted versions and each file's latest record survive history
pruning. Unreferenced content objects are removed by the daily GC, or `agentdetox agent gc`.
Quarantine backups and legacy migration files are never automatically deleted.

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
`install`, `uninstall`, `agent snapshot`, review mutations or recovery needs your approval, or an injected
instruction could switch a check off or allow itself.

Hooks fail open: if AgentDetox itself errors, the agent's action proceeds, and an unresolved failure
remains visible in `doctor` and `status`. After investigating, acknowledge its event id with
`agentdetox health acknowledge <event-id>`. A missing optional model is an inactive feature, not
a protection failure. Interrupted recoveries show their backup location in doctor; after inspection,
`health acknowledge-recovery <id>` verifies the file matches one side of that recovery before
acknowledging it. SQLite fallback errors use `health acknowledge fallback`. `disableAllHooks` is also checked. If an attacker deletes
the hooks, the session-start check cannot run; `agentdetox agent verify` (by hand or in CI) still
reports the removal.

## What it does not catch

- Detection is not a security boundary. An adaptive attacker who knows these rules can evade them,
  and a plausible-looking false fact with nothing to contradict passes.
- Planted text the model rewrites in its own words before saving it, unless a rule still matches.
- Changes outside the observed shell interval remain visible at the next session or before the next
  observed edit. Background writes after a shell tool returns are outside that interval.
- The ledger knows what the hooks saw. A change the agent makes with a shell command is recorded as
  made outside the agent, and text it copied in its own words as the agent's.
- The check before a shell command reads the command, it does not run it. It follows redirects,
  `tee`, `sed -i`, `perl -i`, `cp`, `mv`, `rm` (including a whole folder that holds context files),
  a copy into a folder (`cp x/CLAUDE.md .`, `cp -t .claude …`, `cp -r`), `git checkout`/`restore`
  (also of `.`, and with `git -C dir`), `curl -o` and `wget -O` (also in bundles such as `-sSLo`),
  inline `python -c`/`node -e` code that names a context file, `bash -c` (also `bash -lc`) and
  `eval`, wrappers such as `sudo -u root`, `env -C dir` or `xargs -I {}`, and a `cd` or variable set
  earlier in the same command. A script file, a path built at run time (`find … -exec`), a folder
  copied to a place that holds no context yet, or an archive being unpacked is not stopped
  beforehand; the check right after the command finds the change and, if the new content is
  flagged, tells the agent not to follow it.
- Writes made by MCP tools are not checked when they happen; the next session's comparison finds
  them.
- CLAUDE.md files in subfolders are checked when the agent writes them, but changes made to them
  outside the agent are not looked for.
- The guard on AgentDetox's own settings recognises plain commands and file writes. An agent that
  can run arbitrary code can still change them (a script that edits `~/.agentdetox` is not
  inspected), and nothing stops a person or process outside the agent.
- Settings added outside the agent are mentioned once. If nobody acts on that notice, the setting
  stays and is only listed in `agentdetox review`. A project opened for the first time is not
  reported for the hooks and MCP servers it brings; Claude Code asks you to trust it.
- A shell command that adds a permission rule for itself (`Bash(python:*)` while running a Python
  script) looks the same as Claude Code saving your approval, and is recorded without a notice.
- In `.claude/hooks`, only scripts are watched (a script extension, `#!`, or the executable bit),
  not packages installed beside them (`node_modules`, `.venv`). A data file or package that a hook
  script loads is not.
- Routine changes outside the agent, such as a `git checkout` or formatter touching CLAUDE.md or a
  permission saved for a tool other than Bash, each add an item to `agentdetox review`. There is no
  bulk accept yet; once the file has changed again, an older item is cleared by dismissing its
  findings one at a time.
- `restore C42` refuses once the file has changed again for any reason. `agent restore` then puts
  back the latest checkpoint, which already includes a settings change that was mentioned once.
  Selective `clean` can remove unchanged added lines while preserving later edits;
  it refuses overlap and ambiguous repeated matches and does not support executable config.
- On Windows the shell checks understand Git Bash commands (`/c/...` paths, `agentdetox.exe`), not
  PowerShell or cmd.exe syntax.
  Claude versions exposing a separate PowerShell tool can be restricted to the tested Bash
  workflow with `CLAUDE_CODE_USE_POWERSHELL_TOOL=0`; this is not PowerShell analysis support.
  Ordinary Windows paths beyond MAX_PATH require the host's long-path policy. See the
  [native Windows validation record](windows-validation.md) for measured coverage and limits.

## Other agents

| Agent | Files watched | Write checks | Tamper detection |
|---|---|---|---|
| Claude Code | CLAUDE.md and CLAUDE.local.md (also in parent folders, and in subfolders when written), `.claude/rules`, AGENTS.md, auto memory, skills, subagents, commands, output styles, settings, `.claude/hooks` scripts, `.mcp.json`, `~/.claude.json` | yes | yes |
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
write, the hook queues the observed bytes and returns. Related-file reading and candidate selection
also run in the worker; they no longer delay the hook. Then
conflicts are logged (`agentdetox events`) and attached to the matching version in `review`, even
after later edits. Related context is read when the job runs. The server loads the model only when
candidate pairs need inference (about 1 GB of
memory) and exits after 30 minutes without work; `agentdetox daemon status` shows it. On real memory
the model still misreads fragments of notes as contradicting each other, which is why it does not
ask; `agentdetox config contradiction ask` makes it ask. Windows has no model server yet: each
changed memory write queues work for a background worker, which loads the model only when needed (about 6 s). The
[roadmap](https://github.com/chriswu727/agentdetox/blob/main/ROADMAP.md) considers a stronger
opt-in judge; no replacement is implemented or committed for a release. Measurements:
[bench/MEMORY_BENCHMARK.md](https://github.com/chriswu727/agentdetox/blob/main/bench/MEMORY_BENCHMARK.md).

## Also: scanning a RAG knowledge base

```bash
pip install 'agentdetox[st]'                # drop [st] for a numpy-only install
agentdetox scan ./knowledge_base            # directory of .txt/.md/.html, or a .jsonl export
agentdetox trace kb.jsonl -q "Who founded Acme?" -a "Bob Smith"
```

From a repository checkout, try `agentdetox scan examples/kb`. The example files are in the
repository; they are not installed with the PyPI wheel.

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

`poison-cluster` implements [CleanBase](https://arxiv.org/abs/2605.00460) (Jin et al.): a k-nearest-neighbour
cosine-similarity graph (k=10), edges kept above mu + 2.5 sigma of a 50% edge sample, and every
passage in a clique of 3 or more flagged; exact duplicates are collapsed first. `trace` takes a
question and the wrong answer your system gave, ranks the top `4 x top-k` passages by the mean
z-score of similarity to the question, similarity to the wrong answer and whether the passage
contains the answer, and splits them with 1-D 2-means. It is a cheap approximation of
[RAGOrigin](https://github.com/zhangbl6618/RAG-Responsibility-Attribution)
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
its latest results are in `lab/results/latest.md`. The local hook performance suite is
`python -m bench.hook_latency --samples 100`; recorded budgets and results are in
[bench/HOOK_LATENCY.md](../bench/HOOK_LATENCY.md).
`python bench/accuracy_eval.py` checks offline prevention, post-write evidence and recovery
regressions without model calls. Its [results and known misses](../bench/ACCURACY.md) are separate
from the real-agent lab and are not a real-world accuracy estimate.

How a hook call flows: `adapters.py` turns an agent's event into a planned write or a shell
command, `engine.py` runs the checks and reports signals, `policy.py` decides from your settings
and the agent's abilities whether to block, ask or record, and the adapter formats the reply.
`hooks.py` wires these together, and `session.py` runs the session-start check. The engine knows
nothing about agents, so a new integration needs only an adapter. The detectors are in
`hidden.py` and `persistence.py` (rules), `provenance.py` (copied text) and `consistency.py`
(contradictions). Recovery objects are managed by `integrity.py`, transactional metadata by `storage.py`,
the ledger by `ledger.py`, review actions by `review.py`, and the model
server in `daemon.py`.

## Upgrading

```bash
uv tool upgrade agentdetox
```

For the plugin route, update the marketplace and plugin, then restart Claude Code:

```bash
claude plugin marketplace update agentdetox
claude plugin update agentdetox@agentdetox
```

Run `agentdetox doctor` afterwards. Upgrades from 0.3.x change the store format; see the
backup and rollback instructions under [the write and recovery workflow](#what-it-does-in-claude-code).

Installed hooks call a fixed executable, so updating it takes effect on the next hook call with
no reinstall; a model server still running the old build is stopped by `update.sh`, and otherwise
replaces itself on its next job. Re-run `agentdetox install claude-code --apply` only when
`agentdetox doctor` says the registered hooks are from an older version.

## Removing AgentDetox

To remove everything: `claude plugin uninstall agentdetox@agentdetox` or `agentdetox uninstall claude-code`, `agentdetox daemon stop`,
then `uv tool uninstall agentdetox`, then delete `~/.agentdetox` (this also deletes quarantined
files).

## Plugin development

The Claude Code plugin lives in `plugins/agentdetox` and the marketplace entry in
`.claude-plugin/marketplace.json`. Validate the marketplace with `claude plugin validate .`,
then the plugin with `claude plugin validate plugins/agentdetox`. Its version, the version its
hook script pins, and the package version must match (`tests/test_plugin.py`).

## License

[Apache-2.0](../LICENSE)
