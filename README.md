<div align="center">

<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/agentdetox-mark.svg" alt="AgentDetox — a shield around persistent agent context" width="96" height="96">

# AgentDetox

### Protect your agent's memory: block known-risk writes, detect suspicious changes, and clean up unwanted instructions.

Protection for the memory, instructions, skills and config your coding agent trusts across sessions.

[![PyPI](https://img.shields.io/pypi/v/agentdetox?color=16836b)](https://pypi.org/project/agentdetox/)
[![CI](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml/badge.svg)](https://github.com/chriswu727/agentdetox/actions/workflows/ci.yml)
[![Python](https://img.shields.io/pypi/pyversions/agentdetox)](https://pypi.org/project/agentdetox/)
[![License: Apache-2.0](https://img.shields.io/badge/license-Apache--2.0-blue)](https://github.com/chriswu727/agentdetox/blob/main/LICENSE)

[Quick start](#quick-start) · [How it works](#how-it-works) · [Evidence](#evidence-and-limits) · [Documentation](https://github.com/chriswu727/agentdetox/blob/main/docs/README.md) · [Interactive demo](https://yichenwu.dev/projects/agentdetox)

**English (primary)** · [简体中文](https://github.com/chriswu727/agentdetox/blob/main/README.zh-CN.md)

</div>

---

A poisoned page can become tomorrow's memory. An install script can change `CLAUDE.md` while
your agent is busy elsewhere. Whatever lands in memory, rules or skills is obeyed in every later
session. AgentDetox checks writes to that persistent context, records changes with source
evidence, and lets you remove selected added lines or restore an earlier version, with a backup
either way.

**Try it in ten seconds, with nothing installed** (needs [uv](https://docs.astral.sh/uv/)):

```bash
uvx agentdetox demo          # an attack is blocked, noticed and undone, in a throwaway folder
uvx agentdetox agent scan    # read-only: check the memory, rules and skills your agents already have
```

<p align="center">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/demo.svg" alt="Abridged output of agentdetox demo: a write to memory that runs code fetched from the network is blocked; an install script's change to CLAUDE.md is noticed; the earlier version is restored and the tampered copy kept in quarantine" width="880">
</p>

- **Prevent:** a write to memory, rules or skills that matches a known attack is refused before
  it lands; text copied from a page or file the agent just read is asked about.
- **Detect:** changes made outside the agent (an install script, another tool) are noticed after
  the shell tool and at the next session start.
- **Clean up:** review the diff and where the text came from, remove only the lines you choose,
  or restore the earlier version. Nothing is deleted without a backup. A cleanup changes
  the file, not what a running session has already read: start a new session afterwards.
- **Optional, off by default:** a small model reads each write for what it would make the agent
  do. On attack texts written without sight of the rules it flagged 208 of 210, where the rules
  alone stop about a third
  ([measurements and limits](https://github.com/chriswu727/agentdetox/blob/main/bench/ACCURACY.md#a-model-as-judge-2026-11-10)).

**0.6.0 is published** on [PyPI](https://pypi.org/project/agentdetox/0.6.0/) and
[GitHub](https://github.com/chriswu727/agentdetox/releases/tag/v0.6.0). It is a **preview**,
and a layer of checks and recovery, [not a security boundary](#evidence-and-limits).
[Integration matrix →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#other-agents)

## Quick start

Requires **Python 3.11+**. Install with [uv](https://docs.astral.sh/uv/) or `pipx`:

```bash
uv tool install agentdetox
agentdetox demo
```

The demo uses real hook handlers in a temporary folder: a planted write is denied, shell tampering
is noticed, and the file is restored. It makes **no model calls** and consumes no agent subscription usage.

Connect Claude Code using **one** of these routes:

<details open>
<summary><b>Claude Code plugin</b></summary>

Run in your terminal:

```bash
claude plugin marketplace add chriswu727/agentdetox
claude plugin install agentdetox@agentdetox
```

The plugin uses your installed `agentdetox`. Without it, the plugin needs `uvx` to fetch and run
its pinned release from PyPI. Installing the CLI above also gives you review and recovery commands.

</details>

<details>
<summary><b>Direct hooks in Claude Code settings</b></summary>

```bash
agentdetox install claude-code --apply
```

This backs up and updates your Claude Code settings. AgentDetox follows `CLAUDE_CONFIG_DIR`.
Use this route as an alternative to the plugin.

</details>

Restart Claude Code, then check the installation:

```bash
agentdetox doctor
agentdetox status
```

On Windows, install Git for Windows: shell-write analysis reads Git Bash syntax, not PowerShell
or cmd.exe ([Windows validation](docs/windows-validation.md)).

`doctor` reports missing, outdated or duplicate hooks. The first session scans existing context
before recording recovery checkpoints. [Installation, upgrades and removal →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#install)

## How it works

<p align="center">
<picture>
<source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow-mobile.svg">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow.svg" alt="Check planned writes; notice context changes; review diffs and source evidence; restore an earlier version with a backup" width="880">
</picture>
</p>

1. **Before a write:** check planned Write/Edit content and recognized shell writes. High-risk
   rule matches are denied; flagged text you supplied yourself asks instead, except hidden text. Changes to hooks,
   MCP servers, permissions and other guardrails need approval.
2. **After a write or shell tool:** retain versions and source evidence. Shell completion or
   failure triggers a scoped comparison and a review notice for changed context. The interval
   identifies when a change happened; it does not prove which process wrote it.
3. **At session start:** reconcile changes made outside the agent. Flagged content is reported
   until reviewed. Newly added runnable settings are mentioned once and stay in review.
4. **When you review:** inspect the diff and evidence, accept that exact version, dismiss a finding,
   remove selected added lines, or restore the version before a change. Recovery checks for newer
   edits and backs up the current file.

Watched Claude context includes `CLAUDE.md`, parent instructions, auto memory, rules, skills,
subagents, commands, output styles, hook scripts, settings and MCP config.
Rules cover English and Chinese. [Full coverage and behavior →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#what-it-does-in-claude-code)

### A review you can act on

```bash
agentdetox review --interactive           # browse this project's files in a terminal
agentdetox review --project . --since 7d  # recent project and auto-memory changes
agentdetox review C42                    # inspect a change id from your review list
agentdetox restore C42                   # preview the version before that change
agentdetox restore C42 --apply           # back up the current file and restore
```

`C42` is an example id; use the id shown by your own review list. Acceptance and dismissal never
grant permanent trust to a source. Recovery restores a **whole recorded version**, which can also
undo benign additions. For a newly added config entry, removing it with the tool that added it
is often preferable to restoring the whole settings file.

`agentdetox clean C42` lists the lines a change added to memory, instructions or skills;
`agentdetox clean C42 --lines 3,5-7` previews removing only those, keeping everything else.
Run the exact apply command printed by that preview. Cleanup backs up the file and rescans it;
it does not choose lines for you, restore overwritten text or judge whether text is true.
[Review, settings and recovery details →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#day-to-day)

<a id="what-it-does-not-catch"></a>

## Evidence and limits

AgentDetox is a layer of checks and recovery, **not a security boundary or a factual verifier**.
Paraphrased payloads and plausible false facts can pass. Arbitrary scripts and dynamically built
paths may escape pre-execution checks; scoped post-tool observation can detect persistent changes
afterwards. Detached background writes need later reconciliation. Hooks fail open on errors,
which remain visible in `doctor` and `status`; a write to agent context that could not be checked asks instead. Code running as your user can alter the hooks or store.

The measurements below are dated runs on authored or synthetic cases, not real-world accuracy
or production-support guarantees.

- **Offline regression gallery:** authored prevention, monitoring and byte-exact recovery cases,
  plus a separate 21-case acceptance set with three explicit semantic misses.
  [Protocol and results](https://github.com/chriswu727/agentdetox/blob/main/bench/ACCURACY.md).
- **Claude Code lab:** on the 0.5.0 candidate (2026-11-10), 12 scenarios run with and without
  AgentDetox passed 23 of 24 checks. On the 0.6.0 candidate (2026-11-11), with AgentDetox only,
  9 of 12 passed: in one run of five, a later memory write naming a non-default registry got
  through after the first had been asked about; the other two failures were the client's or the
  model's own.
  [Results](https://github.com/chriswu727/agentdetox/blob/main/lab/README.md#060-candidate-2026-11-11).
- **Hook latency, 2026-11-11:** 100 samples per case on one Mac, no NLI inference, on the 0.6.0
  candidate before its last commits. All 12 budgets passed: Bash pre/post P95 **109.1 ms**;
  startup with 1,000 unchanged files **121.7 ms**; four concurrent writes plus a Bash pair
  **235.5 ms**.
  [Raw data](https://github.com/chriswu727/agentdetox/blob/main/bench/results/hooks-0.6.0-2026-11-11.json) ·
  [method and limits](https://github.com/chriswu727/agentdetox/blob/main/bench/HOOK_LATENCY.md).
- **100k synthetic inventory, 2026-11-10:** full/incremental inspection, cancellation/resumption
  and scoped dismissal/reopening passed. About 419 MB of notes took **316 s** for first inspection,
  **15.3 s** unchanged, with **46.8 MB** process peak RSS.
  [Protocol and raw report](https://github.com/chriswu727/agentdetox/blob/main/bench/LARGE_MEMORY.md#100k-completion-and-scoped-triage).

Source matching is evidence of copied text, not proof of malicious intent or human authorship.
An empty rescan does not certify a file as safe.
[Full limitations](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#what-it-does-not-catch) ·
[Threat model](https://github.com/chriswu727/agentdetox/blob/main/SECURITY.md)

### Local processing, sensitive history

Hooks and checks make no network calls, with one exception you have to turn on: the optional
model check (`config judge`, or `agent inspect --judge`) sends the text it reads to a model
through your Claude Code. There is no telemetry or account. Installation, the
plugin's `uvx` fallback and optional model downloads need network access. File copies and source
evidence stay in `~/.agentdetox`; copies of config files can contain secrets. Back up the entire
store, including `objects/`, and review retention before deleting history.
[Privacy and stored data →](https://github.com/chriswu727/agentdetox/blob/main/PRIVACY.md)

## More workflows

- **Other agents:** experimental Codex and Cursor hooks; no OpenClaw plugin, and Cursor has not been run.
  `agentdetox agent inspect` finds the memory, rules and skill files of Claude Code, Codex, Cursor and
  OpenClaw where each client keeps or relocates them and records what is flagged as review items, so
  `clean` and `restore` work without any hook. It checks files, not whether a client delivers hook
  events or whether remembered text is true.
  [Integration matrix](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#other-agents).
- **A model's reading (off by default):** `agentdetox config judge ask` has a
  small model read each write to memory, rules and skills for what it would make the agent do;
  it catches what the rules' wordings miss and can only add a question.
  [What it costs and what it is not](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#a-models-reading-of-each-write-optional).
- **Contradiction checks:** optional local NLI, recorded in the background by default because of
  false positives. [Setup and limits](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#contradiction-detection-experimental).
- **Existing memory libraries:** `agentdetox library scan <folder>` inventories
  a folder you choose, inspects its text files with the per-file rules, resumes after interruption
  and never calls a file clean; `clean M<ID>` removes reviewed lines with a backup, and
  `library dismiss` sets a false positive aside for one file's exact bytes without allowlisting it.
  [Library guide](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#inspecting-a-library-of-memory-files).
- **RAG knowledge bases:** `agentdetox scan` for hidden instructions and suspicious passage clusters;
  `trace` ranks leads behind a wrong answer. [Scanner guide](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#also-scanning-a-rag-knowledge-base).

## Documentation and development

[Documentation index](https://github.com/chriswu727/agentdetox/blob/main/docs/README.md) ·
[User guide](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md) ·
[Changelog](https://github.com/chriswu727/agentdetox/blob/main/CHANGELOG.md) ·
[Roadmap](https://github.com/chriswu727/agentdetox/blob/main/ROADMAP.md) ·
[Contributing](https://github.com/chriswu727/agentdetox/blob/main/CONTRIBUTING.md)

```bash
./scripts/check.sh  # lint, type checks and tests
```

See [architecture](https://github.com/chriswu727/agentdetox/blob/main/docs/architecture.md) and
[design decisions](https://github.com/chriswu727/agentdetox/blob/main/docs/decisions.md) before
changing the hook or recovery path. The offline gallery makes no model calls; real-agent lab
runs require explicit authorization and a session cap.

Licensed under [Apache-2.0](https://github.com/chriswu727/agentdetox/blob/main/LICENSE).
