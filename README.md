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
your agent is busy elsewhere. AgentDetox checks writes to persistent context, records changes
with source evidence, and lets you remove selected added lines or restore an earlier version,
with a backup either way.

**0.4.1 is published** on [PyPI](https://pypi.org/project/agentdetox/0.4.1/) and
[GitHub](https://github.com/chriswu727/agentdetox/releases/tag/v0.4.1).
The project is in **preview**: Claude Code is supported; Codex and Cursor hooks are experimental;
OpenClaw has tamper detection only. Development supports native Windows with Python 3.12 and
Git Bash, alongside macOS/Linux. Windows offline validation covers the installed-wheel lifecycle;
real-client and sustained daily-use validation remain separate. See [Windows evidence](docs/windows-validation.md).
Native Windows latency measurements still exceed several existing budgets; the
[performance record](bench/HOOK_LATENCY.md) retains failures and paired optimization results.

<p align="center">
<picture>
<source media="(max-width: 600px)" srcset="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow-mobile.svg">
<img src="https://raw.githubusercontent.com/chriswu727/agentdetox/main/assets/workflow.svg" alt="Check planned writes; notice context changes; review diffs and source evidence; restore an earlier version with a backup" width="880">
</picture>
</p>

## Quick start

Requires **Python 3.11+**. Install with [uv](https://docs.astral.sh/uv/) or `pipx`:

On Windows, install Git for Windows for Claude's Bash tool. PowerShell can launch these CLI
commands, but AgentDetox's shell-write analysis supports Git Bash syntax; PowerShell/cmd.exe
syntax is not supported. Windows uses background NLI workers, without a resident model server.
Native development commands are in [CONTRIBUTING.md](CONTRIBUTING.md#setup-and-checks).

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

`doctor` reports missing, outdated or duplicate hooks. The first session scans existing context
before recording recovery checkpoints. [Installation, upgrades and removal →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#install)

## How it works

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

`agentdetox clean C42` lists added lines.
Use `agentdetox clean C42 --lines 3,5-7` to preview removing only the lines you selected from
memory, instructions or skills, while keeping other content and non-conflicting later edits.
Run the exact apply command printed by that preview; a changed file invalidates it. Cleanup
backs up the current file and rescans the result. It does not automatically select copied text,
restore overwritten text or judge factual correctness. The terminal review also offers this action.
[Review, settings and recovery details →](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#day-to-day)

<a id="what-it-does-not-catch"></a>

## Evidence and limits

AgentDetox is a layer of checks and recovery, **not a security boundary or a factual verifier**.
Paraphrased payloads and plausible false facts can pass. Arbitrary scripts and dynamically built
paths may escape pre-execution checks; scoped post-tool observation can detect persistent changes
afterwards. Detached background writes need later reconciliation. Hooks fail open on errors,
which remain visible in `doctor` and `status`. Code running as your user can alter the hooks or store.

- **Offline regression gallery:** authored prevention, monitoring and byte-exact recovery cases,
  plus a separate 21-case acceptance set with three explicit semantic misses. These are not
  real-world accuracy estimates.
  [Protocol and results](https://github.com/chriswu727/agentdetox/blob/main/bench/ACCURACY.md).
- **Real Claude Code lab, 2026-11-09:** two development scenarios passed their final checks
  using four sessions, including two retained quiet-use failures and a clarified editing-only
  scenario. This supplements the ten-scenario 0.4.1 acceptance; it is not a full rerun.
  Guardrail success and user-task completion are reported separately.
  [Recorded results](https://github.com/chriswu727/agentdetox/blob/main/lab/results/latest.md).
- **Development latency, 2026-11-10:** 100 samples per case on one Mac, no NLI inference.
  All 12 original budgets passed both idle and during a library scan. Under that scan load,
  Bash pre/post P95 was **112.6 ms**; startup with 1,000 unchanged files **135.4 ms**;
  four concurrent writes plus a Bash pre/post pair **306.4 ms**. Earlier failures remain retained.
  [Method, raw data and limits](https://github.com/chriswu727/agentdetox/blob/main/bench/LARGE_MEMORY.md#hook-latency-during-inspection).

Source matching is evidence of copied text, not proof of malicious intent or human authorship.
An empty rescan does not certify a file as safe.
On development `main`, `agentdetox library` inspects an existing folder of memory files and
cleans reviewed lines; it is measured against a separate
[scale protocol](https://github.com/chriswu727/agentdetox/blob/main/bench/LARGE_MEMORY.md),
whose 1k/10k/100k tiers are not current production-support guarantees.
[Full limitations](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#what-it-does-not-catch) ·
[Threat model](https://github.com/chriswu727/agentdetox/blob/main/SECURITY.md)

### Local processing, sensitive history

Hooks and checks make no network calls. There is no telemetry or account. Installation, the
plugin's `uvx` fallback and optional model downloads need network access. File copies and source
evidence stay in `~/.agentdetox`; copies of config files can contain secrets. Back up the entire
store, including `objects/`, and review retention before deleting history.
[Privacy and stored data →](https://github.com/chriswu727/agentdetox/blob/main/PRIVACY.md)

## More workflows

- **Other agents:** experimental Codex and Cursor hooks; OpenClaw tamper detection.
  [Integration matrix](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#other-agents).
- **Contradiction checks:** optional local NLI, recorded in the background by default because of
  false positives. [Setup and limits](https://github.com/chriswu727/agentdetox/blob/main/docs/user-guide.md#contradiction-detection-experimental).
- **Existing memory libraries (development `main`):** `agentdetox library scan <folder>` inventories
  a folder you choose, inspects its text files with the per-file rules, resumes after interruption
  and never calls a file clean; `clean M<ID>` removes reviewed lines with a backup.
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
