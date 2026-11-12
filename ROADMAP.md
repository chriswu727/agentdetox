# Roadmap

Last updated 2026-11-12. Current release:
[0.6.0](https://github.com/chriswu727/agentdetox/releases/tag/v0.6.0). What has shipped is in
the [changelog](CHANGELOG.md). This file lists only open work.

## Direction

AgentDetox tracks the persistent context that coding agents reload: memory, rules, skills and
security-relevant config. Its value is a reviewable history and recoverable versions, with
detection evidence attached to changes. Claude Code remains the primary supported agent.

Attribution is evidence, not proof of authorship, and a change made outside the agent is worth
reviewing but is not automatically malicious. A working command is not evidence of accurate
detection, and an attack caught in a fixture is not evidence that installation works for a new
user.

## Planned, not started

- An MCP server exposing read-only checks (scan, the review list, a change's detail), for
  clients that have no hooks.
- A skill, so that an agent knows how to run review and cleanup when the user asks for them.
- Lower hook latency on Windows by avoiding a new process for each hook. Seven of twelve
  budgets are still exceeded there ([measurements](bench/HOOK_LATENCY.md)).
- A blind test of whether the model check points at the right lines. Today only a hand spot
  check of nine attacks exists ([details](bench/ACCURACY.md#which-lines-2026-11-11)).
- Deciding whether the model check should be on by default. It is off because each checked
  write costs a model call and sends its text to the user's model provider.

## Detection

- Paraphrased, delayed, mixed-source and consolidated writes. The rules stop about a third of
  blind attack text and no paraphrase; text the agent rewords before saving, and text the user
  pastes in person, rest on the rules and the optional model check.
- A plausible false fact needs trusted evidence to verify it. The contradiction model is not a
  reliable factual judge, and the model check does not judge truth.
- A new blind set for any further rule change: the sealed half of the current one is spent.
- Associate changed context with the later sessions that loaded it, once transcript evidence
  supports it.

## Reach

- Cover what the client file checks do not reach: Codex's SQLite memory state, Claude Code
  `@path` imports and `autoMemoryDirectory`, OpenClaw `$include` files, and an OpenClaw plugin
  that checks writes as they happen.
- Verify the Codex and Cursor hooks on real installs; `install --apply` stays refused for both
  until then.
- Remove one added hook, MCP server or permission from a config file, and put back a line that a
  change replaced. Today config can only be restored as a whole file, and `clean` removes lines
  without reinstating what they replaced.
- Library inspection: a false-positive review on a real library, applying cleanup on Windows,
  checks that need context across files (contradictions, duplicates, attribution), and
  database or vector-store adapters ([protocol](bench/LARGE_MEMORY.md)).
- PowerShell and cmd.exe shell syntax on Windows, where only Git Bash is analysed.

## Teams and CI

- Repository policy files and a PR check for changes to instructions, rules, skills and MCP config.
- SARIF output, a pre-commit hook and a GitHub Action.
- Portable attribution metadata without embedding private transcript content in commits.

These need validation in a real team's repository before being described as supported.

## Measurements

Quiet normal use, recoverable data, visible failure and local storage guide the work. Measure
wrong blocks and unnecessary questions, time to resolve a review, restore data loss,
installation time, and P95 hook latency with documented fixtures. Block a release on a failed
installed-wheel journey, a new regression or a hook error, and keep acknowledged misses visible
in every accuracy report. Still to measure through sustained use: whether weekly review stays
useful after several weeks, and false alarms per user per week. Automated scenarios cannot
establish those.
