# Changelog

Notable changes to AgentDetox. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
before 1.0, a minor version may change commands, settings or the snapshot store.

## [0.2.0] - unreleased

The first release on PyPI. 0.1.0 was a knowledge-base scanner published on GitHub as `ragscan`;
0.2.0 renames it AgentDetox and extends it to what agents trust and reload: memory, rules,
instruction and skill files, and config.

### Added

- **Claude Code protection** (`agentdetox install claude-code`). Hooks check every write to
  memory, CLAUDE.md, rules, skills and config, including shell redirects, `tee`, `sed -i`, `cp`,
  `mv` and `rm`. Planted instructions are denied, unless you typed or pasted the text yourself,
  in which case you are asked. Changes to hooks, MCP servers or permissions (the prompt says what
  is added or removed), suspicious writes, and memory that points package installs at a
  non-default registry need your approval. At session start, files changed outside
  the agent since the last snapshot are reported with the command that restores each one.
  `CLAUDE_CONFIG_DIR` is followed.
- **Claude Code plugin** (`/plugin install agentdetox --marketplace chriswu727/agentdetox`), as an
  alternative to `install claude-code`. It runs the installed `agentdetox`, or its own release
  through `uvx`; `install` and `doctor` notice when both routes register the hooks.
- **Snapshots, tamper detection and restore** (`agentdetox agent snapshot|verify|restore|scan`).
  The store in `~/.agentdetox` is private (0700/0600). A restore quarantines the current file
  instead of deleting it.
- **`agentdetox demo`**: an attack caught and undone in a throwaway folder, using the real hooks.
  `install` ends by saying what is now watched.
- **Contradiction detection** (experimental; optional `nli` extra, then `agentdetox fetch-models`). A
  multilingual NLI model compares new memory with what the agent already knows. It records
  conflicts by default and asks only if you set it to. One background model server per store
  keeps the model loaded, so a write costs the hook about 0.1 s.
- **Provenance check.** A memory write mostly copied from web pages, MCP data, command output or
  files the agent just read asks for approval, unless you asked the agent to remember it.
- **Day-to-day commands.** `agentdetox status`, `events` (each with the command or file it was
  about), `doctor`, and `allow <id>` to
  permanently allow a reviewed false positive. `config <check> ask|record|off` sets each check;
  the settings live in `~/.agentdetox/config.toml`, and `AGENTDETOX_<CHECK>` overrides them.
- **Guard on AgentDetox's own state.** An agent needs approval to change AgentDetox's settings,
  allowlist or snapshots, or to run the commands that do.
- **Experimental hooks for Codex and Cursor.** OpenClaw gets tamper detection only.
- **Windows support**, so far tested only in simulation. Windows has no model server yet.
- **Benchmarks.** An agent memory poisoning benchmark (v0, built from public data only) and a
  provenance benchmark, in `bench/`.

### Security

- Background processes and the `python -m` hook fallback start Python with `-I`. Without it, a
  repository could plant an `agentdetox` package that the hook would import.

## [0.1.0] - 2026-10-27

Released on GitHub as `ragscan`. It scans RAG knowledge bases for hidden prompt injections and
PoisonedRAG-style poisoning (CleanBase clique detection), and traces wrong answers back to the
passages responsible.

[0.2.0]: https://github.com/chriswu727/agentdetox/compare/ba1cc83...main
[0.1.0]: https://github.com/chriswu727/agentdetox/commit/ba1cc83
