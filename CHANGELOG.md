# Changelog

Notable changes to AgentDetox. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
before 1.0, a minor version may change commands, settings or the snapshot store.

## [Unreleased]

### Security

- A Write or Edit whose text contained `*** Begin Patch` was parsed as a Codex patch, so a
  planted CLAUDE.md write could skip the content check by including that marker. Only a call
  that names no target file is treated as a patch.
- A hook, helper command (`apiKeyHelper` and the like), MCP server, environment variable or plugin
  added outside the agent is reported at the next session start instead of being accepted
  silently. AgentDetox's own hooks count only when they run this installation.
- Agent writes that change `env`, helper commands or MCP auto-enable settings need approval, and
  setting an `AGENTDETOX_*` variable through them is denied.
- Watched files are matched by their real location and, on macOS and Windows, regardless of case,
  so writing `claude.md` or through a symlink is checked like writing `CLAUDE.md`.
- CLAUDE.md, CLAUDE.local.md and AGENTS.md in parent folders, output styles and `.claude/hooks`
  scripts are watched; a CLAUDE.md or AGENTS.md in any subfolder is checked when written. A hook
  script changed outside the agent is reported at the next session.
- Claude Code hooks take the project root from `CLAUDE_PROJECT_DIR`, so a session working in a
  subfolder still guards the project's CLAUDE.md and `.claude/` settings.
- File names, flagged lines and config values shown to the agent or in the terminal have line
  breaks, terminal escapes and other invisible characters shown as `\uXXXX`, so a planted file
  name cannot add a fake line to AgentDetox's notice or hide text from a reviewer.
- When a shell tool writes content that a rule flags, the immediate notice says so and tells the
  agent not to follow it, instead of the neutral "writing process unknown" message.
- A process holding AgentDetox's store lock no longer lets writes through unchecked: the content
  check still runs when the bookkeeping before a write times out, and session start reports that
  the store is locked instead of saying nothing.

### Added

- Immediate review of scoped context changes across successful or failed shell tools, with terminal notices,
  transactional start-state capture, parallel-call isolation and unknown-process attribution.
- Project-scoped review with file grouping, literal path/finding search and pagination beyond 200 changes.
- Interactive terminal review with file history, confirmation before acceptance/recovery, and stale-version checks.
- Review JSON pages include totals for the entire selection, operation/state counts and pagination metadata.
- Offline prevention, monitoring and recovery regression gallery with explicit known misses and a CI gate.

### Fixed

- Session start compares and scans without holding the store lock, taking it only to record the
  result, so parallel hooks no longer wait on it (or time out during a contradiction check in
  `ask` mode). A file that changes while the check runs is left for the next check instead of
  being trusted unread.
- The newest known version of a file is taken from the order changes were recorded, not by
  comparing local timestamps, so a clock change (daylight saving, travel) cannot make AgentDetox
  credit the agent with a change made outside it, or the reverse.
- `agentdetox agent restore` uses the same recovery as `review`: it is journalled, refuses to
  overwrite a file that changed while it ran, and records the result in one transaction.
- Codex `apply_patch` writes are recorded after they are applied, instead of appearing as changes
  made outside the agent at the next session.
- `python -m agentdetox.cli review` and the other review commands no longer fail with `NameError`.
- A store write requested inside a read-only connection fails at once with a clear error, and an
  event logged there is kept instead of lost.
- Diff-like `++` content no longer escapes write and observation checks.
- A quoted attack example no longer hides a later active instruction matched by the same rule.
- Negated, quoted and recollected remember phrases no longer automatically exempt copied writes;
  later explicit revocation overrides an earlier save request.
- Findings sharing an anchor retain the highest observed severity.
- `doctor` run from the home folder no longer reports the same settings file twice.
- Review-based recovery warns about residual rule findings, retains them for review and does not
  advance the safe checkpoint to a version with unsuppressed high findings.

## [0.3.0] - 2026-10-30

### Added

- `review`: diffs and evidence, exact-version acceptance, per-finding dismissal and `--since 7d` summaries.
- `restore C<ID>` previews recovery; `--apply` backs up the current file and refuses stale versions.
- Transactional SQLite metadata with indexed history, validated legacy migration and unchanged original files.
- Separate observed writers, per-added-line text attribution, recovery checkpoints and accepted versions.
- Copied-source and background contradiction findings attached to their observed changes.
- JSONL export and opt-in history pruning that preserves pending, accepted and recovery-critical records.
- Recovery operation journaling and explicit acknowledgement of investigated health failures.

### Changed

- Load numerical libraries only for checks that use them. Five hook latency cases meet their documented
  P95 budgets with 100 samples each on the reference Mac; see `bench/HOOK_LATENCY.md`.
- Real-agent lab results distinguish command attempts, confirmed execution, notification and task completion.
- The demo now exercises review, recovery preview and explicit application.


### Fixed

- Preserve deleted files’ recovery checkpoints and report disabled Claude Code hooks.
- Validate recovery copies before changing files, preserve permissions and use unique quarantine backups.
- Report hook failures in events, doctor and status; optional models no longer count as health failures.

## [0.2.0] - 2026-10-28

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
- **Ledger** (`agentdetox log`, `agentdetox blame <file>`). Every change to a watched file is
  recorded with where it came from: your own words, the agent, a named web page or tool output it
  copied, or a change made outside the agent's edit tools. The versions before and after are kept,
  so `blame` can say where each line came from.
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
- **Windows support**, tested in CI but not yet on a real machine. Windows has no model server yet.
- **Benchmarks and an evaluation lab.** An agent memory poisoning benchmark (v0, built from public
  data only) and a provenance benchmark, in `bench/`. The lab in `lab/` replays attacks and
  everyday use against real Claude Code sessions, with and without AgentDetox.

### Security

- Background processes and the `python -m` hook fallback start Python with `-I`. Without it, a
  repository could plant an `agentdetox` package that the hook would import.

## [0.1.0] - 2026-10-27

Released on GitHub as `ragscan`. It scans RAG knowledge bases for hidden prompt injections and
PoisonedRAG-style poisoning (CleanBase clique detection), and traces wrong answers back to the
passages responsible.

[0.2.0]: https://github.com/chriswu727/agentdetox/compare/ba1cc83...main
[0.1.0]: https://github.com/chriswu727/agentdetox/commit/ba1cc83
