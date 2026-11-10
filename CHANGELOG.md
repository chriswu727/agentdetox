# Changelog

Notable changes to AgentDetox. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
before 1.0, a minor version may change commands, settings or the snapshot store.

## [Unreleased]

### Added

- `agentdetox library`: inspect an explicitly chosen folder of UTF-8 memory files
  (`.md`, `.markdown`, `.mdc`, `.txt`). `library scan` keeps a durable inventory in its own
  database, reads and hashes every candidate on every run, reruns the rules only for changed
  bytes or a changed detector (`--full` for all), and can be cancelled, killed and continued;
  `--background` uses a detached worker and reports a failed start. `library status` and
  `library review` show inspected, suspicious, low-only, queued, not-inspected, failed, stale
  and missing files, exclusions by extension and what the allowlist hides. Nothing is reported
  as clean, nothing is checkpointed, and session start does not read the inventory.
- `agentdetox clean M<ID>` removes chosen lines from an inspected library file through the
  existing preview hash, journal, quarantine and history (undo with `restore C<ID>`). It applies
  to the exact inspected version only and is refused on Windows, where the file's folder cannot
  be held open. The inventory records that a cleanup, not a scan run, inspected the cleaned bytes.
- A synthetic end-to-end library benchmark harness (`bench/library_eval.py`) and a library step
  in the installed-wheel journey.

### Security

- `restore`, `agent restore` and `clean` could write outside the reviewed location: a parent
  folder replaced by a symbolic link, before applying or at the final rename, redirected the
  write to a file with the same content elsewhere. On macOS and Linux they now open the file's
  folder once, without following links the user could repoint, and read, back up, replace and
  delete through that open folder; quarantine copies are written the same way and verified
  before the target is touched. A folder moved during a recovery leaves a failed operation with
  its backup, and nothing at the path's new target. **Behavior change:** a path that passes
  through a user-owned folder link (a linked project or `~/.claude`) is refused by these
  commands; system links such as `/tmp` on macOS are followed. Windows checks the path before
  and after each step, which narrows the gap without closing it. No compare-and-swap is claimed
  against another same-user program changing the same file in the same folder.
- An agent needs approval to run `library cancel` or `library scan --restart`.

### Changed

- Persist background contradiction jobs before waking the worker; recover after crashes and
  upgrades, retry up to three attempts, and retain failed jobs. Distinguish missing models,
  stalled queues and failures in doctor/status. Add `daemon retry`, seven-day retention and
  a visible 500-job queue limit. Explicit retry restarts workers after transient queue I/O errors.
- Add native Windows development check/update entry points while preserving Bash wrappers;
  make optional NLI dependencies explicit with `update.py --nli`.
- Gate Windows CI on lint, types, tests, offline galleries, distributions and the installed
  wheel lifecycle through Git Bash, including space/Unicode paths and mixed line endings.
- Make lab executable discovery, hook quoting, UTF-8 decoding and nested file outcome paths
  portable. Archive every run without overwriting failures and retain timeout outcomes.
- Reduce repeated Windows filesystem work by checking existing storage directories before
  creating them, while still repairing permissions. Hash unchanged files without decoding
  or reopening them, and load the NLI transport only when used.

### Fixed

- Selective cleanup applies its 1 MB limit before reading, at the preview and at every later
  check in the recovery, so a file (or recorded version) that is or has grown larger is refused
  without being loaded into memory. Whole-version restore is not limited.
- Prepare selective cleanup (reading, planning, rule scans) without the store lock and recheck
  the file under it, so a preview no longer makes other hooks wait. Cleaning a file that still is
  the recorded version, and listing changes to files with thousands of repeated lines, no longer
  take quadratic time; a change too large to compare within a budget is listed without line counts.
- Analyze narrowly recognized literal `printf '%s'`/`printf '%s\n'` and quoted `cat` heredoc writes to memory or
  instructions as prose, while scanning the remaining executable shell text independently.
  Benign quoted safety notes no longer produce a false high-severity block. Shell context
  writes still require approval; this does not bypass provenance or configuration guards.
- Bind pre-write external-change findings to the captured bytes and scan outside the global
  store lock; retry if another writer advances the ledger before recording.
- Detect bounded soft-wrapped instructions in memory and instruction files, preserving the
  original source lines for stable finding IDs and cleanup. Keep code and Markdown block
  boundaries separate, and retain safety-prohibition checks.
- Check substantive copied passages as well as whole writes, so ordinary surrounding notes
  cannot dilute a copied payload below the whole-write threshold. Scope remember requests
  to the referenced source or latest source for generic requests; unrelated preferences no
  longer exempt all tool outputs. This lexical check does not establish semantic consent.
- Avoid high-severity credential alerts for explicit SSH public-key/config paths and narrow
  secret-redaction guidance. Private keys, ambiguous suffixes, reversals and separate attacks
  remain checked. Apply contradiction candidate limits after eligibility and deduplication.
- Keep shell scripts and frozen fixture bytes unchanged by Git's Windows newline conversion.
  Write exact baseline bytes in offline evaluators and validate cleanup against native line
  endings. Frozen case content and expected labels are unchanged.
- Type-check platform lock imports on Windows and exercise deep-path recovery without
  depending on the host's system-wide long-path policy.
- Hash and scan the same captured bytes when comparing context with its checkpoint. A file
  changing between separate text/hash reads can no longer hide the version just observed.
- Default the entire test suite to a temporary user home as well as a temporary store, so
  tests that omit their own home fixture cannot read the host's Claude context.

### Documentation

- Add deterministic large-memory inventory/rule-scan fixtures and a staged scale, recovery
  and private maintainer-observation protocol. These are not production scale-support claims.
- Link the interactive walkthrough and clarify selective cleanup alongside whole-version recovery.
  Update the user guide to reflect that selective cleanup is available in 0.4.1.

## [0.4.1] - 2026-11-05

### Added

- Selective cleanup for memory, instructions and skills: list added lines with `clean C<ID>`,
  preview an explicit `--lines` selection, then apply only against the previewed file hash.
  Preserve other content and non-conflicting later edits; refuse changed, missing or ambiguous
  selected lines. Terminal review offers the same preview and confirmation flow.
- Cleanup preserves current permissions, quarantines the whole current file and records an
  undoable recovery with the selected lines. Rescan the result, resolve only removed rule
  findings and retain other evidence. Do not infer that copied text is malicious, advance a
  trusted checkpoint, restore overwritten text or perform line surgery on executable config.

### Fixed

- Reuse transcript token and shingle indexes across added lines and repeated tool outputs.
  Analyze provenance outside the global store lock, then recheck the file and ledger versions
  before committing. Retry concurrent changes without trusting unscanned bytes or losing history.
- Match snapshot version guards to the classified path, including writes through a symlinked
  project, so trusted writes do not leave stale checkpoints and trigger repeat notices.
- Route hook invocations through a small entry point instead of loading the complete command UI.
- Move optional contradiction candidate selection into the background worker. Queue the observed
  bytes so later edits cannot redirect a pending check to the wrong recorded version; unrelated
  candidates still do not load the model. Compare normalized line endings before queuing
  unchanged text, while retaining exact captured bytes for version matching.
- Do not request guardrail approval when creating a config file containing only inert metadata;
  newly added execution fields remain guarded. Source exceptions no longer erase attribution
  evidence for later files in the same hook, and copied-text excerpts are deterministic.
- Keep unresolved high-severity recovery findings visible at session start even when the remaining
  text was already in an accepted checkpoint and therefore absent from the incremental diff.
  Recovery notices distinguish reviewing remaining risks from undoing the recovery itself.
- Preserve other handlers and group settings when upgrading or removing AgentDetox hooks that
  share a group with user hooks. Rapid configuration updates keep distinct backups; temporary
  replacement files are private and cleaned up on failure.
- Invalid Claude settings produce an actionable install, uninstall or doctor error without a
  traceback or configuration rewrite. If uninstall removes hooks but cannot update recovery
  metadata, report both outcomes and the health check to run.
- Treat Claude Code's runtime feature caches as data rather than executable settings. A cached
  `statusLine` display string no longer produces a high-severity command alert; real settings
  and per-project MCP configuration remain guarded.
- Scope Claude settings, hooks and MCP command checks to their actual configuration fields;
  nested examples and metadata no longer count as commands or environment overrides. Cosmetic
  hook spinner text stays quiet, and MCP metadata changes stay reviewable without a false
  code-execution alert. Scan executable MCP `headersHelper` commands as well.
- Ignore order and duplicate entries in Claude permission lists and approved project MCP server
  lists; membership changes and command argument order remain guarded. Status line spacing and
  vim indicator visibility no longer request configuration approval.
- Recognize coordinated safety prohibitions and complete conditional approval reminders without
  exempting arbitrary later clauses or reversals. Treat natural-language fetch-and-pipe-to-shell
  instructions as high severity.
- Recognize direct English and Chinese safety prohibitions in visible memory and instructions,
  such as "never disable sandbox" and "不要关闭沙箱". Keep scanning later matches, ambiguous clauses,
  executable configuration, shell commands and hidden text conservatively.

### Quality checks

- Extend latency measurement to 100-line post-write checks, distinct large source outputs,
  concurrent writes plus shell observation, and the optional NLI queue frontend without inference.
  Concurrency tests verify lock availability and stale-version refusal independently of timing.
- Add independently authored, frozen acceptance fixtures separate from the development gallery,
  plus configuration-churn and selective-cleanup journeys. Keep known semantic misses visible.
- CI and releases exercise the built wheel in a fresh environment: preview, install, upgrade,
  repeated install, doctor, registered hook execution, review, recovery and uninstall, including
  paths with spaces and preservation of unrelated user settings. This does not test real-client
  hook delivery or make model calls.
- Release builds also run the offline detection gallery. Reports list prevention and monitoring
  misses, wrong blocks, unnecessary questions, exact restores and known gaps separately. Four
  direct safety-prohibition controls were added; passing the regression gate does not mean every
  authored attack was detected.

### Documentation

- English-first project home with a Simplified Chinese README, an illustrated workflow and a
  documentation index; detailed instructions remain in the user guide.
- Refresh installation commands, release guidance and published 0.4.0 status; distinguish
  historical benchmark records from current capabilities and retain their limitations.

## [0.4.0] - 2026-11-02

### Security

- The shell check no longer assumes a `cd` succeeded or an assignment ran: every folder entered and
  every value given earlier in the command is checked, and a write into a folder known only at run
  time is judged by its file name. A heredoc or `case` with unbalanced parentheses no longer makes
  the check fail (and so let the command through).
- More shell writes are stopped before they run: commands inside `bash -c`, `sh -c` and `eval`,
  also when `-c` is in a bundle such as `bash -lc` or `sh -ec`; behind `nice`, `timeout`, `xargs`,
  `env`, `sudo`, `ionice`, `taskset` or `chrt`, also with options that take a value
  (`sudo -u root`, `env -u X`, `timeout -s KILL 10`, `xargs -I {}`), also bundled (`sudo -Eu root`),
  and `env -S`; in the folder a wrapper switches to (`env -C .claude`, `sudo -D`, `sudo -i`); after a
  `cd` (also `cd -P`, `pushd -n`) or with a variable set earlier in the same command; `${HOME}` and
  globs; `git checkout -- <file>`, `git restore` and `git checkout .`, also after git's own options
  (`git -C .claude`, `-c`, `--work-tree`, `GIT_WORK_TREE`); a copy, move or link into a folder, which
  keeps the source's name (`cp x/CLAUDE.md .`, `cp -t .claude`, `ln -s x/CLAUDE.md`), or of a folder
  over one that holds context files (`cp -r`, `rsync`); the file `time -o` or `rsync --log-file`
  writes; `rm -r` of a folder that holds context files; `curl -o` and `wget -O`, also
  in bundles such as `-sSLo`; `perl -i`; and inline `python -c`, `node -e` and similar code that
  writes a file it names. The same applies to commands that change AgentDetox's own settings.
  `git restore --staged`, which only changes the index, is not asked about.
- A Write or Edit whose text contained `*** Begin Patch` was parsed as a Codex patch, so a
  planted CLAUDE.md write could skip the content check by including that marker. Only a call
  that names no target file is treated as a patch.
- A hook or hook script, helper or status line command, MCP server, plugin or marketplace added
  outside the agent, by an install script for example, is mentioned at the next session start
  instead of being accepted silently, including in a settings file that did not exist before. The
  notice names what was added, says there is nothing to do if you added it yourself
  (`claude mcp add`, `/plugin install`), and is given once; the change stays in review. An
  environment variable counts when it loads code or redirects traffic (`NODE_OPTIONS`,
  `*_BASE_URL`, proxies); any other is recorded quietly. AgentDetox's own hooks count only when
  they run this installation. A shell tool that adds such a setting gets the same wording.
- Agent writes that change `env`, helper commands or MCP auto-enable settings need approval, and
  setting an `AGENTDETOX_*` variable through them is denied.
- Watched files are matched by their real location and, on macOS and Windows, regardless of case,
  so writing `claude.md` or through a symlink is checked like writing `CLAUDE.md`.
- CLAUDE.md, CLAUDE.local.md and AGENTS.md in parent folders, output styles and `.claude/hooks`
  scripts are watched; a CLAUDE.md or AGENTS.md in any subfolder is checked when written. A hook
  script changed outside the agent is reported at the next session; logs and state files a hook
  keeps beside its script are not watched.
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

- The review list shows, for each file, who made its latest change (the agent, copied from a named
  source, outside the agent, or during a shell command), how many lines it added and removed, and
  its most serious open finding. Long memory-folder paths are shortened as in `agent log`. The
  same fields are in `--format json`.
- Immediate review of scoped context changes across successful or failed shell tools, with terminal notices,
  transactional start-state capture, parallel-call isolation and unknown-process attribution.
- Project-scoped review with file grouping, literal path/finding search and pagination beyond 200 changes.
- Interactive terminal review with file history, confirmation before acceptance/recovery, and stale-version checks.
- Review JSON pages include totals for the entire selection, operation/state counts and pagination metadata.
- Offline prevention, monitoring and recovery regression gallery with explicit known misses and a CI gate.

### Changed

- Session start no longer re-saves files whose trusted version is unchanged: with 1,000 watched
  files it takes about 130 ms (p50), down from 177 ms in 0.3.0, while watching more files
  (`bench/HOOK_LATENCY.md`).
- The store upgrades itself to format 3 on first use and keeps the previous database as
  `state.v1.sqlite3`, which 0.3.x can open again. A one-time step corrects the newest known
  version of files migrated from the 0.2 JSON store. 0.3.0 cannot open a format 3 store.
- A permission rule that Claude Code saves for the command being run, when you approve it and
  choose not to be asked again, is recorded without a mid-session notice or a review item.
- The accuracy gallery (`bench/ACCURACY.md`, run in CI) adds four attack families: shell commands,
  settings changed outside the agent, writes under another name or place, and notice injection.

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
- `doctor` run from the home folder no longer reports the same settings file twice, and shows the
  format the store is in rather than the newest one.
- `review accept` works on `~/.claude.json` and other settings that Claude Code rewrites at every
  start: it compares the security-relevant settings, not the whole file.
- Hooks registered twice (plugin and settings) no longer record a hook error for every shell command.
- `agentdetox uninstall`, for example when switching to the plugin, no longer leaves a security
  notice about AgentDetox's hooks being removed at every session. When nothing else in the file
  changed, the file without them becomes the new snapshot, as `install` does with them.
- Packages installed beside hook scripts (`node_modules`, `.venv`, `site-packages`, `__pycache__`,
  `.git`) are not watched, so `npm install` or `uv sync` in `.claude/hooks` no longer adds thousands
  of review items. A `.exe` there counts as a script on Windows.
- Session notices list at most ten items per section, so their guidance is never cut off.
- A setting a shell tool added is not mentioned again at the next session start.
- Hook scripts added outside the agent are named as such when `CLAUDE_CONFIG_DIR` moves the config
  folder, and deleting watched files is reported when that folder is outside the home folder.
- Changing a status line's options, or turning off `enableAllProjectMcpServers`, is no longer
  described as something new that runs. `NODE_PATH` and `CLASSPATH` count as variables that load
  code.
- Disabling a plugin is no longer reported as something new that runs.
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

[Unreleased]: https://github.com/chriswu727/agentdetox/compare/v0.4.0...HEAD
[0.4.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.4.0
[0.3.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.3.0
[0.2.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.2.0
[0.1.0]: https://github.com/chriswu727/agentdetox/commit/ba1cc83
