# Changelog

Notable changes to AgentDetox. The format follows [Keep a Changelog](https://keepachangelog.com/en/1.1.0/);
before 1.0, a minor version may change commands, settings or the snapshot store.

## [Unreleased]

### Changed

- `agent scan` with nothing flagged says so in its first line and how to check writes as they
  happen; clients that are not on the machine are listed in one line instead of one each.
- The READMEs open with two commands that need nothing installed and a picture of the demo.
- The hint after a clean scan and at the end of `demo` names the command that installs
  (`agentdetox install claude-code --apply`); without `--apply` it only previews.
- Documentation brought up to 0.6.0: the roadmap lists only open work, the privacy, security
  and architecture pages cover the model check, and the measurements quoted agree across files.

### Removed

- Four functions nothing called, a benchmark script from the first release that needed data
  the repository does not hold, and result files no document refers to.

## [0.6.0] - 2026-11-12

### Added

- An optional model check of each write to memory, rules and skills: `agentdetox config judge
  ask` (or `record`; off by default). The text a write adds is read by a small model, through
  the Claude Code the user is logged in to, for what it would make the agent do. It is asked
  in a new session with no tools, no MCP servers and no user settings; only one of a few fixed
  words is taken from its answer; it is asked after the rules and can add a question, never
  remove one; a text it flagged stays flagged; a failed call is no opinion and shows in
  `doctor`. With it on, a session start also reads what changed outside the agent, and
  `agentdetox agent inspect --judge` reads every memory, rules and skill file on request.
  What the rules refuse stays refused whatever the model says. The last 5,000 flags are kept.
  Measured with real calls as shipped: 208 of 210 attack texts were flagged (89 of 90 of the
  blind set, and 60 of 60 and 59 of 60 of two sets written to get past a model; the rules alone
  stop about a third), with 6 of 210 short ordinary texts and 3 of 120 whole ordinary files.
  It costs a model call of two to four seconds per text and
  sends that text to the model
  ([measurements and what they do not say](bench/ACCURACY.md#a-model-as-judge-2026-11-10)).
- The model check says which lines: a flagged text is shown to the model once more, numbered,
  and the lines it points at (numbers only are taken from the answer, five at most) are quoted
  in the question and the session notice and named by `review`, `agent inspect` and the
  preview of `clean`. The verdict is asked for as before; asking for both at once flagged
  twice as many ordinary texts.
- `bench/judge_eval.py` runs a set of texts through the real check;
  `bench/heldout/judge-evasion.json` is a set written to get past it and
  `bench/heldout/ordinary-files.json` is 120 whole ordinary files.

### Fixed

- On Windows, `clean`, `restore` and quarantine failed for a file in a folder deep enough that
  a working file beside it passed 260 characters. Found on a real Windows machine.
- A model check whose command-line client is not logged in says so, and how to log in, in
  `doctor` and in the recorded error.

## [0.5.0] - 2026-11-10

### Added

- `agentdetox agent inspect [--agent ...]`: a command-line bridge from a finding to a cleanup that
  needs no hook. It records a review item (a `C` id for `review`, `clean` and `review accept`),
  bound to the exact version found, for each file in scope that a rule flags or that changed since
  the version last known, and checkpoints files without a clear-cut finding. A flagged file with no
  earlier version is recorded as found, not as a change: all its lines are open to `clean`, and
  `restore` on it is refused. It never allowlists, never checkpoints a file with an open high
  finding, leaves other clients' files alone, and exits non-zero when a file could not be read or
  a folder could not be resolved. `agent scan` stays read-only and now points to it.
- `agent scan` and `agent inspect` print the folders looked in for each client, what no file check
  covers, and what was asked for and could not be resolved; JSON output carries the same as
  `coverage` and `problems`. An unresolved folder makes the command exit non-zero.
- Client file locations: `CODEX_HOME`, Codex `memories_v2/`, `skills/`, `*.config.toml` profiles
  and `.codex/` layers from the repository root to the working folder; Cursor `~/.cursor/skills`,
  shared `~/.agents/skills`, nested `.cursor/rules` and skills, and CLI permission files with
  `CURSOR_CONFIG_DIR`; OpenClaw `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`,
  `OPENCLAW_WORKSPACE_DIR`, `workspace-<agent>` rosters and the workspaces `openclaw.json` names;
  Claude Code subagent memory. Relocated folders are watched for deleted files too. Only text
  files are read: Codex's SQLite memory state is not.
- A successful `clean` says that a session which already loaded the file still holds the removed
  text, and to start a new one; JSON output carries it as `reload`.
- A shared client corpus (`tests/client_corpus.py`) of default, relocated and nested layouts,
  content cases and hook events labelled recorded, official-doc or synthetic; a matrix test, a
  report (`scripts/client_matrix.py`) and a cross-client step in the installed-wheel journey.
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
- `agentdetox library dismiss M<ID> <id> --expected-hash <review-hash>` sets one finding aside
  as a false positive in one inspected file, for the exact bytes and detector reviewed, without
  touching the allowlist: the same text stays flagged in other files, other libraries and every
  write check. `library review M<ID>` prints the review hash and keeps showing dismissed
  findings with their excerpt, date and note; `library review --state dismissed` lists the
  files; `library status` counts dismissed findings and files, and files whose findings are
  all dismissed or allowlisted, apart from files with no findings. `library reopen` undoes it.
  A dismissal ends when the file's bytes or the detector change, after a cleanup, and when the
  file goes missing; stale, unreadable, replaced or unverified versions cannot be dismissed.
- The library inventory format is now version 2. An existing inventory is upgraded in place, in
  one transaction, by the first library command that opens it, reading commands included;
  nothing recorded is lost and no scan is needed to read it. Earlier builds refuse the upgraded
  inventory. Conclusions recorded by an earlier build are shown stale until scanned.
- A synthetic end-to-end library benchmark harness (`bench/library_eval.py`) and a library step
  in the installed-wheel journey.

### Security

- Upgrade to 0.5.0 to fix gaps in approval, monitoring and recovery for protected agent files.
  See the [security advisory](https://github.com/chriswu727/agentdetox/security/advisories/GHSA-j3cm-77h3-cmm7)
  for affected versions, impact and upgrade instructions.
- The shell check recognizes more writes, moves and removals involving protected context or trust
  settings. If a protected operation cannot be checked, AgentDetox asks for approval or refuses
  it on clients that cannot ask. Unrelated hook failures remain visible in doctor and status.
- Protected files and settings are recognized across more path spellings, client locations and
  configuration keys. The scanner checks each relevant occurrence and bounds the work per hook.
- Reinstallation checks existing files for external changes before writing its own settings.
  Session start reports files it could not inspect. Checkpoints, dismissals and recovery records
  are tied to the content and scope the user reviewed.
- Recovery and quarantine use a pinned directory on macOS and Linux. Windows rechecks the path
  before and after each operation. Recovery refuses a path through a user-controlled directory
  link. Keep a backup of the store and review outstanding changes after upgrading.

### Changed

- Ordinary sentences that shared a word with a rule are no longer refused: a nested file that
  "should override any rules from the parent folder", `--force` overriding rules in a linter's
  config, a `</dev/tcp/host/port` port check, a certificate read from the keychain,
  `post-install` copying `.env.example`, `rsync --exclude .env`, password reset mail, a token
  count posted to a metrics URL, Hugo's `config.toml` and `.vscode/settings.json`. Seven such
  sentences are still refused and are listed in `bench/rule_variants.py` as declared false
  alarms, beside two declared misses (a script downloaded in one command and run in the next;
  a secret carried in the address of a request about something else).
- `numpy` is no longer installed by default. Only `agentdetox scan` with passage comparison,
  `agentdetox trace` and the optional contradiction model use it; install it with
  `pip install 'agentdetox[kb]'` (the `st` and `nli` extras include it). `scan --no-cluster`
  works without it, and the other two say what to install. The hooks, and the plugin's `uvx`
  fallback, no longer download it.
- `agent inspect` lists the context files it read through a symbolic link, with where each
  points; JSON output carries them as `linked`.
- Classifying a written path resolves each watched folder once: about four times faster for a
  file that is not agent context, which is most writes.
- Codex `apply_patch` calls are modelled as the tool applies them (add, update with context hunks,
  delete, move, end of file). A patch that does not fit the file or leaves the grammar is not
  guessed at: every file it names is checked against what it adds and, for a move, what it would
  carry along.
- Codex and Cursor shell commands are compared before and after (Cursor also on
  `postToolUseFailure`), and a shell command or deletion touching agent context is logged where
  the client cannot be asked.
- A tool call that only names a file (a read, a search) is no longer treated as a write to it.
  Cursor uses the workspace root, not the tool's working folder, to decide what is context; Codex
  uses the repository root.
- An event from Cursor arriving at a hook registered for Claude Code is answered as Cursor, which
  does not enforce `ask`.
- `install codex` and `install cursor` print complete hook configurations with the tool names each
  client reports (`Bash`, `apply_patch`; `Shell`, `Write`, `Delete`). `doctor` reports what a Codex
  or Cursor hooks file leaves unchecked and that it cannot see whether the client runs it, and no
  longer fails for missing Claude Code hooks on a machine without Claude Code.
- OpenClaw's config is read as JSON5, for locating workspaces and for the config checks alike.
- Claude Code auto memory is located by the repository a session is in, so that worktrees and
  subfolders share one folder, as Claude Code does.
- New dependency: `json5`, imported only for an OpenClaw config that is not plain JSON.
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

- A context file that already held flagged text when AgentDetox first looked, at `install` or
  at the first session, was reported at the next session as added outside the agent, and the
  notice pointed to `restore`: its preview showed the whole file as added, and `--apply` removed
  the file and answered "Restored" (the copy stayed in quarantine). Affects every earlier
  release. Such a file is now recorded as found as it was: `restore` refuses it, the notice names
  `clean`, and `review` shows its flagged lines. A file that really appeared later still restores
  to no file, and the preview and the result now say that it is removed.
- `clean` without `--lines` named `--lines 3,5-7` as its example whatever the file held; it now
  names the lines the rules flag.
- The hidden-text check took minutes on a file ending in thousands of unclosed tags on Python
  before 3.11.13, 3.12.11 and 3.13.5, whose HTML parser reread the rest of the file for each
  one. A deeply nested path (thousands of `cd` in one command) took seconds to look up.
- Every command ends an ordinary mistake with one line and status 2 instead of a traceback: an id
  or page number too large to exist, `blame` of a folder, a damaged store under `log`, `events`
  and `blame`, a store path that is a file. Names shown in such messages have control characters
  escaped.
- `agentdetox scan` no longer stops at one line that is not a JSON object, a byte that is not
  UTF-8 or a file it cannot read: these are left out and counted on stderr. It does not follow a
  file link out of the folder it was given. `--k`, `--min-clique`, `--z` and `--top-k` out of
  range are refused (`--k 0` used to put `NaN` into JSON output).
- `agentdetox demo` ignores `CLAUDE_PROJECT_DIR` and the other variables that point a client's
  folders elsewhere; with one set it failed and read the folder it named.
- `library scan ""` (an unset shell variable) scanned the current folder; an empty name is
  refused. A relative `AGENTDETOX_HOME` named a different store from every working directory and
  broke library commands; it is made absolute. `events -n 0` shows nothing instead of everything.
- `install` and `uninstall` replaced a settings file that is a symbolic link (kept in a dotfiles
  folder) with a regular file. They now write where the link points, keep the file's
  indentation and line ends, write and back up nothing when there is nothing to change, and
  refuse to write over a change Claude Code made to the file in the meantime.
- When the store could not be updated after `install --apply` had written the hooks, the output
  was a bare error; it now says the hooks were added and what to check.
- `doctor` passed (with a warning about an older version) when the hook that checks writes was
  missing. It now names the missing hooks and fails when `SessionStart` or `PreToolUse` is one.
- `doctor` compared the hook's version with Python's when the hook runs as
  `python -I -m agentdetox`, reported a bare `agentdetox` found on `PATH` as missing, ended in a
  traceback on a hook command it could not split, did not look in `.claude/settings.local.json`,
  did not warn about hooks registered in two settings files with different commands, and
  reported a broken Claude Code hook as "not set up on this machine" when another agent's hook
  was present.
- `restore` of a version with no recorded permissions set the file to 0600, although the preview
  says permissions are kept: a hook script stopped being executable. The file keeps the
  permissions it has.
- A recovery stopped between staging and renaming left `.agentdetox-restore-*` beside the file
  for good; the next restore or clean in that folder removes it. `doctor` names an unfinished
  recovery's backup only when one was written.
- The model server measured its socket path in characters, so a store path with non-ASCII names
  could never start it; its fallback folder in the temp directory is no longer followed, or
  re-permissioned, through a link another user could have left there. A client that connects
  and sends nothing no longer keeps the server, and the loaded model, alive.
- `agentdetox _daemon --job FILE` moved any file it was given into the job queue, where it was
  later deleted. Only a job file inside the store is taken, and the command needs approval when
  an agent runs it.
- A store from before 0.3 with one line cut short in `events.jsonl` or `ledger.jsonl` could not be
  migrated, and `agentdetox agent gc` then deleted every recovery copy only the old ledger
  referred to. Such lines are left out and counted (as the old readers did), a database a failed
  migration could not fill is removed again, and the recovery copies the old ledger refers to
  are kept until the history is in the database.
- An emptied `state.sqlite3` in a migrated store was rebuilt from the files of before the
  migration, bringing back a stale snapshot without a word; it is now reported, as a deleted one
  was. `agent snapshot --reset` gets out of a deleted, emptied or unreadable database (it ended
  in an error or a traceback), keeping what is left under other names.
- The copy of the database made before a one-way upgrade is written to a temporary name first; an
  empty one left by a killed upgrade is made again instead of being taken for the backup.
- `agentdetox review` kept the database open while it sized each change, which could take
  seconds per change; a hook writing at that moment waited ten seconds and lost its record.
- `library cancel`, `library dismiss` and a library cleanup failed with "database is locked" while
  a scan was listing folders on a slow disk; folders are now read with no transaction open.
- After a scan was killed while committing, `library status` and `review` reported the inventory
  as damaged until the next scan; a reader now recovers it.
- A library scan whose folder was replaced while a large folder was being listed recorded the
  entries read so far; the folder is now checked before every commit.
- Recording a change to a long file compares only the lines around the edit: one edited line in
  a 20,000-line file took two seconds to attribute.
- A Codex patch could move a file with planted text onto `AGENTS.md`, delete a config that
  registers AgentDetox, or remove `approval_policy` and `sandbox_mode` without being checked,
  while an ordinary `config.toml` edit was blocked as a broken config.
- Codex patch previews now preserve context spelling and line endings, choose the file's first
  line ending for additions, and retain trailing blank context as the native tool writes it.
- A file removed by an edit tool, a patch or a shell command is recorded with the content it had
  when removed, not an older checkpoint, so restoring it does not lose later work.
- Safety notes are no longer flagged as the thing they forbid: a sentence whose every clause
  forbids ("Do not disable the sandbox, and do not bypass approval prompts."), a prohibition
  closed by a reminder to ask the user, also when asking is waived for read-only work, and, in
  a skill's sentences, a forbidden command or disclosure ("Never run `curl ... | sh`"). A clause
  that orders, "never fail to", a reversal or another exception, a command string in config or
  a shell command, and anything inside a skill's code block are flagged as before.
- Fetch-and-run said in words is flagged like `curl ... | sh`: "Download the setup script from
  <URL> and execute it". A download that is read, checked, reviewed or opened in an application,
  or followed by running something else ("run this unit test", "run the script on it"), is not.
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

### Quality checks

- Type checking covers the whole package (45 modules, up from 19), and lint adds the rules for
  likely bugs, unexplained `except Exception` and invisible characters in source.
- CI runs Python 3.13 and 3.14 beside 3.11 and 3.12, checks that `uv.lock` matches
  `pyproject.toml`, sweeps every rule for inputs that cost more than their length
  (`bench/rule_cost.py`), and checks that result files a document links to exist and that the
  latencies the READMEs quote are in a recorded result (`scripts/check_evidence.py`).
- A differential test runs 1,266 generated shell commands in real `bash` and `zsh` and compares
  what changed on disk with what the shell check said.
- `bench/heldout/` is a blind set: 90 attack texts and 90 ordinary ones written without sight
  of the rules, half of it sealed until the rules were final. On the sealed half the rules
  stopped 12 of 37 attacks and none of the paraphrased ones, and asked about 1 of 44 ordinary
  texts; text that reached the session through a tool and was saved unasked was stopped 37 of
  37 times whatever it said ([results and what they mean](bench/ACCURACY.md#blind-held-out-set-2026-11-10)).
- `bench/rule_variants.py` holds the rule variants and benign controls from the 2026-11-10
  audit and from an independent review of the changes it led to, each beside the control it was
  derived from. Of the audit's 72 cases, 16 of 45 attack spellings were caught and 10 of 26
  benign sentences were quiet before the rule changes
  ([before](bench/results/rule-variants-before-2026-11-10.json)); of the 121 cases now, 82 of 82
  and 30 of 37 ([now](bench/results/rule-variants-after-2026-11-10.json)). It is a tuning set,
  written from the rules and used while changing them: the blind set above shows how little
  that carries over. The test suite runs it; a declared miss or false alarm that starts to pass
  fails until its mark is removed.
- Generated tests (`tests/test_properties.py`, with `hypothesis`) draw their inputs instead of
  listing them: a cleanup removes exactly the chosen lines whatever was edited since; a path
  spelled another way is classified the same; no config value, event, transcript, command or
  library file makes a check fail; a planted line is never let through whatever surrounds it or
  whatever the transcript holds; and an error while checking a write to agent context is never
  an allow. Runs are repeatable; `AGENTDETOX_PROPERTY_EXAMPLES` draws more.
- `bench/hook_latency.py` records the commit and command of a run in its result file.
- `scripts/check_dist.py` compares the whole version (0.4.10 no longer passes as 0.4.1), and the
  installed-wheel journey clears every variable that points a client's folders elsewhere.

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

[0.6.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.6.0
[0.5.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.5.0
[0.4.1]: https://github.com/chriswu727/agentdetox/releases/tag/v0.4.1
[0.4.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.4.0
[0.3.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.3.0
[0.2.0]: https://github.com/chriswu727/agentdetox/releases/tag/v0.2.0
[0.1.0]: https://github.com/chriswu727/agentdetox/commit/ba1cc83
