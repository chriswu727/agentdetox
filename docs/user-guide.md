# User guide

[Documentation](README.md) · [Project home](../README.md) · [简体中文入门](../README.zh-CN.md)

Applies to **AgentDetox 0.5.0**, released 2026-11-10. Claude Code is the supported integration;
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
is enabled and installed, and `agentdetox doctor` warns if the hooks are registered twice. The
plugin counts only as AgentDetox's own (`agentdetox@agentdetox`) and only when Claude Code's record
of installed plugins has it: an `enabledPlugins` entry alone, which a project's settings can
carry, runs no hooks, and `doctor` then reports the hooks as not installed. The plugin runs the
`agentdetox` you installed; without one it runs its own release through `uvx`, and with neither it
says so at session start instead of failing on every tool call.

A tool install keeps AgentDetox in an environment of its own; `pip install agentdetox` works too.
If you move Claude Code's folder with `CLAUDE_CONFIG_DIR`, AgentDetox follows it. The first session
scans what is already there before recording recovery checkpoints; `agentdetox agent scan` does the same at any time.
Running `install --apply` again later (after an upgrade, say) first records what changed outside
the agent since the last check, as a session start would, and lists each change with its id
(`agentdetox review C<ID>` shows one) and what needs review; it accepts nothing but its own hooks.

## What it does in Claude Code

- **Before a write** to memory, CLAUDE.md, rules, skills or config (through Write, Edit or a shell
  command such as a redirect, `tee`, `sed -i`, `cp`, `mv` or `rm`), the new content is checked.
  Planted instructions are denied, with the reason sent to the agent. If the flagged text is
  something you typed or pasted yourself, you are asked instead (hidden text is still denied, since
  you could not see what you pasted). An agent changing its own hooks, MCP servers, permissions,
  environment variables, helper commands (`apiKeyHelper`, `fileSuggestion` and the like), sandbox
  or the switches that stop it asking needs your approval, and the prompt says exactly what is
  added or removed. Other settings (model, theme) are not guarded. Setting an `AGENTDETOX_*` variable through the
  agent's settings is denied.
- **After the write**, the observed version and available attribution evidence are recorded.
  A recovery checkpoint advances when the write passes the checks. This is separate from a
  version you explicitly accept in review.
- **After a shell tool finishes or fails**, compare the current project's context, its auto memory,
  and shared Claude context files with the versions captured before the tool. A context file kept
  elsewhere and linked into place (a dotfiles folder) is compared by what the link points to, and
  a file swapped for a link during the tool is recorded as that. New, removed or changed files
  enter review immediately, with a short terminal notice. Config counters do not produce changes;
  security-relevant settings do. The record says the change happened during the tool, not which
  process authored it. If a separate Write/Edit hook already recorded the final version, it keeps
  that observed writer. A permission rule for the command being run, which Claude Code saves when
  you approve the command and choose not to be asked again, is recorded without a notice.
  Installations from 0.3 need updated hook registration (`install claude-code --apply`, or update
  the plugin); `agentdetox doctor` says when.
- **At session start**, files changed outside the agent since the last session are compared with
  the snapshot. A file that cannot be read is named once and set aside; every other file is
  still compared. A changed file that takes too long to check is reported as not checked. Suspicious content is reported to the agent, which is told not to follow it and to
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
In 0.5.0, a sentence may forbid in several clauses ("Do not disable the sandbox, and
do not bypass approval prompts.") or end in a reminder to ask the user, and the sentences of a
skill are read the same way; a skill's code blocks are not, and neither is a clause that orders,
reverses or makes an exception. Fetch-and-run said in words ("download the script from <URL> and
execute it") is flagged like `curl ... | sh`; a download that is read, checked or opened in an
application, or followed by running something else, is not. These are still pattern rules: a list under one
"never", a prohibition wrapped across lines in a skill, and hostile text with no such pattern (a
redirected push target, an order to deceive, a false fact) are known to be judged wrongly.
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

A missing, emptied or damaged metadata store is reported instead of silently rebuilt. To start
over without it, `agentdetox agent snapshot --reset` keeps what is left under another name and
begins a new store; the files from before the 0.3 migration are set aside too, not read again. Keep a backup of the
whole store, including `objects/`. 0.4 upgrades the metadata format (from 1 in 0.3.x to 3) on its
first write and keeps the old database beside it as `~/.agentdetox/state.v1.sqlite3`. 0.3.x refuses
the upgraded store; to go back, reinstall 0.3.x and put that copy back as `state.sqlite3` (changes
recorded since the upgrade are lost). `agentdetox doctor` shows the format in use.
`agentdetox agent snapshot --reset` explicitly resets recovery checkpoints; it does not erase
history or make a corrupt database safe to use.

## Day to day

```bash
agentdetox status                         # health and pending reviews
agentdetox agent scan                     # read-only scan of every client's files; says where it looked
agentdetox agent inspect                  # the same, recorded as review items for `clean` (no hook needed)
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

A cleanup changes the file, not what a running agent has already read from it: start a new
session in the affected client before relying on the removal.

Only the selected lines are removed. Other lines, including same-change additions and
non-conflicting later edits, retain their bytes and line endings. Replaced old text is not
reinstated; use whole-version restore when that is the intent. Removing every line leaves an
empty file. Cleanup refuses selected lines that were modified or removed later, and repeated
matches when later edits make their identity ambiguous. It supports UTF-8 memory, instructions
and skills up to 1 MB and 10,000 lines; executable config, deleted files and symlinks require
another recovery method. In 0.5.0, the 1 MB limit is applied before reading: a larger
file, or a larger recorded version, is refused without being loaded, at the preview and at every
later check. Whole-version `restore` keeps no such limit.
Selection is explicit: copied content is not automatically malicious.

In 0.5.0, `restore`, `agent restore` and `clean` open the folder that holds the file
once and read, back up and replace the file through that open folder, so a folder swapped for a
link between review and apply, or during the operation, cannot send the write elsewhere. They
refuse a path that passes through a symbolic link your user could repoint (a linked project or a
linked `~/.claude`); links owned by the system, such as `/tmp` on macOS, are followed. A file
recorded under such a linked path is still watched and reviewed, but must be recovered by hand
from the diff. If the folder is moved or replaced while a recovery runs, the change is applied
inside the folder that was opened, the operation is reported as failed in `doctor` with its
backup, and nothing is written at the path's new target. This is not a lock against other
programs of yours: one that rewrites the same file in the same folder between the last check and
the replacement can still lose that write to the quarantine copy. On Windows the checks are made
on the path before and after instead, which narrows the same gap without closing it.

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
`install`, `uninstall`, `agent snapshot`, review mutations, recovery, stopping or restarting a
library inspection, or dismissing or reopening a library finding needs your approval, or an
injected instruction could switch a check off or allow itself. The same holds when part of such
a command is only filled in when it runs, by `xargs`, a variable, a command substitution, a
file name pattern or braces: the call needs approval unless what is written out is already a
command that can only read (`status`, `events`, `doctor`, `log`, `blame`, `export`, `scan`,
`trace`, `library review`, `library status`, `agent scan`, `agent verify`). So
`agentdetox library review "$ID"` is free and `agentdetox review --project "$PWD"` asks, because
the missing part could as well be `accept C1`. The check recognizes `agentdetox` by name,
through wrappers, `python -m` and `bash -c`; it does not see a program name built at run time.

Hooks fail open: if AgentDetox itself errors, the agent's action proceeds, and an unresolved failure
remains visible in `doctor` and `status`. The exception is a write to memory, instructions, skills,
config or AgentDetox's own files that could not be checked: you are asked about it (Codex and
Cursor, which cannot ask, refuse it), with the error named in the message. Text that takes more
than 15 seconds to check counts as not checked (`OverBudget`); in a library scan such a file is
listed as not inspected, "took too long to check". After investigating, acknowledge its event id with
`agentdetox health acknowledge <event-id>`. A missing optional model is an inactive feature, not
a protection failure. Interrupted recoveries show their backup location in doctor; after inspection,
`health acknowledge-recovery <id>` verifies the file matches one side of that recovery before
acknowledging it. SQLite fallback errors use `health acknowledge fallback`. `disableAllHooks` is also checked. If an attacker deletes
the hooks, the session-start check cannot run; `agentdetox agent verify` (by hand or in CI) still
reports the removal.

## Inspecting a library of memory files

Hooks watch changes. A folder of memory that already exists (thousands of notes an agent or a
memory tool reloads) needs looking at first. `agentdetox library` inspects one folder you name.
It is included in 0.5.0.

```bash
agentdetox library scan ~/notes/memory        # list the folder; inspect what is new or changed
agentdetox library scan L1 --background       # the same in a detached worker; returns at once
agentdetox library status                     # coverage and progress of every library
agentdetox library review L1                  # files with high or medium findings
agentdetox library review L1 --state failed   # or low, dismissed, stale, queued, uninspected, missing, inspected
agentdetox library review M42                 # one file: version, findings, line numbers, review hash
agentdetox library dismiss M42 <id> --expected-hash <review-hash> --note "why"   # false positive in this file
agentdetox library reopen M42 <id>            # undo that: the finding is listed and counted again
agentdetox clean M42                          # list its lines; then --lines, --expected-hash, --apply
agentdetox library cancel L1                  # stop after the file in hand; scan again to continue
agentdetox library scan L1 --full             # inspect every file again, changed or not
agentdetox library scan L1 --restart          # abandon an unfinished run and start a new one
```

**Scope.** Only the folder you name is read, and nothing above it. Your home folder, a folder
that holds it, a whole disk and anything overlapping `~/.agentdetox` are refused, whatever the
path is spelled like; a folder already scanned is the same library under any spelling. Files ending in `.md`, `.markdown`,
`.mdc` or `.txt` are candidates and are read as memory text by the same per-file rules that check
an agent's writes. Every other file is counted as excluded, by extension, and shown in `status`;
it is not inspected. Symbolic links are counted and never followed, inside the folder or out of
it. Nothing is sent anywhere, no model runs, and the knowledge-base `scan` command with its
embedding and clustering is a different command that this one never calls.

**What a scan concludes.** Each candidate is in one of five states:

| State | Meaning |
|---|---|
| inspected | Read in full and judged by the rules, at the bytes whose hash is shown |
| queued | Seen in a listing, not read yet (the run is unfinished) |
| not inspected | Larger than 1 MB, not UTF-8, binary, a symbolic link, not a regular file, or took too long to check |
| failed | Could not be read, changed or was replaced while being read, or its folder became a link |
| missing | Inspected earlier and absent from a complete listing of its folder |

**Stale** is not a sixth state but a qualifier of an inspected file: its conclusion was not
verified by the latest run, or was made by an older detector. Stale files are counted within
the inspected ones, `status` says how many there are, and `--state stale` lists them.

An inspected file is **suspicious** when it has a high or medium finding, is listed apart when it
has **low-severity findings only**, and otherwise has **no findings recorded**. That last phrase
means the deterministic rules matched nothing in the bytes read. It is never a verdict that a
file is clean or true: paraphrased instructions and plausible false facts pass, and a first scan
establishes what was read, not that it can be trusted. Findings whose id you allowed with
`agentdetox allow <id>` are hidden from these lists; `status` counts how many findings in how many
files your allowlist hides, and a file whose findings are all hidden is counted on its own line,
not among the files without findings. The allowlist is applied when a list is shown, so allowing
or re-flagging an id needs no new scan. Findings you dismissed for one file (below) are counted
the same way: apart, never as "no findings". At most 50 findings are stored per file, the most severe
first; the number left out is shown, and a file with findings left out stays suspicious. A rule
reports its first match in a file, so cleaning one flagged line can reveal another at the next look.

**Versions.** A conclusion belongs to the exact bytes read (their SHA-256) and to the detector
that judged them: the release, the size limits, and the source text of the rules and of the
library inspection code itself, so a development build that reads or judges files differently
is a different detector even without a new version number. File timestamps and line endings of
the installed code do not count. Every scan reads and hashes every
candidate again: size and modification time are never taken as proof that a file is unchanged.
The rules run again only when the bytes or the detector changed; `--full` runs them on every
file. After an upgrade that changes the rules, earlier conclusions are shown as stale until the
next scan. Starting any new run marks earlier conclusions stale until that run has verified them.

**Runs.** Progress is saved as the scan goes: which folders are still to be listed and which
files still to be verified. Ctrl-C, `library cancel`, a crash or a kill lose at most the batch in
hand, and `library scan` continues the same run, including a run stopped while folders were
still being listed. A continued run keeps the mode (`--full` or not) and the detector it started
with; asking for something else is refused, and `--restart` abandons the unfinished run so that
nothing it verified counts for the new one. One scan runs at a time per store; a second is
refused. `--background` saves the run, starts a detached worker and waits until the worker has
taken the run. If the worker fails to start, the command says why (from `~/.agentdetox/library.log`)
and exits 1; the saved run can then be continued in the foreground. `library scan` exits 0 when the
run completed, 3 when it was stopped before the end, and 2 when it was refused.

A folder that cannot be listed (permissions, an I/O error) is reported, and the files known below
it stay as they were, marked stale: a listing error never turns unvisited files into deletions. A
file is reported missing only when its folder was listed to the end without it. If the library
folder itself is replaced or recreated (a different folder at the same path), scans and cleanups
refuse until `library scan L1 --restart`, which discards the earlier conclusions: they described
another folder. If the inventory file is deleted or emptied, commands say so instead of reporting
that nothing was ever scanned.

**Cleanup.** `agentdetox clean M42` uses the same preview hash, recovery journal, quarantine copy
and history as `clean C42`, with these differences. It works on the exact inspected version only:
after any edit to the file, however unrelated, it refuses until the library is scanned again,
because the findings and line numbers describe bytes that are no longer there. Every line of the
file can be chosen, by its line number in that version; the lines the findings point at are
shown by `library review M42`. Applying records an ordinary history entry, so
`agentdetox restore C<ID>` undoes it, and the inventory is updated to the cleaned bytes with what
the rules still find in them. `library review M42` then says that a cleanup inspected those
bytes, not a scan run, until a later scan verifies them by hash or (`--full`) judges them
again. Nothing is trusted or checkpointed by a scan or a cleanup. A cleanup never reads more
than 1 MB of the file, at the preview or at any later check: a file that grew past that after
it was inspected, even between the preview and the last check before the replacement, is refused
and left as it is.
Applying needs a system where AgentDetox can hold the file's folder open (macOS, Linux). On
Windows the preview works and applying is refused with an explanation: remove the lines with an
editor and scan again.

**Dismissing a false positive in one file.** `agentdetox allow <id>` stops a text being flagged
everywhere: in every file, every write check and every later version. To set a finding aside in
one inspected file only, dismiss it there:

```bash
agentdetox library review M42        # shows each finding's id, and the review hash of this version
agentdetox library dismiss M42 0c6eacf0b4 --expected-hash <review-hash> --note "quoted in the install guide"
agentdetox library reopen M42 0c6eacf0b4
```

A dismissal belongs to one finding in one file, at the exact bytes and detector that were
reviewed. The review hash names all of it (the library folder, the file, the content hash and
the detector), so the hash of another file with the same content, of the same file id in
another inventory, or of an earlier version is refused. Several ids can be given at once;
either all are dismissed or none.

- **What it changes.** One row in the library inventory. The file is not touched, the finding
  and its excerpt stay stored, nothing is added to the allowlist and the hook store is not
  opened. The same text in another file, in another library and in anything an agent writes is
  flagged as before.
- **What you still see.** `library review L1` lists files with open findings, so a file whose
  high and medium findings are all dismissed leaves that list; `--state dismissed` lists the
  files that have dismissed findings, and `library review M42` shows each one marked
  `DISMISSED`, with its excerpt, when it was set aside and the note. `library status` counts
  dismissed findings and files, and counts a file whose findings are all dismissed or
  allowlisted on its own line, never among the files with no findings recorded. A dismissal is
  your decision about one version, not a verdict that the file is clean.
- **When it is refused.** The conclusion must be current: the file inspected (not queued,
  failed or missing), by the detector now installed, and verified by the latest run of its
  library. The file is then read again, within the 1 MB limit and without following links, and
  must still hold the inspected bytes; it is read once more at the moment the decision is
  recorded, so an edit made in between refuses it too. A scan in progress that has not reached
  the file, an unreadable or replaced file, a replaced library folder or an outdated review
  hash all refuse, and nothing is recorded. Run or finish the scan and review again.
- **When it ends.** As soon as the inventory records anything else for that file: other bytes
  (even if the flagged line is still there, and even if the file later returns to the earlier
  bytes), another detector, a cleanup, the file going missing or becoming a link, or
  `scan --restart` of a replaced folder. The finding is then open again. Scanning the same
  bytes again with the same detector, with or without `--full`, keeps the dismissal, as does a
  scan in which the file could not be read. Because the detector includes the release,
  **dismissals end at the first scan after you upgrade AgentDetox**; use `allow` for an
  exception that should last.
- **What it can hide.** Only the stored finding. A rule reports its first match in a file, so
  while that match is dismissed a later match of the same rule in the same file is not listed
  either. Findings left out by the 50-per-file limit cannot be dismissed, and such a file stays
  suspicious.

The inventory's format changed to hold dismissals. The first library command of this version,
including `status` and `review`, upgrades an existing inventory in one transaction and keeps
everything in it; no scan is needed to read it. If the upgrade cannot be written (a read-only
store), the command says so and changes nothing. Conclusions recorded by an earlier build are
shown stale until scanned, as after any detector change. An older AgentDetox refuses the
upgraded inventory rather than misread it.

An agent needs your approval to run `library cancel`, `library scan --restart`,
`library dismiss`, `library reopen` or `clean M42 … --apply`; scanning, status, review and
cleanup previews are free. A `library` command completed at run time (`… | xargs agentdetox
library`, `agentdetox library $ACTION …`) needs approval too, except `library review` and
`library status`, which stay free with arguments from `xargs` or a variable.

Limits: files over 1 MB and folders nested deeper than 64 levels are not inspected; cleanup keeps
its 10,000-line limit; contradiction checks, duplicate detection and source attribution do not
run on libraries; a dismissal covers one stored finding, not a line range or a whole file, and
no record is kept of a dismissal once it has ended. Scale has been exercised with synthetic
folders only; see the [large-memory protocol](../bench/LARGE_MEMORY.md).

## What it does not catch

- Detection is not a security boundary. An adaptive attacker who knows these rules can evade them,
  and a plausible-looking false fact with nothing to contradict passes.
- Planted text the model rewrites in its own words before saving it, unless a rule still matches
  or the [model check](#a-models-reading-of-each-write-optional-development-main) is on.
- Changes outside the observed shell interval remain visible at the next session or before the next
  observed edit. Background writes after a shell tool returns are outside that interval.
- The ledger knows what the hooks saw. A change the agent makes with a shell command is recorded as
  made outside the agent, and text it copied in its own words as the agent's.
- The check before a shell command reads the command, it does not run it. It reads every line
  of a command and every command in it: after `;`, `&&`, a pipe or a line break, in a subshell, a
  function body, a `$(…)` or backtick substitution (also inside double quotes), and in a script
  handed to a shell (`bash -c`, `eval`, a here-string, a heredoc, or an `echo` or `printf` piped
  into `sh`). It follows redirects, `tee`, `sed -i` (also `-Ei` and `--in-place`), `perl -i`,
  `ruby -i`, `awk -i inplace`, `sort -o`, `patch FILE`, `cp`, `mv` (what it writes and what it
  moves away), `rm` (including a whole folder that holds context files), a copy into a folder
  (`cp x/CLAUDE.md .`, `cp -t .claude …`, `cp -r`), `git checkout`/`restore`/`rm`/`mv` of a path
  (also of `.`, and with `git -C dir`), `curl -o`/`-O` and `wget` (also in bundles such as
  `-sSLo`), a path spelled out in inline `python -c`/`node -e` code that writes, wrappers such as
  `sudo -u root`, `env -C dir` or `xargs -I {}`, and a `cd` or variable set earlier in the same
  command. A command that cannot be read to its end (an unclosed quote) and names a context file
  or AgentDetox asks. A script file, a path built at run time (`find … -exec`), a folder copied
  to a place that holds no context yet, an archive being unpacked, or a git command that
  rewrites the work tree as a whole (`git checkout <branch>`, `reset --hard`, `stash`, `pull`)
  is not stopped beforehand; the check right after the command finds the change and, if the new
  content is flagged, tells the agent not to follow it.
- Writes made by MCP tools are not checked when they happen; the next session's comparison finds
  them.
- A path is judged by the file it names: another case, another Unicode form of a folder's name,
  macOS's second name for the data volume (`/System/Volumes/Data/…`) and a link all reach the
  same file. A context file or folder that is itself a link (`~/.claude/CLAUDE.md` or
  `~/.claude/skills` kept in a dotfiles folder) is also recognised when the agent writes to where
  the link points. A single linked file inside a folder of many (`~/.claude/rules/x.md` pointing
  elsewhere) is not recognised at its other location before the write; the check after a shell
  tool and at session start see the change. `restore` and `clean` refuse a linked file: change
  it where it lives.
- CLAUDE.md files and `.claude` folders in subfolders are checked when the agent writes them, but
  changes made to them outside the agent are not looked for. `.claude` folders between the project
  and the root of its repository are watched like the project's own; whether Claude Code loads
  each kind of file from there was not verified, and watching one it does not load costs a
  question when the agent writes it. A `.claude` above the repository is not the project's.
- What an installed plugin brings (the skills, commands and hooks under `~/.claude/plugins/cache`)
  is not watched: it changes whenever the plugin updates.
- The rules read common spellings of what they look for, and no more. A script downloaded by one
  command and run by the next is not flagged, and five ordinary sentences are still refused
  (turning off a payment provider's sandbox mode, skipping code-owner approvals, "forget about
  any earlier guidelines for the v1 API", a model's `[INST]` markers, "run ruff check without
  asking"). Both lists are kept, with every case, in `bench/rule_variants.py`.
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

Three different things are easy to mistake for one another. They are listed separately here and
should be read separately everywhere else.

- **File checks** (find, review, clean, restore) work on files on disk and need no client. They are
  as good as AgentDetox's knowledge of where a client keeps its files.
- **Hook checks** (block or record a write as it happens) need the client to deliver an event and
  honour the reply. The evidence differs by client. Claude Code has been run in real model
  sessions (the [lab](../lab/README.md)). Codex's own runtime has been driven without a model: the
  installed Codex CLI is given fixed tool calls by a local stand-in for the model service
  ([`lab/codex_contract.py`](../lab/README.md#codex-native-contract-without-inference)), which
  exercises real hook delivery, blocking, the comparison across a shell command, cleanup, a fresh
  client's reload of the cleaned file and undo, but not Codex's trust prompt, its installer or
  anything a real model decides. Cursor has never been run; OpenClaw has no hook to run.
- **Whether text is true** is checked by neither. The rules match instruction-like patterns, miss
  paraphrases and plausible false facts, and "no findings" means only that the rules found nothing.
  On a [blind set](../bench/ACCURACY.md#blind-held-out-set-2026-11-10) written without sight of
  the rules they stopped 12 of 37 attack texts and none of the paraphrased ones. What stops the
  rest is where text came from: text a tool brought into the session, saved without your having
  asked, is asked about whatever it says (37 of 37). Text you paste yourself, text the agent
  rewords, and files that arrive outside the agent have only the rules.

| Client | Files found (0.5.0) | File checks: scan, inspect, clean, restore | Hook checks |
|---|---|---|---|
| Claude Code | CLAUDE.md and CLAUDE.local.md (also in parent folders and, when written or inspected, in subfolders), `.claude/rules`, AGENTS.md, auto memory and its subfolders (shared by a repository's worktrees), subagent memory, skills, subagents, commands, output styles, settings, `.claude/hooks` scripts, `.mcp.json`, `~/.claude.json`; `.claude` folders up to the repository root and, when written or inspected, in subfolders; follows `CLAUDE_CONFIG_DIR` | yes | supported; real sessions in the [lab](../lab/README.md) |
| Codex | AGENTS(.override).md, text files in `memories/` and `memories_v2/`, `skills/`, `config.toml`, `*.config.toml` profiles, `hooks.json`, `rules/*.rules` under `~/.codex` or `CODEX_HOME`; `~/.agents/skills`; in a repository, `.codex/` and `.agents/skills` from the root down to the working folder | yes | experimental: `install codex` prints the hooks; exercised on the native Codex CLI 0.167 runtime with fixed tool calls, not in model sessions |
| Cursor | `.cursor/rules` (`.mdc` and `.md`) and `.cursor/skills` (also in subfolders), `.cursorrules`, AGENTS.md, `~/.cursor/skills`, `~/.agents/skills`, `mcp.json`, `hooks.json`, CLI permissions (`cli-config.json`, `.cursor/cli.json`, `CURSOR_CONFIG_DIR`) | yes | experimental: `install cursor` prints the hooks; built from Cursor's documentation, never run in Cursor |
| OpenClaw | AGENTS, SOUL, USER, IDENTITY, BOOT, BOOTSTRAP, MEMORY, daily memory and skills in each workspace; `openclaw.json`; state folders `~/.openclaw` and `~/.openclaw-<profile>`, `workspace-<agent>` rosters, `OPENCLAW_HOME`, `OPENCLAW_STATE_DIR`, `OPENCLAW_CONFIG_PATH`, `OPENCLAW_WORKSPACE_DIR`, and the workspaces `openclaw.json` configures (read as JSON5) | yes; also compared at the session start of any hooked client | none of its own: there is no OpenClaw plugin, so nothing is checked as OpenClaw writes |
| WorkBuddy | paths guessed from a third-party write-up, shown as *unverified* | unverified | none |

What is not covered, client by client, is printed by `agentdetox agent scan` under "Not covered"
(for a client not found on the machine, only its name; `--format json` lists all of them):
Codex's SQLite and generated memory state and how Codex regenerates memory; Claude Code files
pulled in with `@path` imports, auto memory moved with `autoMemoryDirectory` and what installed plugins bring; Cursor's User
and Team Rules, which are not files; OpenClaw's SQLite state, sandbox workspaces and `$include`
files. A folder you asked for that cannot be resolved (an environment variable naming a missing
folder, an `openclaw.json` that does not parse or names a relative or unset path) is listed under
"Not resolved" and makes the scan exit non-zero: it is never reported as nothing found.

### Checking a client's files without a hook

```bash
agentdetox agent scan --agent openclaw --user-only   # read-only: findings, folders looked in
agentdetox agent inspect --agent openclaw --user-only  # the same, recorded as review items
agentdetox review C12                                # what was found, bound to that version
agentdetox clean C12                                 # its lines; add --lines 3 to preview removing one
agentdetox restore C13 --apply                       # undo a cleanup (the id the cleanup prints)
```

`agent scan` only reads, and creates nothing in AgentDetox's store. `agent inspect` is the bridge to a cleanup for a client with no hook, a
hook that is not installed or trusted, and text that was there before AgentDetox was. For every
file in scope it records a review item when a rule finds something or the file changed since the
version last known, bound to the exact bytes found. A file found with flagged text and no earlier
version is recorded as *found as it was*: no history is invented for it, every line can be chosen
in `clean`, and there is nothing to `restore`. Files without a clear-cut (high) finding get a
recovery checkpoint; that is something to restore to, not an acceptance, and files with only
lesser findings are checkpointed with those findings left open. Nothing is added to the allowlist.
`--agent` limits the run to those clients: other clients' files are not read, recorded or
checkpointed. An inspection that could not read a file or resolve a folder exits non-zero.

Selective cleanup still applies only to memory, rules and skill files. A hook, MCP server or
permission added to a config file can be reviewed and, while the file is unchanged, restored as a
whole; removing just the added entry is not implemented.

### What the experimental hooks do

Codex and Cursor cannot be asked a question from a hook (Codex ignores `ask`; Cursor accepts it
from `preToolUse` and does not enforce it), so checks set to `ask` record instead, and changes to
the client's own hooks, MCP servers or permissions are blocked, whether they come through an
edit tool, a patch fed to the shell (`apply_patch <<EOF`, also after a `cd` or inside `bash -lc`),
or a shell command that writes, moves or deletes a config file holding them.

- **Codex.** `apply_patch` calls are modelled as Codex applies them (add, update with context,
  delete, move), so the result is what is checked: a patch that moves a file onto AGENTS.md is
  judged by what lands there, deleting a guarded config is blocked, and an ordinary `config.toml`
  edit is not. A patch that does not fit the file is not guessed at: what it adds, and what a
  move would carry along, is still checked. Shell commands are compared before and after, also
  when they fail, and a change to a context file is recorded with "writing process unknown" and
  reported to the agent. Codex runs a hook only after you trust it in `/hooks`, and again after
  its command changes; AgentDetox cannot see that state, and `doctor` says so.
- **Cursor.** The same comparison across `Shell` calls uses `postToolUse` and
  `postToolUseFailure`. Cursor documents no input shape for its `Write` and `Delete` tools, so
  those are read by the fields they carry and a write that cannot be read is blocked for config
  and recorded for other files. Cursor also loads the hooks in Claude Code's settings by default;
  an event from Cursor reaching AgentDetox's Claude Code hook is answered as Cursor.
- A shell command that names a context file is logged even though it cannot be asked about.
- The provenance check ("copied from what the agent just read") needs Claude Code's transcript and
  is not available for other clients: their ledger entries say only that the agent wrote the file.

`agentdetox install codex` and `install cursor` print the hook configuration; `--apply` is refused
for both until installing them has been verified on real installs.

## A model's reading of each write (optional, development `main`)

```bash
agentdetox config judge ask      # or: record. Off again: agentdetox config judge off
agentdetox doctor                # says whether the check is on and can reach a model
```

The rules read wordings someone has seen before. On texts written without sight of them they
stop about a third, and none of those that say the same thing in other words. This check hands
the text a write adds to memory, rules or a skill to a small model and asks what it would have
the agent do: run something fetched from the network, read or send out secrets, weaken its own
safeguards, set aside what you told it, hide what it does, or carry an instruction you would
not see. On the same texts it flagged 89 of 90, and 60 of 60 written on purpose to get past a
model; it also flagged 3 of 150 short ordinary texts and 2 of 120 whole ordinary files
([measurements, and what they do not say](../bench/ACCURACY.md#a-model-as-judge-2026-11-10)).

It is off unless you turn it on, because of what it costs:

- **A model call for every such write**, through the Claude Code you are logged in to (`claude`
  must be on the path; any client's hooks can use it). Two to four seconds and a fraction of
  a cent each. Other tool calls are not affected.
- **The text being written is sent to the model.** It is text the agent was about to keep in its
  own context, which the same provider reads in every later session.

What keeps the check from becoming a way in:

- The model is asked in a new session with no tools, no MCP servers, no skills and none of your
  settings, in an empty folder, and nothing of the session is saved. The agent whose write is
  being checked is not asked.
- Only one of a few fixed words is taken from its answer. The sentence you see is AgentDetox's,
  so a text cannot use the model to tell you, or the agent, anything.
- It is asked after the rules and can only add a question. What the rules or the text's origin
  already stop stays stopped; when the model says a text is fine, nothing else is relaxed.
- An answer that cannot be read counts as a flag. A call that fails (no client, not logged in,
  no network, over 30 seconds) counts as no opinion: the write is decided by the other checks,
  the failure is recorded, and `doctor` shows it.
- It is asked without the reasoning step a model otherwise takes, which made its answer to a
  borderline text change from one asking to the next. A text it flagged stays flagged without
  being asked about again, until you allow its id.
- **It also reads what arrives outside the agent.** At a session start, files that changed
  outside the agent and that the rules let pass are read too: the added text of a file known
  before, the whole of a new one, up to eight per start (the rest at the next), for at most
  twenty seconds. A flag is reported like a clear-cut rule finding and the file is not trusted
  until you review it. `agentdetox agent inspect --judge` reads every memory, rules and skill
  file on request, with no hook and whatever the setting says: one call per file.

What it is not:

- **Not certain.** It misses some attacks (one reworded one in the tests is flagged six times
  in ten), and a reworded text is a new question.
- **Not proof against a text written to persuade it.** One such attack got through until the
  brief was changed for it; the rules stopped that one. That is why the model is asked last
  and can only add.
- **More false flags in Chinese** than in English in the tests (4 of 51 against 1 of 203),
  mostly notes about where a secret is kept.
- **It does not soften the rules.** A file the rules refuse stays refused when the model
  finds it fine.
- With an agent that cannot be asked (Codex, Cursor), a flag is recorded, as for the other
  configurable checks.
- Tested on macOS. On Windows the call has not been run.

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

### Background work on development main

In 0.5.0, background contradiction work survives worker crashes.
`agentdetox doctor` and `agentdetox status` distinguish failed checks, work waiting for a model,
and work stalled for more than ten minutes. Failed work gets at most three automatic attempts,
with 5-second and 60-second retry delays, and remains available for inspection for seven days.
After fixing the reported cause, run `agentdetox daemon retry`. It restarts a resident worker
when necessary; corrupt retained jobs remain visible and cause retry to exit unsuccessfully.
If the model is missing, fetch it first or explicitly turn contradiction checks off. Turning
the check off stops new submissions; it does not certify previously queued versions as clean.
`daemon stop` leaves queued work on disk. Expired work is reported, not counted as checked.

## Also: scanning a RAG knowledge base

```bash
pip install 'agentdetox[st]'                # or 'agentdetox[kb]' for a numpy-only install
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
`tests/test_properties.py` draws its inputs (events, configs, transcripts, commands, edits) and
checks properties that must hold for all of them; `AGENTDETOX_PROPERTY_EXAMPLES=2000` draws more
than the default.
`python -m bench.rule_variants` runs the rule spellings and benign sentences from the 2026-11-10
audit and its review; it is a tuning set with its misses declared, not an accuracy estimate.
`python -m bench.heldout_eval` runs the blind set through the pre-write hook; that one is the
estimate, and its sealed half has been used once.
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
uv tool upgrade agentdetox            # installed with `uv tool install`
pip install --upgrade agentdetox      # installed with pip, in the same environment
```

For the plugin route, update the marketplace and plugin, then restart Claude Code:

```bash
claude plugin marketplace update agentdetox
claude plugin update agentdetox@agentdetox
```

Run `agentdetox doctor` afterwards. Upgrades from 0.3.x change the store format; see the
backup and rollback instructions under [the write and recovery workflow](#what-it-does-in-claude-code).

`install` and `uninstall` write a linked settings file where the link points, keep its
indentation and line ends, and stop without writing if the file changed while they worked.

Installed hooks call a fixed executable, so updating it takes effect on the next hook call with
no reinstall. A model server still running the old build replaces itself on its next job;
`agentdetox daemon stop` stops it at once (in a source checkout, `./scripts/update.sh` does this
too). Re-run `agentdetox install claude-code --apply` only when
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
