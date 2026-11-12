# Architecture

AgentDetox is a command-line program that agents run as hooks. Each hook call is a new process
that reads one event as JSON on stdin and answers on stdout. A small entry point routes hooks
without importing the command UI. State lives in `~/.agentdetox`. Two kinds of process outlive
a command: the background model server (or, on Windows, its job-queue workers), only when
contradiction checks are on, and a library scan worker started with `library scan --background`,
which exits when its scan ends or is cancelled. The optional model check starts the user's
`claude` command for each text it asks about and waits for it.

## A hook call

```
agent event (JSON on stdin)
   │
   ▼
adapters.py   which event, which project, which files or shell command
   │          (Claude Code, Codex and Cursor each speak a different protocol)
   ▼
engine.py     checks a planned write or a shell command and returns Signals
   │          (planted, user-written, own-state, guardrails, shell-write,
   │           deletion, unread, suspicious, copied, contradiction, judge)
   ▼
policy.py     turns Signals into one Decision: allow, ask or deny,
   │          from the user's settings and whether the agent can ask
   ▼
adapters.py   renders the Decision in the agent's reply format
```

`context.py` knows where each client keeps its files and resolves the folders a user can move
(`CLAUDE_CONFIG_DIR`, `CODEX_HOME`, OpenClaw's state folder and the workspaces its JSON5 config
names). `adapters.py` decides which client an event is from by the event itself, so a Cursor event
reaching a hook registered for Claude Code is answered as Cursor; it treats a tool call as a write
only when it carries content, a patch or a deletion. `patch.py` models a Codex `apply_patch` call
as the tool applies it and marks what it cannot model instead of guessing. `inspection.py` is the
session-start check run from the command line for chosen clients (`agent inspect`).

`hooks.py` wires these together and logs every decision that was not a plain allow to
SQLite. Before a write, a file that no longer matches the last version AgentDetox knows is
first recorded as changed outside the agent, so the agent is never credited with that change.
For a config file, which rewrites its own counters and caches, that means a difference in the
sections it guards; the snapshot then stays behind until the next session has reported it.
After a write, the engine captures the file and ledger versions, computes attribution and findings
without the store lock, then rechecks both versions before recording. Concurrent changes trigger
a bounded retry; unchecked bytes never become a trusted checkpoint. Transcript indexes are local
to one check and shared across added lines, with no timestamp-based integrity shortcut.
Eligible recovery checkpoint updates and history additions commit in one transaction. At session start, `session.py` compares every watched file with
its snapshot, records changes made outside the agent, and tells the agent about them. A file with
flagged content keeps its old snapshot, so it is reported every session until reviewed; a settings
addition that runs code is told once and the snapshot moves on, since repeating it would not stop
it running. Config files are compared by their security-relevant sections only, because agents
rewrite their own config (counters, caches) at every start.

Claude JSON configuration is interpreted by field position. Runtime caches and unrelated metadata
are outside the guarded root/project settings; command checks read helper commands, status-line
commands, hook handlers and MCP launch fields rather than recursively matching any `command` key.
Hook spinner text is cosmetic. Metadata inside a guarded hook or MCP section remains reviewable,
but only changes to execution fields justify a notice that its runnable configuration changed.
Other agents retain their existing config interpretation; this is not a general JSON schema validator.

Shell tools with stable tool-use ids additionally pass through `observation.py`. A transaction stores
pre-tool content references for the current project, its Claude auto memory and shared user-level
Claude context. Success and failure hooks compare those files and discover additions. Records keep
external authorship and before/after evidence, deduplicate versions already recorded by edit tools,
and preserve the recovery checkpoint. A config change that only adds a permission rule for the
command being run is how Claude Code saves an approval; it is recorded without a notice. A brief
`systemMessage` reaches the terminal as well as the agent context. The observer hashes scoped contents; it does not rely on mtime as an integrity proof.

Optional contradiction record jobs carry the observed bytes to the worker. Related-file reads,
candidate selection and inference happen there; findings attach to the matching recorded hash,
even if the file was edited again before the job ran. Related context is read at processing time.

The optional model check (0.6.0, off by default) is `judge.py`. With it on, `engine.py` asks it
about the text a write adds to memory, rules or a skill when the rules did not refuse it, and
`session.py` asks it about files that changed outside the agent. Its answer can only add a
`judge` signal beside the others; it removes no question and no refusal. See
[ADR 22](decisions.md#adr-22-a-model-reads-context-writes-last-and-may-only-add-a-question) and
[PRIVACY.md](../PRIVACY.md#what-the-optional-model-check-sends).

Since 0.5.0, `background.py` persists jobs before waking the worker. Files are private,
written through a temporary file, flushed and atomically renamed. Directory sync is used where
supported; hardware power-loss durability is not certified. The process holding the daemon lock
owns execution. Attempts are persisted before work; successful processing removes the job and
failure retains it with bounded retries. Missing models leave waiting work rather than a false
success. A restart adopts legacy jobs and drains the saved queue. Delivery is at least once:
diagnostic contradiction events can repeat after a crash, while ledger findings are upserted.
`doctor`/`status` expose failed, waiting and stalled work. Explicit retry restarts a worker that
left an I/O-blocked job queued. This queue carries contradiction checks only; library inspection keeps its own run state (below).

## Modules

| Module | Role |
|---|---|
| `adapters.py` | Agent hook protocols: events, file changes, reply formats |
| `engine.py` | The checks; knows nothing about agents or settings |
| `policy.py` | Block, ask or record |
| `entrypoint.py` | The installed command: routes a hook call to `hooks.py` without importing the command UI |
| `hooks.py` | Entry point for hook calls; fails open, except that an unchecked write to context asks |
| `observation.py` | Scoped shell start states, end comparison, immediate review findings and notices |
| `session.py` | The session-start check |
| `context.py` | Which files each agent reloads; classifying a path; Claude Code's folder names |
| `shell.py` | What a shell command writes or deletes, and whether it changes AgentDetox |
| `paths.py` | Which file a path names: comparison by device and file number, not by spelling |
| `persistence.py` | Rules for agent footholds, and the security-relevant parts of config files |
| `agentscan.py` | Runs the rule modules over one context text by file kind; the scan behind `agent scan` |
| `findings.py` | The finding record, severities and stable finding ids |
| `hidden.py` | Hidden text and injection phrasing |
| `budget.py` | The time one piece of text may be checked for, looked at between rules |
| `provenance.py` | Reading the session transcript: copied text, and text the user wrote |
| `judge.py` | The optional model check: asks the user's `claude` command about a text in a session with no tools, reads back a category and line numbers, keeps the last 5,000 flags |
| `consistency.py` | Splitting memory into statements and finding contradictions with an NLI model |
| `daemon.py` | The model server (Unix socket), or a job queue where there is none (Windows) |
| `background.py` | Durable job files, attempts, retention and background health |
| `integrity.py` | Snapshot store: baseline, content-addressed copies, verify, restore, quarantine, locking |
| `safefs.py` | File access through an opened folder, so a swapped parent cannot redirect recovery, cleanup or library reads |
| `library.py` | Inspection of a chosen folder of memory files: durable runs, inventory, review, exact-version cleanup and dismissal |
| `storage.py` | SQLite schema, transactional legacy migration, indexed metadata and references |
| `review.py` | Diff, exact-version accept, finding dismissal, recovery journal and retention |
| `cleanup.py` | Explicit added-line selection and conflict-checked mapping onto current text |
| `review_ui.py` | The terminal review loop, over the same version-checked actions as the commands |
| `compat.py` | What differs between POSIX and Windows: file locks, program names, hook quoting |
| `ledger.py` | Each change with its origin, the versions before and after, and `blame` |
| `allowlist.py`, `events.py`, `settings.py` | Allowed ids, the event log, the settings file |
| `install.py`, `doctor.py`, `status.py`, `demo.py`, `cli.py` | Installing hooks, health, the commands |
| `scan.py`, `corpus.py`, `embed.py`, `cluster.py`, `trace.py` | The RAG knowledge-base scanner |

## Data

See [PRIVACY.md](../PRIVACY.md) for what each file in `~/.agentdetox` holds. Writes to the store
take `store.lock` and a SQLite transaction. Content objects are hash-validated and atomically
replaced before metadata references them. Migration validates every referenced object, commits
schema and metadata together, and preserves the original JSON files. Lines of the old logs that are not records (cut short by a crash) are left out and counted
in a `migration_skipped` event, as the old readers left them out; a database a failed
migration could not fill is removed again, so the old files go on being read and what only
they refer to is never taken for unreferenced. A migration marker prevents
silent fallback to those stale files if the database later disappears.

Recovery uses a durable operation record, a verified backup, and an atomic replacement. If the
process stops between filesystem and metadata updates, the unfinished operation remains visible
in doctor with its intended hashes and backup path. File updates and database commits cannot be
one OS transaction; the journal exposes that gap rather than hiding it. External processes do not
honor the store lock, so recovery rechecks the observed hash before replacing a file.

On POSIX, recovery and cleanup open the folder holding the target once, component by component
and without following a link the user could repoint, and do every later read, the temporary
file, the rename and the delete through that open folder. The quarantine copy is written the
same way below the store, and the folder it was written to must still be the one its path names
before the target is touched. A target folder that is moved or replaced meanwhile is detected
after the rename and reported as a failed operation; the write stays in the folder that was
opened. There is no compare-and-swap: another program of the same user can change the file in
that folder between the last hash check and the rename. Windows has no directory descriptors
in Python, so the same checks are made on the path before and after each step.

Checkpoints, observed versions and explicit user acceptance are separate fields. An automatic
checkpoint is recoverable state, not proof of user intent. Finding dismissal is specific to a
change and never grants permanent source trust. History retention is opt-in and preserves pending
findings, accepted versions, the latest per-file record and content needed for recovery.

## Library inspection

`agentdetox library` inspects one folder the user names. Its state is `library.sqlite3`, apart
from `state.sqlite3`: every write to the latter takes `store.lock`, which hooks wait on, and a
scan commits thousands of batches. A scan never takes that lock, records no checkpoint and
stores no file content. Folders are read with no transaction open and what was read is
saved in a short one, so a slow disk does not keep `cancel`, `dismiss` or a cleanup from
the inventory. A reader that finds a journal left by a killed scan rolls it back through
one write connection and then reads. No hook, and no part of session start, loads the module or opens the
file; `agentdetox status` reads a few counts from it.

```
library scan DIR
   │  prepare   under library.lock: the root (path and filesystem identity), the run row
   ▼            (mode, detector), the root folder queued for listing
enumerate      folders with todo=1 are listed through the opened root, no link followed;
   │           entries are saved in chunks, a folder is "listed" only with its last entry
   ▼
inspect        files with todo=1: open beneath the root, read at most 1 MB, check the file
   │           did not change or get replaced meanwhile, hash; rules run only when the hash
   ▼           or detector differs from the recorded conclusion; results commit per batch
reconcile      entries absent from a folder listed to its end in this run become missing;
               files below an unlisted folder keep their rows and are shown stale
```

The frontier (folders to list) and the queue (files to verify) are rows, so a killed process
loses the batch in hand and redoing it is idempotent; per-folder counters are saved only with
the folder's last entry, so relisting counts nothing twice. One process holds `library.lock`;
the system releases it when the process dies. A detached worker (`--background`) is the same
code started with `python -I -m agentdetox library _worker <run>`. Cancellation is a flag on
the run row, read between files and listing chunks. The root's path must keep naming the
folder that was opened: this is checked before every batch is recorded and before a run
completes. Relative paths read back from the inventory are validated before use.

A conclusion is bound to the SHA-256 of the bytes one read captured and to a detector id:
the release, the limits, and the source text of the rule modules, of `library.py` and of
`safefs.py` (text only, so timestamps and a checkout's line endings do not change it).
Findings store the flag id, rule, severity, message, an excerpt and a line hint: at most 50
per file. Cleanup of a library file (`clean M<ID>`) reads and plans without the store lock,
then takes it, rechecks the file, the inventory row and the root, and runs the same
journalled recovery as `clean C<ID>` through a folder pinned beneath the root. A pin used for
selective cleanup carries the 1 MB limit, and every read through it (the preview, the check
under the lock, and each check inside the recovery) refuses a larger file before loading it;
whole-version restore uses a pin without a limit. After a cleanup the row holds the cleaned
bytes' hash and findings, no inspecting run, and `cleanup_run`: the latest run, for which the
conclusion counts as current. The row also stops waiting, and a scan batch records a file only
if the row still holds the version seen when the batch picked it up, so a batch that read the
earlier bytes cannot write over a finished cleanup. A later scan verifies the cleaned bytes by
hash like any other.

A dismissal (`library dismiss M<ID> <flag>`) is a row in `dismissals`, keyed by file and flag
id and carrying the content hash and detector it was made for. It never changes `findings`,
`allowlist.json` or `state.sqlite3`, and takes neither `store.lock` nor `library.lock`. Two
things keep it bound to one version. Every reader joins a dismissal to a finding on file,
flag, hash and detector, so a row that outlived its version hides nothing. And every writer of
this version deletes a file's dismissals when it records anything but the same bytes judged
again by the same detector: a scan batch (which compares the row it picked up with what it
concluded), a cleanup, a link, a missing file, a restarted root. A read that failed keeps the
last inspected version, its findings and its dismissals. Recording a dismissal needs a current
conclusion (inspected, this detector, verified by the latest run) and the review hash, which
covers the root's path and filesystem identity, the file id and relative path, the content
hash and the detector. The file is read again through the root within the scan's limits,
first without any lock, so an unreadable file holds nothing up. The row, the review hash, the
bytes on disk and the stored finding are then all checked again inside the `BEGIN IMMEDIATE`
transaction that inserts the row, so a scan or cleanup that commits first wins, and an edit
made before the transaction is refused. An edit after that last read is not seen: the
dismissal then stands for bytes no longer on disk, review says the file changed, and the next
scan ends it.

`library.sqlite3` carries a format version. Version 2 adds `dismissals` and changes no
existing table. Opening an older inventory, for reading as well, first runs the missing
steps in one transaction that rereads the version under the write lock; a failure rolls back
and is reported, and a newer, lost or emptied inventory is refused as before. Upgrades only
add tables because a scan worker of the older version may still be running on its open
connection: it keeps writing the tables it knows, and the join above is why it cannot make a
dismissal apply to bytes it recorded later.

## Distribution

The Python package (`agentdetox` on PyPI) carries everything. The Claude Code plugin in
`plugins/agentdetox` only registers hooks that run that package: the installed command, or its
pinned release through `uvx`. `agentdetox install claude-code` registers the same hooks in
settings instead; the two must not both be active.
