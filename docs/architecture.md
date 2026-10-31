# Architecture

AgentDetox is a command-line program that agents run as hooks. Each hook call is a new process
that reads one event as JSON on stdin and answers on stdout. State lives in `~/.agentdetox`; a
background model server is the only long-lived process, and only when contradiction checks are on.

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
   │           suspicious, copied, contradiction)
   ▼
policy.py     turns Signals into one Decision: allow, ask or deny,
   │          from the user's settings and whether the agent can ask
   ▼
adapters.py   renders the Decision in the agent's reply format
```

`hooks.py` wires these together and logs every decision that was not a plain allow to
SQLite. Before a write, a file that no longer matches the last version AgentDetox knows is
first recorded as changed outside the agent, so the agent is never credited with that change.
After a write, the engine records the observed version, attribution evidence and findings.
Eligible recovery checkpoint updates and history additions commit in one transaction. At session start, `session.py` compares every watched file with
its snapshot, records changes made outside the agent, and tells the agent about suspicious ones.

Shell tools with stable tool-use ids additionally pass through `observation.py`. A transaction stores
pre-tool content references for the current project, its Claude auto memory and shared user-level
Claude context. Success and failure hooks compare those files and discover additions. Records keep
external authorship and before/after evidence, deduplicate versions already recorded by edit tools,
and preserve the recovery checkpoint. A brief `systemMessage` reaches the terminal as well as the
agent context. The observer hashes scoped contents; it does not rely on mtime as an integrity proof.

## Modules

| Module | Role |
|---|---|
| `adapters.py` | Agent hook protocols: events, file changes, reply formats |
| `engine.py` | The checks; knows nothing about agents or settings |
| `policy.py` | Block, ask or record |
| `hooks.py` | Entry point for hook calls; fails open |
| `observation.py` | Scoped shell start states, end comparison, immediate review findings and notices |
| `session.py` | The session-start check |
| `context.py` | Which files each agent reloads; classifying a path; Claude Code's folder names |
| `shell.py` | What a shell command writes or deletes, and whether it changes AgentDetox |
| `persistence.py` | Rules for agent footholds, and the security-relevant parts of config files |
| `hidden.py` | Hidden text and injection phrasing |
| `provenance.py` | Reading the session transcript: copied text, and text the user wrote |
| `consistency.py` | Splitting memory into statements and finding contradictions with an NLI model |
| `daemon.py` | The model server (Unix socket), or a job queue where there is none (Windows) |
| `integrity.py` | Snapshot store: baseline, content-addressed copies, verify, restore, quarantine, locking |
| `storage.py` | SQLite schema, transactional legacy migration, indexed metadata and references |
| `review.py` | Diff, exact-version accept, finding dismissal, recovery journal and retention |
| `ledger.py` | Each change with its origin, the versions before and after, and `blame` |
| `allowlist.py`, `events.py`, `settings.py` | Allowed ids, the event log, the settings file |
| `install.py`, `doctor.py`, `status.py`, `demo.py`, `cli.py` | Installing hooks, health, the commands |
| `scan.py`, `corpus.py`, `embed.py`, `cluster.py`, `trace.py` | The RAG knowledge-base scanner |

## Data

See [PRIVACY.md](../PRIVACY.md) for what each file in `~/.agentdetox` holds. Writes to the store
take `store.lock` and a SQLite transaction. Content objects are hash-validated and atomically
replaced before metadata references them. Migration validates every referenced object, commits
schema and metadata together, and preserves the original JSON files. A migration marker prevents
silent fallback to those stale files if the database later disappears.

Recovery uses a durable operation record, a verified backup, and an atomic replacement. If the
process stops between filesystem and metadata updates, the unfinished operation remains visible
in doctor with its intended hashes and backup path. File updates and database commits cannot be
one OS transaction; the journal exposes that gap rather than hiding it. External processes do not
honor the store lock, so recovery rechecks the observed hash before replacing a file.

Checkpoints, observed versions and explicit user acceptance are separate fields. An automatic
checkpoint is recoverable state, not proof of user intent. Finding dismissal is specific to a
change and never grants permanent source trust. History retention is opt-in and preserves pending
findings, accepted versions, the latest per-file record and content needed for recovery.

## Distribution

The Python package (`agentdetox` on PyPI) carries everything. The Claude Code plugin in
`plugins/agentdetox` only registers hooks that run that package: the installed command, or its
pinned release through `uvx`. `agentdetox install claude-code` registers the same hooks in
settings instead; the two must not both be active.
