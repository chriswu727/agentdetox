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
`events.jsonl`. After a write, the engine trusts the file as written. At session start,
`session.py` compares every watched file with its snapshot and tells the agent about suspicious
changes made outside it.

## Modules

| Module | Role |
|---|---|
| `adapters.py` | Agent hook protocols: events, file changes, reply formats |
| `engine.py` | The checks; knows nothing about agents or settings |
| `policy.py` | Block, ask or record |
| `hooks.py` | Entry point for hook calls; fails open |
| `session.py` | The session-start check |
| `context.py` | Which files each agent reloads; classifying a path; Claude Code's folder names |
| `shell.py` | What a shell command writes or deletes, and whether it changes AgentDetox |
| `persistence.py` | Rules for agent footholds, and the security-relevant parts of config files |
| `hidden.py` | Hidden text and injection phrasing |
| `provenance.py` | Reading the session transcript: copied text, and text the user wrote |
| `consistency.py` | Splitting memory into statements and finding contradictions with an NLI model |
| `daemon.py` | The model server (Unix socket), or a job queue where there is none (Windows) |
| `integrity.py` | Snapshot store: baseline, content-addressed copies, verify, restore, quarantine, locking |
| `allowlist.py`, `events.py`, `settings.py` | Allowed ids, the event log, the settings file |
| `install.py`, `doctor.py`, `status.py`, `demo.py`, `cli.py` | Installing hooks, health, the commands |
| `scan.py`, `corpus.py`, `embed.py`, `cluster.py`, `trace.py` | The RAG knowledge-base scanner |

## Data

See [PRIVACY.md](../PRIVACY.md) for what each file in `~/.agentdetox` holds. Writes to the store
take `store.lock`; the baseline is written to a temporary file and renamed, so a crash leaves the
old baseline intact. A missing or damaged baseline is reported at every session instead of being
silently rebuilt, since deleting it would otherwise launder tampering.

## Distribution

The Python package (`agentdetox` on PyPI) carries everything. The Claude Code plugin in
`plugins/agentdetox` only registers hooks that run that package: the installed command, or its
pinned release through `uvx`. `agentdetox install claude-code` registers the same hooks in
settings instead; the two must not both be active.
