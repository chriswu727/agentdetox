# Privacy

AgentDetox runs on your machine and sends nothing anywhere. It has no telemetry, no account and
no server.

## Network access

Hooks and checks make no network calls. Three commands download software, and only when you
choose them:

- `agentdetox fetch-models` downloads the contradiction model from Hugging Face.
- `scan` with the `st` extra downloads its embedding model from Hugging Face on first use.
- The Claude Code plugin, when no `agentdetox` command is installed, runs its pinned release
  through `uvx`, which downloads it from PyPI.

## What it reads

- The files it watches: the agent's memory, instruction and rules files, skills and config.
- Only when you run `agentdetox library scan <folder>`: the names of everything in that folder
  and the content of its `.md`, `.markdown`, `.mdc` and `.txt` files up to 1 MB each. Links are
  not followed. Cleaning a library file stores the versions before and after in `objects/` and a
  quarantine copy, as any recovery does.
- For the provenance check, the end of the current Claude Code session transcript (at most the
  last 4 MB), to compare a memory write with what the agent read in the last three of your
  prompts. The transcript is read, not copied.

## What it stores

Everything lives in `~/.agentdetox` (or `AGENTDETOX_HOME`), private to your user (0700, files 0600):

| Path | Contents |
|---|---|
| `objects/` | Full copies of each watched file at its last trusted version, and of the earlier versions the ledger refers to, named by hash. These include settings files, so any secret written in them (an MCP server's token, say) is copied too |
| `state.sqlite3` | Transactional checkpoints, observed and accepted hashes, changes and per-line attribution evidence, findings and review state, hook events and recovery operations. Shell start states store scoped paths, hashes, file kinds, permissions and tool/session ids until completion. No shell command text is stored by this observation feature |
| `state.v1.sqlite3` | Pre-0.4 metadata database retained when format 1 upgrades to format 3; keep it with the corresponding content objects for a 0.3.x rollback |
| `baseline.json`, `ledger.jsonl`, `events.jsonl` | Original pre-0.3 files retained unchanged after a successful migration. No longer the authoritative store |
| `quarantine/` | Unique recovery backups and manifests; never automatically deleted |
| `events-fallback.jsonl` | Events written while SQLite was unavailable; retained until `health acknowledge fallback` moves them to an acknowledged archive |
| `sqlite-migrated` | Marker preventing a deleted database from silently reimporting stale legacy files |
| `background/` | On development `main`: durable contradiction jobs containing earlier text and captured bytes, retry metadata and retained failures; private files removed after completion or retention expiry |
| `pending/` | Legacy contradiction jobs used by 0.4.1; the development worker adopts them into `background/` |
| `library.sqlite3`, `library.inventory` | On development `main`, only after `agentdetox library scan`: for each folder you scanned, its path and filesystem identity, every candidate file's relative path, size, content hash and state, per-folder counts of excluded files by extension, run history, and for each finding its id, rule, severity, message, an excerpt of at most 200 characters and line numbers (at most 50 findings per file). No file content beyond those excerpts. The marker file lets a deleted inventory be reported as lost |
| `library.log`, `library.lock` | The detached scan worker's start, finish and error lines, and the lock that allows one scan at a time |
| `config.toml`, `allowlist.json` | Your settings and the ids you allowed |
| `daemon.log`, `*.lock`, `nli.sock` | The model server's log, locks and socket |

Unfinished shell start states expire after 24 hours at the next observed shell start. Hash-addressed
content referenced by a start state survives GC until completion or expiry. These copies can include
configuration secrets under the same private-store permissions as other snapshots.

On development `main`, background work is attempted at most three times before being retained
as failed. Waiting jobs expire seven days after enqueueing, and failed jobs seven days after
their last modification, when a worker next prunes the queue. Expired waiting jobs produce an
event; expiry does not mean a successful check. The queue caps waiting and failed jobs together
at 500 (concurrent submissions may briefly exceed this); a rejected submission records a hook
error. Jobs contain full text, not just hashes. No queue contents are sent to a provider.

Copies that neither back a watched file nor a ledger entry are deleted once a day; quarantined files
are not. History grows until you explicitly run `history prune --older-than 90d --apply`. Preview first
without `--apply`. Pending findings, accepted versions, latest records and unresolved hook errors
are retained. Original migration files and quarantine backups remain until you delete them.
`agentdetox export --format jsonl` exports change records, including attribution and file paths;
it is not a complete backup. Back up the entire store for recovery.

## Removing it

`claude plugin uninstall agentdetox@agentdetox` or `agentdetox uninstall claude-code`, then `agentdetox daemon stop`,
`uv tool uninstall agentdetox`, and delete `~/.agentdetox`. Deleting the folder also deletes the
quarantined files.
