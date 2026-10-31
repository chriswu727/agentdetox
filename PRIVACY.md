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
- For the provenance check, the end of the current Claude Code session transcript (at most the
  last 4 MB), to compare a memory write with what the agent read in the last three of your
  prompts. The transcript is read, not copied.

## What it stores

Everything lives in `~/.agentdetox` (or `AGENTDETOX_HOME`), private to your user (0700, files 0600):

| Path | Contents |
|---|---|
| `objects/` | Full copies of each watched file at its last trusted version, and of the earlier versions the ledger refers to, named by hash. These include settings files, so any secret written in them (an MCP server's token, say) is copied too |
| `state.sqlite3` | Transactional checkpoints, observed and accepted hashes, changes and per-line attribution evidence, findings and review state, hook events and recovery operations. Event payloads include file paths, reasons and excerpts |
| `baseline.json`, `ledger.jsonl`, `events.jsonl` | Original pre-0.3 files retained unchanged after a successful migration. No longer the authoritative store |
| `quarantine/` | Unique recovery backups and manifests; never automatically deleted |
| `events-fallback.jsonl` | Events written while SQLite was unavailable; retained until `health acknowledge fallback` moves them to an acknowledged archive |
| `sqlite-migrated` | Marker preventing a deleted database from silently reimporting stale legacy files |
| `pending/` | Contradiction-check jobs waiting for the model server, including the earlier text of the file just written; removed once checked |
| `config.toml`, `allowlist.json` | Your settings and the ids you allowed |
| `daemon.log`, `*.lock`, `nli.sock` | The model server's log, locks and socket |

Copies that neither back a watched file nor a ledger entry are deleted once a day; quarantined files
are not. History grows until you explicitly run `history prune --older-than 90d --apply`. Preview first
without `--apply`. Pending findings, accepted versions, latest records and unresolved hook errors
are retained. Original migration files and quarantine backups remain until you delete them.
`agentdetox export --format jsonl` exports change records, including attribution and file paths;
it is not a complete backup. Back up the entire store for recovery.

## Removing it

`/plugin uninstall agentdetox` or `agentdetox uninstall claude-code`, then `agentdetox daemon stop`,
`uv tool uninstall agentdetox`, and delete `~/.agentdetox`. Deleting the folder also deletes the
quarantined files.
