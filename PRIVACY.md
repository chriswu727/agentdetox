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
| `ledger.jsonl` | One line per change to a watched file: when, which file, where it came from (you, the agent, a named web page or tool output it copied, or something outside the agent), the session id, and which copies in `objects/` hold the version before and after |
| `baseline.json` | The list of watched files and which copy is trusted for each |
| `quarantine/` | Files replaced by `agentdetox agent restore`, kept until you delete them |
| `events.jsonl` | What was blocked, asked, recorded or noticed: the command or file paths, the reason, and up to a few hundred characters of the flagged text. Rotated at 5 MB, keeping one older file |
| `pending/` | Contradiction-check jobs waiting for the model server, including the earlier text of the file just written; removed once checked |
| `config.toml`, `allowlist.json` | Your settings and the ids you allowed |
| `daemon.log`, `*.lock`, `nli.sock` | The model server's log, locks and socket |

Copies that neither back a watched file nor a ledger entry are deleted once a day; quarantined files
are not. The ledger and the history it keeps grow with use; nothing prunes them yet.

## Removing it

`/plugin uninstall agentdetox` or `agentdetox uninstall claude-code`, then `agentdetox daemon stop`,
`uv tool uninstall agentdetox`, and delete `~/.agentdetox`. Deleting the folder also deletes the
quarantined files.
