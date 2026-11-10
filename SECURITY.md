# Security policy

## Supported versions

Security fixes are made on the latest published AgentDetox release. Upgrade before reporting a
problem so the report reflects the current code.

## Reporting a vulnerability

Do not open a public issue for a vulnerability that could put users at risk, such as a way to get
planted content past the checks or to make AgentDetox trust a tampered file. Use
[private vulnerability reporting](https://github.com/chriswu727/agentdetox/security/advisories/new)
with:

- the AgentDetox version (`agentdetox --version`), operating system and agent (Claude Code, Codex,
  Cursor) with its version;
- reproduction steps and the expected impact;
- the relevant `agentdetox events` lines and a minimal example, with secrets removed.

You should receive an acknowledgement within seven days. Please allow time for a coordinated fix
before publishing details.

## What AgentDetox defends against

AgentDetox protects the files an agent reloads and obeys: memory, instruction and rules files,
skills, and the config that sets its hooks, MCP servers and permissions.

In scope:

- **Planted instructions the agent is steered into writing**, through its edit tools or a shell
  command, including text copied from web pages, MCP data or files it read.
- **Changes made outside the agent**, by a dependency's install script, another program or a sync:
  suspicious content reported at the next session until reviewed, anything new that would run (a
  hook, helper command, MCP server, plugin, or an environment variable that loads code) mentioned
  once, both recorded in the ledger and reversible with `agentdetox restore C<ID>`.
- **An agent changing its own guardrails**: hooks, MCP servers, permissions, environment variables
  and helper commands.
- **An agent changing AgentDetox's own state**: its settings, allowlist and snapshots, by writing
  them or by running the commands that change them.

Out of scope; see the [full limitations](docs/user-guide.md#what-it-does-not-catch):

- **Someone or something running code as the user** outside the agent's tool calls. It can edit
  `~/.agentdetox`, the ledger included, or remove the hooks; the session-start check and
  `agentdetox agent verify` report what they can, but nothing on the same account can prevent it.
- **Adaptive evasion of the rules.** Detection is not a security boundary; a plausible false fact
  with nothing to contradict, or planted text the model rewrites, can pass.
- **Everything else an agent does.** AgentDetox is not a firewall for tool calls or network access.

## Design choices that affect security

- **Hooks fail open.** If AgentDetox itself errors, the agent's action proceeds, and `doctor` and
  `status` show the failure. A security tool that broke every tool call would be uninstalled.
- **Nothing is deleted.** A restore moves the current file to `~/.agentdetox/quarantine`.
- **Recovery cannot be pointed elsewhere by swapping a folder** (development `main`, macOS and
  Linux). `restore` and `clean` open the folder holding the file without following links the
  user could repoint, and read, back up and replace through that open folder; a path through
  such a link is refused. This does not stop a program running as the user from changing the
  same file in that folder at the last moment, and Windows only checks the path before and after.
- **A library scan reads, it does not trust.** `agentdetox library` inspects one folder the
  user names. The name given is resolved once, when the folder is first scanned, and that
  resolved folder is the library; no link found inside it is followed (links are counted). A
  scan records no checkpoint and never reports a file as clean.
- **The store is private.** `~/.agentdetox` is created 0700 and its files 0600.
- **No imports from the project.** Background processes and the `python -m` hook fallback start
  Python with `-I`, so a repository cannot plant an `agentdetox` package for the hook to import.
- **Local checks.** Hooks and checks make no network calls. Installation, the plugin's `uvx`
  fallback and optional model downloads require network access. The fallback fetches a release
  pinned by version, not by hash. See [PRIVACY.md](PRIVACY.md).
- **The shell check reads, it does not run.** A command is checked before it runs by parsing it;
  where the parse is uncertain (a `cd` that may fail, a variable set elsewhere) it assumes the
  worse case or judges the target by its file name. A script file or a path built at run time
  is checked right after the command instead.
- **A blocked store is reported.** If another process holds AgentDetox's store lock, content
  checks still run and session start says the store is locked.
