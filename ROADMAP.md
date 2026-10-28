# Roadmap

Last updated 2026-10-28. This says where AgentDetox is going and why; the
[changelog](CHANGELOG.md) says what has shipped.

## What AgentDetox is becoming

An integrity layer for what AI agents remember and obey: their memory, instruction and rules files,
skills, and the config that decides their tools and permissions.

Today AgentDetox is a set of detectors (rules, a provenance check, a contradiction check) with
snapshots underneath for recovery. The detectors judge content, and content judgement is an arms
race: in real sessions the model already refuses obvious planted instructions, and what slips past
the model, such as a plausible-looking line or a paraphrase, mostly slips past rules too. What only
AgentDetox does is track these files across sessions: noticing when something the agent will obey
changed, who changed it, and putting it back.

## The bet: a ledger for agent context

Every change to an agent's context is recorded with its origin:

- **you**, typing or pasting it;
- **the agent, at your request**;
- **the agent, copying untrusted input**: a web page, an email, MCP data, a file it just read,
  named;
- **something outside the agent**: another program, a dependency's install script, a sync.

Writes the hooks see carry their session and sources; a change the hooks did not see is external
by definition, which is the strongest risk signal there is. The existing checks become signals on
ledger entries instead of separate features. Users get a history of each file, a per-line origin
(`blame`), one review inbox for everything recorded but not blocked, and rollback to any point.

Why this rather than better detection:

- Rewording gets past a rule. It does not get past "this line came from the email you just read"
  or "this line appeared while `npm install` was running".
- As of the October 2026 survey, nobody else records origin when the write happens. Forensics tools
  attribute after the fact, memory-guard libraries need the integrator to label each write, and
  Claude Code's protected paths exempt auto memory.
- A ledger extends naturally to teams: policies and reviews can live in the repository and in
  pull requests.

The risk is that agent vendors add memory protection themselves. The answer is depth (origin,
history, recovery, not a permission prompt) and covering more than one agent.

## Principles

- **Quiet when nothing is wrong.** When AgentDetox speaks, it says what changed, why it matters
  and what to do, in that order.
- **Never lose the user's data.** Replaced files are quarantined, not deleted.
- **Fail open, but visibly.** A broken hook lets the agent work and shows up in `status` and
  `doctor`.
- **Local only.** Nothing leaves the machine.
- **Judged by real use.** Progress is measured by what users run into, not by benchmark scores.

## Milestones

### 0.2: Preview release for Claude Code

- **Honest scope.** Claude Code is supported. Codex and Cursor are experimental, OpenClaw gets
  tamper detection only, and WorkBuddy leaves the docs until its file layout is verified.
  Contradiction detection is an optional, experimental extra. The knowledge-base scanner stays,
  as a secondary feature.
- **The first five minutes.** `agentdetox demo` shows a tampering attack being caught and undone
  without touching real files. `install` ends by saying what is now protected. The README leads
  with the problem, the demo and a two-line install.
- **Don't block what the user wrote.** Text the user typed or pasted in the session asks for
  confirmation instead of being denied outright.
- **Distribution.** PyPI (TestPyPI first) and a Claude Code plugin.

Done when: one command installs it; someone new can install it and see the demo within two minutes;
a week of the maintainer's daily use produces no block that cannot be explained.

### 0.3: The ledger

- Change records with origin for every watched file, from hook-observed writes and from diffs of
  changes the hooks did not see.
- A check right after each shell command the agent runs, so a change made during the session by
  another program (an install script, say) is reported on the spot rather than at the next session.
- `agentdetox log`, `agentdetox blame <file>`, `agentdetox review` (one inbox replacing today's
  separate event log and allow list), and rollback to a point in time.
- Rules, provenance and contradiction findings attached to ledger entries as signals.

Done when: every change in a real store has an origin, and a week's review takes the user a minute.

### 0.4: Teams and CI

- A policy file kept in the repository.
- `agentdetox ci`: checks a pull request's changes to CLAUDE.md, AGENTS.md, rules, skills and MCP
  config, with SARIF output, a pre-commit hook and a GitHub Action.
- A scan of skills and MCP servers before they are installed.

Done when: it runs on at least one real team's repository.

### 0.5: Judgement and reach

- An LLM judge for contradictions and fabricated facts, replacing the NLI model as the recommended
  path. Whether this can use the agent's own model depends on what each agent's hooks allow; to be
  checked first.
- Detection rules shipped as rule packs that update independently of releases.
- Codex and Cursor verified on real installs; Gemini CLI.

### 1.0: Stable

- A frozen store format, with migrations from every earlier version.
- A published latency budget for hooks, met on ordinary laptops.
- Windows verified on real machines.
- A threat model, a security policy and a documentation site.

### After 1.0

This depends on a decision not yet made: whether AgentDetox stays an open-source developer tool or
grows into a company. The first path leads to community rule packs and more agents; the second to
organisation-wide policy, central reporting and managed deployment.

## Not planned

- Tuning detectors to benchmark scores.
- More work on the NLI contradiction model; the LLM judge replaces it.
- A prompt-injection classifier for tool output as the agent reads it. Others do this; AgentDetox
  uses where text came from instead.
- More agents before the ones already claimed are verified on real installs.

## How progress is measured

- Real users, and how many keep it installed.
- Wrong blocks and needless questions per user per week, counted locally and shared only if the
  user chooses.
- Hook latency at the slowest 5%.
- Data lost by a restore: must stay at zero.
- Time from install to seeing protection work for the first time.
