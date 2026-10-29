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

## How AgentDetox stands out

Detecting injected text and gating tool calls is a crowded field, with large vendors and the models
themselves improving at it. AgentDetox competes on what that field does not do.

1. **Every line has a known origin.** `agentdetox blame MEMORY.md` says, line by line, "you, in
   session 3", "copied by the agent from this page in session 7", or "appeared at 14:02 while
   `npm install` ran, outside any session". Origin also sets how strict the content checks are:
   text you wrote is trusted, text that arrived from web pages or MCP data gets the strictest
   checks. A memory write that follows untrusted reading in the same stretch of a session, without
   you asking to remember anything, is marked as tainted, which covers what the model rewrites in
   its own words and copy detection misses. The hard part is precision: reading the project's own
   files must not count the way a web page does.
2. **It cleans up, not just warns.** When something is found, one flow covers what changed, where
   it came from, how far it reached (which sessions loaded it and what ran in them), restoring
   everything it touched, and what to rotate if credentials were within reach.
3. **Worth opening when nothing is wrong.** A weekly "what your agent learned" review: new
   memories, where each came from, stale or contradicting entries to tidy. Users get memory hygiene
   every week, and security comes with it. This is also where contradiction detection pays off.
4. **Across agents and repositories.** People run Claude Code, Codex and Cursor on the same
   repository, sharing AGENTS.md and CLAUDE.md, so poison written by one agent reaches all of them.
   Each vendor protects only its own agent; one neutral ledger covers them all. Origin also
   travels with commits, so a pull-request reviewer can see that an instruction line was written by
   an agent after it read an issue body.
5. **Proof anyone can rerun.** A public gallery replays documented real-world attacks (the npm
   postinstall memory compromise, settings-file worms, rules-file backdoors, memory-poisoning
   papers, malicious skills) against real agent sessions, without and with AgentDetox, next to an
   honest list of what it does not catch.

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
- **Distribution.** PyPI, published from GitHub Actions, and a Claude Code plugin.

Done when: one command installs it; someone new can install it and see the demo within two minutes;
a week of the maintainer's daily use produces no block that cannot be explained.

### 0.3: The ledger

- Change records with origin for every watched file, from hook-observed writes and from diffs of
  changes the hooks did not see.
- A check right after each shell command the agent runs, so a change made during the session by
  another program (an install script, say) is reported on the spot rather than at the next session.
- `agentdetox log` and `agentdetox blame <file>` (shipped early, in 0.2), and rollback to a point in
  time.
- Checks weighted by origin, and memory written after untrusted reading marked as tainted.
- `agentdetox review`: one inbox for everything recorded but not blocked, replacing today's
  separate event log and allow list, and the weekly "what your agent learned" summary.
- An incident flow: what changed, its origin, which later sessions loaded it and what ran in them,
  one restore for all of it, and what to rotate. How far back sessions can be traced depends on
  each agent's transcripts; to be designed against Claude Code's first.

Done when: every change in a real store has an origin, a week's review takes the user a minute,
and the maintainer opens the weekly summary because it is useful, not because something fired.

### 0.4: Teams and CI

- A policy file kept in the repository.
- `agentdetox ci`: checks a pull request's changes to CLAUDE.md, AGENTS.md, rules, skills and MCP
  config, with SARIF output, a pre-commit hook and a GitHub Action.
- Origin that travels with commits, so `ci` and reviewers see who or what wrote each instruction
  line. Git notes or commit trailers are the candidates; to be designed.
- A scan of skills and MCP servers before they are installed, calling Cisco's or Snyk's scanner
  when one is installed rather than rebuilding them.

Done when: it runs on at least one real team's repository.

### 0.5: Judgement and reach

- An LLM judge for contradictions and fabricated facts, replacing the NLI model as the recommended
  path. Sending memory text to a model is a step away from "local only", so it is opt-in and uses
  either a local model or the provider the agent already sends that text to. Whether hooks can use
  the agent's own model depends on each agent; to be checked first.
- Detection rules shipped as rule packs that update independently of releases.
- Codex and Cursor verified on real installs, sharing one ledger with Claude Code; Gemini CLI.
  Codex writes memories in a background pass no hook sees, so there the ledger relies on diffs.

### 1.0: Stable

- A frozen store format, with migrations from every earlier version.
- The 100 ms latency budget for hook checks, met on ordinary laptops.
- Windows verified on real machines.
- A threat model, a security policy and a documentation site.

### Throughout: the attack gallery

Each documented real-world persistence attack becomes a scripted replay against real agent
sessions, run without and with AgentDetox, published with the results. A release that stops
catching a replayed attack it used to catch does not ship. The list of what AgentDetox does not
catch is kept next to it.

### After 1.0

This depends on a decision not yet made: whether AgentDetox stays an open-source developer tool or
grows into a company. The first path leads to community rule packs and more agents; the second to
organisation-wide policy, central reporting and managed deployment.

## Not planned

- Tuning detectors to benchmark scores.
- More work on the NLI contradiction model; the LLM judge replaces it.
- A prompt-injection classifier for tool output as the agent reads it. Others do this; AgentDetox
  uses where text came from instead.
- A firewall for every tool call the agent makes. That field is crowded and not where AgentDetox
  adds anything.
- Its own skill or MCP marketplace scanner; it calls existing ones instead.
- More agents before the ones already claimed are verified on real installs.

## How progress is measured

What AgentDetox should be able to say on its front page, and keep true:

- Every line in a watched file has a known origin.
- No wrong blocks in weeks of daily use, first on the maintainer's machine, then on users'.
- Every attack in the gallery is caught when replayed; one that is not is listed among the known
  gaps until it is.
- Each hook check finishes in under 100 ms at the slowest 5%.

And behind those:

- Real users, and how many keep it installed and open the weekly summary.
- Wrong blocks and needless questions per user per week, counted locally and shared only if the
  user chooses.
- Data lost by a restore: must stay at zero.
- Time from install to seeing protection work for the first time.
