# Design decisions

Each entry records a choice someone might later want to undo, and what it would cost.

## ADR 1: Hooks fail open

If AgentDetox errors, the agent's action proceeds. A security hook that broke every tool call
would be removed within a day, leaving no protection at all. Trade-off: a crash is a silent gap,
so `doctor` and `status` must show it.

## ADR 2: Never delete; never trust what was flagged

A restore moves the current file to quarantine. A file with a high-severity finding keeps its old
snapshot entry, so the pre-tampering version stays restorable however many sessions pass.
Trade-off: quarantine grows until the user deletes it.

## ADR 3: The engine knows no agents

Adapters translate each agent's hook protocol into planned writes and shell commands; the engine
checks those and the policy decides. A new agent needs only an adapter and a file profile.
Trade-off: an agent feature with no counterpart elsewhere (Claude Code's transcript) reaches the
engine as an optional argument.

## ADR 4: Clear-cut findings block; everything else asks or records

Rules marked high (running fetched code, reverse shells, loosening the agent's guardrails, reading
credentials) deny the write. Everything less certain asks where the agent can ask and records where
it cannot. A finding in text the user typed or pasted themselves asks instead of blocking, since
the user is the authority on their own text; hidden text never counts as theirs.

## ADR 5: Contradictions are recorded, not asked

On one real user's memory the NLI model called many unrelated notes contradictory, and thresholds
low enough to be quiet left little recall. So contradiction checks run after the write, in a
background model server, and are logged. Trade-off: a fabricated fact is noticed, not stopped. The
roadmap replaces the model with an LLM judge before this asks again.

## ADR 6: Local only

Nothing is sent anywhere: no telemetry, no cloud checks. Trade-off: no shared threat data and no
usage numbers; measuring false positives depends on users choosing to share their counts.

## ADR 7: Where text came from, not a classifier

AgentDetox does not run an injection classifier on what the agent reads. Models already resist
much of that, and others build classifiers. It judges a write by its origin: what the user said,
what the agent read, what changed outside it. Trade-off: planted text that the model rewrites and
no rule matches gets through until origin tracking covers paraphrase.

## ADR 8: One model server per store

Loading the NLI model takes seconds and about 1 GB, too slow for a hook. A server started on
demand keeps it loaded and exits after 30 idle minutes; where Unix sockets are unavailable,
background workers take turns on a job queue. Trade-off: a second process to manage, which
`daemon status` and `update.sh` handle.

## ADR 9: The plugin and settings hooks are alternatives

Claude Code runs a plugin's hooks in addition to identical ones in settings, so both together would
run every check twice. `install` declines when the plugin is enabled and `doctor` warns about both.

## ADR 10: Record where every change came from, and keep the history

Every change to a watched file is recorded with its origin (the user, the agent, a named input the
agent copied, or something outside the agent) and the versions before and after, which are kept
while the ledger refers to them. Detection can be reworded around; origin cannot, and history is
what makes `blame`, review and rollback possible. Trade-off: the store grows with use until pruning
exists, and a change made by the agent's shell commands is recorded as "outside the agent's edit
tools" until a post-command check tells the two apart.
