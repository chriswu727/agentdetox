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
background model server, and are logged. Trade-off: some conflicting claims may be noticed after
they persist; a novel false fact can
pass entirely. A stronger opt-in judge is a roadmap consideration, not an implemented replacement
or a commitment to enable prompting by default.

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
while the ledger refers to them. Text attribution is an inference and can be evaded by paraphrase; history is
what makes `blame`, review and rollback possible. Trade-off: the store grows with use unless the
user explicitly prunes it, and a change observed during a shell command retains unknown-process
attribution.
The interval does not establish process authorship (see ADR 16).

## ADR 11: Prepare recovery before replacing a file

Recovery verifies the stored content hash, writes a temporary replacement with the saved permissions,
and verifies a unique quarantine copy before replacing the target. Deleted files retain their
checkpoints. A failed preparation leaves the current file in place; unsupported symbolic links are
rejected rather than followed. Legacy checkpoints without permissions restore as 0600.

## ADR 12: Separate observed, checkpointed and accepted versions

A hook observes a writer and may infer a text source; it does not observe human authorship.
Store per-added-line matches and retain unknown attribution for unmatched text. Recovery
checkpoints advance independently of explicit user acceptance. Accept is hash-specific; dismiss
resolves one finding on one change. Persistent source exceptions remain an advanced allowlist
operation. This reduces accidental long-term trust at the cost of another review for a new version.

## ADR 13: SQLite metadata, immutable content objects

Use the Python standard library's SQLite for indexed history and atomic metadata changes, retaining
hash-addressed content objects. Legacy migration validates references in one transaction and keeps
original files byte-for-byte. Metadata and filesystem recovery need a durable operation journal
because they cannot share one atomic commit. Opt-in pruning keeps unresolved and recovery-critical
records; exporting JSONL supports inspection but does not replace a complete store backup.

## ADR 14: Measure execution separately from attack attempts

Real-agent validation records attempted commands, successful tool results confirming execution,
hook decisions, user notification and task completion separately. A failed or incomplete session
cannot be reported as an attack prevented. The headless lab refuses permission questions, so a
correct guardrail may leave the user's requested change incomplete; report that explicitly.

## ADR 15: Review files first, preserve version-specific actions

Group the inbox by file, with a project filter covering repository paths and its Claude auto-memory
folder. Shared user rules stay in the global view rather than being assigned to every project.
Pagination removes the old 200-record ceiling; counts describe the full filtered selection.
Interactive file selection opens individual changes, with explicit confirmation and the same
hash checks as scripted actions. It does not bulk-accept a file's history. A real terminal is
required so piped agent output cannot drive approval prompts.

## ADR 16: Observe shell intervals without guessing process authorship

Capture hash-addressed versions before a Claude shell tool, then compare the scoped project,
auto-memory folder and shared Claude context after either success or failure. Keep per-tool start
states in SQLite so parallel calls cannot overwrite one another, and retain referenced objects
through GC. Capture and upgrade failures roll back; observation errors never weaken a pre-existing
permission question. A known edit-tool write keeps its observed attribution. Other changes enter
review with an explicit unknown-process label, even when no injection rule matches. Config churn
outside guarded sections stays quiet. This costs two scoped file reads per shell call; other
projects' auto memory is excluded. Detached background writes and writes later reverted within the
interval remain outside the evidence. Denied or abandoned tools leave start states that expire
at the next capture after 24 hours.

## ADR 17: Compute evidence outside the store lock

Post-write provenance scales with transcript size and added lines. Holding the global lock while
computing it can make unrelated hooks time out and lose observation. Capture the base and current
bytes briefly, compute evidence without the lock, and validate both versions before committing.
Retry up to three times, then report a visible failure rather than trust unchecked content.
The optional contradiction worker receives captured bytes instead of reopening a potentially
newer target; related context is evaluated when the job runs, not frozen at write time.

Pre-write external-change observation also scans captured bytes outside the lock and retries
when the ledger base changes. It records the version actually observed, even if a subsequent
filesystem edit has already replaced it. This path does not advance a trusted checkpoint.

## ADR 18: Bounded prose analysis with original evidence

Memory and instruction rules may join soft-wrapped prose, including short list continuations,
within eight lines and 2,048 characters. Blank lines, separate list items, other Markdown blocks,
fenced/indented code, sentence endings and independent action lines bound the analysis.
Configuration and shell syntax keep their existing analysis. Hidden Unicode
and HTML checks still receive original text. Matched rule spans map back to the original source
lines, so adjacent ordinary notes do not change finding IDs or falsely resolve retained findings
during cleanup. The snapshot and restoration bytes are never normalized.

Copied-text checks inspect both the complete addition and substantive passages. A local passage
must have at least twelve tokens, eight distinct tokens, six matching six-token shingles and
70% shingle overlap; the original whole-write threshold remains unchanged.
This reduces dilution by unrelated notes but remains lexical evidence for review, not a verdict
of maliciousness. Remember intent is scoped using explicit source URLs or shared target words;
generic instructions refer to the latest relevant source, excluding housekeeping reads of
recognized agent context. Page references prefer web sources. URL matching tolerates a trailing
slash and surrounding punctuation but does not assume different schemes or hosts are equivalent.
Ambiguous references may still prompt.
The same scoped result is used in source attribution metadata. Paraphrases and semantic intent
remain outside this rule's guarantees.
