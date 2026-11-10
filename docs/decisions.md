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

## ADR 19: Recover through an opened folder, and refuse replaceable links

A path names whatever its folders point at when it is used. `restore` and `clean` checked the
file's hash and then wrote by path, so a parent folder swapped for a link to a folder holding
a file with the same bytes received the write (reproduced). On POSIX the folder holding the
target is now opened once, one component at a time with no-follow opens, and the read, the
temporary file, the rename and the delete all go through it; the quarantine copy is written
the same way and its folder verified before the target is touched. A link in the path is
followed only when the current user cannot repoint it (owned by root, in a root-owned folder
others cannot write, as `/tmp` on macOS or `/home` on some Linux systems); when running as
root no link is followed. Trade-off: files recorded under a path that passes through the
user's own link (a linked project folder, a linked `~/.claude`) can no longer be restored or
cleaned through AgentDetox, where they could before. Recording the resolved location with
each change would allow them safely and is the alternative if this proves too strict. The
operating system offers no compare-and-swap for a file: a same-user program can still change
the file inside the opened folder between the last check and the rename, and Windows gets
path checks before and after instead of an opened folder.

## ADR 20: Library inspection is an inventory bound to bytes, apart from the hook store

Inspecting an existing folder of memory is separate from watching changes. Its state is its
own SQLite file so that a long scan never holds the lock hooks wait on, and it stores
metadata only: no content copies at scan time, at most 50 findings per file. A conclusion is
bound to the hash of the bytes read and to a detector id, which is derived from the source of
the rules and of the inspection code rather than maintained by hand; every run reads and hashes every
candidate, because size and modification time do not prove content. Nothing is ever called
clean: a file is inspected at those bytes, or visibly queued, not inspected, failed, stale or
missing, and a listing error never becomes a deletion. Only one extension set is inspected
and everything else is counted. One runner at a time, with folders to list and files to
verify kept as rows, gives crash recovery without a scheduler; a continued run keeps its
mode and detector. Cleanup applies to the exact inspected version only, through the existing
journal, quarantine and history, so it needs no stored copy of the flagged version; after
any edit the library is scanned again first. A scan trusts nothing and writes no checkpoint,
and session start does not read the inventory, so historical findings never interrupt a
session. Trade-offs: an unchanged library still costs a full read per scan; false positives
are silenced with the global allowlist because there is no per-file dismissal; rules that
need context (contradictions, duplicates, source attribution) do not run; applying a cleanup
is refused on Windows, where the folder cannot be held open. (Per-file dismissal was added
later: ADR 21.)

## ADR 21: A library dismissal is a decision about one file at one version

The only way to silence a false positive in an inspected library was the global allowlist,
which also silences the same text in every other file, in write checks and in later versions.
A dismissal instead names one stored finding of one file and is bound to the content hash and
detector that were reviewed. It lives in the library inventory, so hooks never see it, and it
hides the finding from the open queue only: the row, its excerpt, the date and the user's note
stay visible, and status counts dismissed findings and files apart from files without
findings. Recording one requires the review hash (library folder, file, content hash,
detector) from `library review`, a conclusion that is current, and the same bytes on disk,
read again inside the transaction that records the decision.

Chosen: the decision ends when the inventory records any other version of the file, including
a return to the earlier bytes after an intermediate version, and a detector change such as an
upgrade. Rescans of the same bytes by the same detector keep it. Not chosen: keeping it across
detector changes or re-applying it whenever the same bytes reappear. Both would be friendlier
(a branch switch and back, or an upgrade, loses triage work) but let a decision made about one
conclusion suppress a later one the user never looked at; `allow` remains the lasting
exception. Validity is also enforced when reading, by joining on hash and detector, rather
than only by deleting on write, because a scan worker of the previous inventory version can
still be writing after an upgrade and knows nothing of the table. For the same reason the
upgrade only adds a table.

Trade-offs: a dismissed first match of a rule leaves later matches of that rule in the file
unlisted, as allowlisting does; findings beyond the 50 stored per file cannot be dismissed, so
such a file stays suspicious; no history of ended dismissals is kept; nothing is written to
the event log, because that would take the store lock hooks wait on; and since the inspection
code is part of the detector id, conclusions from the build before this one are stale after
upgrading and must be scanned before anything in them can be dismissed.
