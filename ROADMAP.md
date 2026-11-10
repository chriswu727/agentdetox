# Roadmap

Last updated 2026-11-10. Current published release:
[0.4.1](https://github.com/chriswu727/agentdetox/releases/tag/v0.4.1). The
[changelog](CHANGELOG.md) records releases; this document separates
implemented capabilities from product hypotheses and future work.

## Direction

AgentDetox tracks the persistent context that coding agents reload: memory, rules, skills and
security-relevant config. Its practical value is a reviewable history and recoverable versions,
with detection evidence attached to changes. Claude Code remains the primary supported agent.

Attribution is evidence, not proof of authorship. Hooks can observe a tool writing a file and
match added text to a user message or tool result. They cannot reliably identify paraphrases,
prove who authored copied text, or attribute a shell script's writes to its exact process.
External changes are worth reviewing but are not automatically malicious.

The two product priorities are a reliable journey from installation through daily use and
accurate prevention, monitoring and recovery. A working command is not evidence of accurate
detection; an attack caught in a fixture is not evidence that installation works for a new user.
Development uses reproducible cases and maintainer self-use; no external user recruitment is planned.

## Release readiness

Since 0.4.1, CI installs the built wheel in a fresh environment
outside the repository and exercises preview, installation, upgrade, repeated installation,
doctor, registered hook commands, review, stale-version refusal, exact recovery and uninstall.
The journey includes paths with spaces, mixed hook groups and user-setting preservation. The
same journey and the offline detection gallery gate publication in the release workflow.
This does not validate real-client hook delivery, network outages or everyday Windows use.

Track these outcomes independently:

- Installation and maintenance: failed steps, actionable errors, preserved settings and backups.
- Normal use: wrong blocks, unnecessary questions and hook P95 latency against existing budgets.
- Prevention and monitoring: per-family misses, including acknowledged gaps, and retained evidence.
- Recovery: exact restored bytes, refusal to overwrite newer work, quarantine copies and residual
  findings. Whole-version restoration can still undo benign additions in the same change. On
  `main`, explicit selected-line cleanup preserves unselected content and non-conflicting later
  edits, with a preview hash, conflict refusal, quarantine and residual scanning. Also on `main`,
  recovery and cleanup write through an opened folder on POSIX, so a parent folder replaced by a
  link cannot redirect them; a same-user program racing the final replacement is not excluded.

Block a release on a failed journey, a new regression or a hook error. Keep acknowledged semantic
misses visible in every accuracy report; a passing regression gate is not a claim of complete
protection. Authored controls cannot establish a real-world false-positive rate.

## Accuracy work

- Shipped in 0.4.0: [offline regression gallery](bench/ACCURACY.md), diff-prefix and quoted-decoy
  fixes, stricter remember-intent handling, highest-severity retention and recovery target rescans,
  and gallery families for shell commands, settings changed outside the agent, writes under another
  name or place, and notice injection, from an independent security review.
- Extend benign controls and realistic memory-specific attacks before tuning semantic detection.
  Keep the tuning set separate from future held-out tests; retain known misses in every report.
- Evaluate paraphrased, delayed and mixed-source writes. Source similarity is evidence for review,
  not proof that content is malicious or that a specific person authored it.
- Shipped in 0.4.1: explicit selected-line cleanup for memory, instructions and skills,
  including later non-conflicting edits. Automatic selection and structural config cleanup are
  not implemented; checking remaining rules does not establish factual correctness.
- A plausible false fact needs trusted evidence to verify it. Do not promote uncertainty into an
  automatic block or describe the current local NLI model as a reliable factual judge.

## 0.3: Review and recovery

Shipped in 0.3.0:

- A single review list, diffs, per-finding dismissal and acceptance of an exact version.
- Per-added-line attribution evidence, separated from the observed writer.
- Recovery preview, stale-version checks, verified quarantine backups and an operation journal.
- SQLite metadata with indexed history, transactional migration and retained original JSON files.
- Weekly recent-change review, JSONL export and explicit history retention with preview.
- Visible hook failures and disabled-hook checks; optional model absence does not degrade health.
- Measured hook latency budgets and real-agent scenarios distinguishing attempts, execution,
  notifications and user-task outcomes.

Still to validate through sustained use: whether weekly review remains useful after several weeks,
false alarms per user per week, and installation and recovery usability for new users. Automated
scenarios cannot establish those outcomes.

## 0.4: Observation and hardening

Shipped in 0.4.0 (see the changelog for the full list):

- Project-scoped shell-interval observation after successful or failed tools.
  Detached background writes and changes outside these intervals still need later reconciliation.
- Project/file filtering, file grouping, search, pagination, terminal review, and a list that says
  who made each change and its worst finding.
- The fixes from an independent security and architecture review: settings that run code, watched
  paths, the shell pre-check, notice injection, a held store lock, one recovery path, and history
  that does not depend on the clock.

## Next

The agreed delivery sequence is:

1. Make current protection dependable: captured-byte evidence, durable background checks,
   reviewed accuracy defects, cross-platform validation, unchanged hook budgets, and a private
   maintainer-observation baseline. Unreleased fixes remain distinct from published 0.4.1.
2. Add scoped lifecycle evidence and large-library inspection: initial inventory, full and
   incremental background scans, progress, interruption recovery, version-bound findings and
   reviewed cleanup. Start with files; database/vector adapters require separate validation.
   On development `main`: `agentdetox library` inspects an explicitly chosen folder of UTF-8
   memory files with a durable inventory, content-hash incremental runs, cancellation and
   resumption, a detached worker, exact-version cleanup through the existing journal and
   quarantine, and dismissal of a finding for one file's exact bytes and detector. Dismissals
   deliberately expire on a detector change. Synthetic 1k/10k/100k inspection contracts,
   100k scoped-triage checks and the recorded hook budget gate during an active scan passed
   on the development Mac; raw evidence is in the large-memory protocol. Not done:
   real-library false-positive review, applying cleanup on Windows,
   context-dependent checks (contradictions, duplicates, attribution) and any adapter.
3. Validate sustained maintainer use and release a scoped stable capability. Thirty qualifying
   active days is a proposed gate, not a claim already achieved or a reason to recruit users.
4. Research semantic attacks, including paraphrase and poisoned consolidation. This can start
   alongside stage 2, initially recording evidence without changing blocking decisions. Promotion
   requires its own held-out accuracy, false-positive and performance gates.

The [large-memory protocol](bench/LARGE_MEMORY.md) defines proposed 1k/10k/100k tiers and
separates inventory measurements from production prevention, detection and disinfection.
No stage promises factual truth from a hash, copied-text match or contradiction score.

- Associate changed context with later sessions that loaded it. Do not claim downstream impact
  until the available transcript evidence supports it.
- Explore paraphrase attribution with explicit uncertainty and benign-project controls.
- Restructure the engine (checks apart from recording) and the store modules, as the architecture
  review recommends; deferred past 0.4.0 to avoid regressions before the release.

## Teams and CI

- Repository policy files and a PR check for changes to instructions, rules, skills and MCP config.
- SARIF output, a pre-commit hook and a GitHub Action.
- Portable attribution metadata without embedding private transcript content in commits.

These require validation in a real team's repository before being described as supported.

## Detection and reach

- Consider an opt-in local or provider model for contradiction judgement. Remote analysis must
  clearly state which content leaves the machine; the default remains local only.
- Verify Codex and Cursor on real installs before expanding their experimental status.
- Remove one added hook, MCP server or permission from a config file, and put back a line that a
  change replaced. Today config can only be restored as a whole file, and only while it is
  unchanged; `clean` removes lines and never reinstates what they replaced.
- Cover what the client file checks do not reach: Codex's SQLite memory state, Claude Code `@path`
  imports and `autoMemoryDirectory`, OpenClaw `$include` files, and an OpenClaw plugin for checks
  as it writes.
- Verify Windows on a real machine; passing CI is not sufficient evidence of everyday usability.
- Keep a reproducible attack gallery alongside known gaps. A failed run is not prevention.

## Principles and measurements

Quiet normal use, recoverable data, visible failure and local storage guide the implementation.
Measure wrong blocks and unnecessary questions, time to resolve a review, restore data loss,
installation time, and P95 hook latency with documented fixtures. No telemetry is collected;
long-term user feedback is voluntary. Known gaps include paraphrased payloads, plausible false
facts without contradictions, arbitrary scripts that bypass hooks, and attribution before the
ledger existed.
