# Roadmap

Last updated 2026-10-31. The [changelog](CHANGELOG.md) records releases; this document separates
implemented capabilities from product hypotheses and future work.

## Direction

AgentDetox tracks the persistent context that coding agents reload: memory, rules, skills and
security-relevant config. Its practical value is a reviewable history and recoverable versions,
with detection evidence attached to changes. Claude Code remains the primary supported agent.

Attribution is evidence, not proof of authorship. Hooks can observe a tool writing a file and
match added text to a user message or tool result. They cannot reliably identify paraphrases,
prove who authored copied text, or attribute a shell script's writes to its exact process.
External changes are worth reviewing but are not automatically malicious.

Current priority is accuracy of prevention, monitoring and cleanup. Hook latency remains a budget,
while progress is judged by attack-family misses, benign interruptions, retained evidence and
residual findings after recovery. Development uses reproducible offline cases and maintainer
self-use; no external user recruitment is planned.

## Accuracy work

- Implemented on main: [offline regression gallery](bench/ACCURACY.md), diff-prefix and quoted-decoy
  fixes, stricter remember-intent handling, highest-severity retention and recovery target rescans.
- Extend benign controls and realistic memory-specific attacks before tuning semantic detection.
  Keep the tuning set separate from future held-out tests; retain known misses in every report.
- Evaluate paraphrased, delayed and mixed-source writes. Source similarity is evidence for review,
  not proof that content is malicious or that a specific person authored it.
- Evaluate removal of contaminated spans while preserving benign edits. Current recovery restores
  a whole recorded version; checking its rules does not establish factual correctness.
- A plausible false fact needs trusted evidence to verify it. Do not promote uncertainty into an
  automatic block or describe the current local NLI model as a reliable factual judge.

## 0.3: Review and recovery

Implemented in this release:

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

## Next: Better observation

- Implemented on main: project-scoped shell-interval observation after successful or failed tools.
  Detached background writes and changes outside these intervals still need later reconciliation.
- Associate changed context with later sessions that loaded it. Do not claim downstream impact
  until the available transcript evidence supports it.
- Explore paraphrase attribution with explicit uncertainty and benign-project controls.
- Implemented on main: project/file filtering, file grouping, search, pagination and terminal review.
  Continue improving these against the maintainer's own work and reproducible local scenarios.

## Teams and CI

- Repository policy files and a PR check for changes to instructions, rules, skills and MCP config.
- SARIF output, a pre-commit hook and a GitHub Action.
- Portable attribution metadata without embedding private transcript content in commits.

These require validation in a real team's repository before being described as supported.

## Detection and reach

- Consider an opt-in local or provider model for contradiction judgement. Remote analysis must
  clearly state which content leaves the machine; the default remains local only.
- Verify Codex and Cursor on real installs before expanding their experimental status.
- Verify Windows on a real machine; passing CI is not sufficient evidence of everyday usability.
- Keep a reproducible attack gallery alongside known gaps. A failed run is not prevention.

## Principles and measurements

Quiet normal use, recoverable data, visible failure and local storage guide the implementation.
Measure wrong blocks and unnecessary questions, time to resolve a review, restore data loss,
installation time, and P95 hook latency with documented fixtures. No telemetry is collected;
long-term user feedback is voluntary. Known gaps include paraphrased payloads, plausible false
facts without contradictions, arbitrary scripts that bypass hooks, and attribution before the
ledger existed.
