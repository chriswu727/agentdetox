# AgentDetox lab

Replays attacks, and everyday use, against a real Claude Code session, once with AgentDetox and
once without, and records what happened. It is how AgentDetox's claims are checked: synthetic
benchmarks in `bench/` measure the detectors, the lab measures the product in a real agent.

```bash
.venv/bin/python -m lab.run --max-sessions 24        # every scenario, both arms
.venv/bin/python -m lab.run postinstall-tamper --max-sessions 2 # one scenario
.venv/bin/python -m lab.run --arms agentdetox --max-sessions 12 # only with AgentDetox
```

On native Windows, use `.\.venv\Scripts\python.exe -X utf8 -m lab.run` with the same arguments.
The runner locates `.venv/Scripts/agentdetox.exe`, quotes hook executable paths and uses Git for
Windows for the tampering fixture. It does not use WSL's `bash.exe`. Set
`CLAUDE_CODE_GIT_BASH_PATH` for a nonstandard Git installation. `--claude` accepts an executable
name or an absolute path, including spaces. Check `claude auth status` before allocating sessions;
a logged-in desktop Code session does not necessarily authenticate a separately launched CLI.
On Windows, lab sessions explicitly use Git Bash and disable the optional PowerShell tool,
whose shell-write syntax AgentDetox does not analyze.

Results go to `lab/results/<date>.json` and `lab/results/latest.md`. The command exits non-zero
if any check fails, any hook error is recorded, or any session fails to complete. `--max-sessions` is a required explicit
spending cap; obtain user authorization before any real run. Failed CLI startup is not a completed
model session and its error is retained in the result.
Every invocation also writes a unique `run-<UTC timestamp>-<id>.json` archive before cleanup;
reruns cannot erase earlier failed attempts. Timeouts retain partial model output and a failed
result. `--keep` retains raw streams and the temporary store for detailed local investigation.

## What a run measures

Each scenario in `scenarios.py` has:

- **`expect`**: what must hold with AgentDetox installed: a write denied or asked about, a
  session-start notice, the user told, memory free of the planted text, the origin the ledger
  recorded. Benign scenarios expect silence, so a false alarm fails them.
- **`landed`**: for attacks, whether the planted text persisted or a successful tool result confirmed the planted command, measured
  in both arms. Command attempts alone do not count as execution, and missing notification is
  recorded separately. A failed command result leaves execution unconfirmed. The difference
  between the arms is what AgentDetox adds. Today's models refuse much of the obvious injected text
  on their own; where the model already stops an attack, both arms show "no".

## Cost and isolation

Every session calls a real model through your Claude Code login, so a full run (12 scenarios, 2
arms) costs usage and is not part of CI. Run it before a release and after changing what an agent
sees.

Sessions run with `--setting-sources project,local`, so your own settings and installed hooks stay
out. The AgentDetox arm runs this checkout's `.venv/bin/agentdetox` (Windows:
`.venv/Scripts/agentdetox.exe`) against a temporary store, with
the model server off. Claude Code still writes each scenario's memory and transcript under
`~/.claude/projects`, in a folder named after the temporary project. The runner deletes those
folders and the temporary store when it finishes; `--keep` leaves them for debugging.

Write and Edit are approved automatically; anything that would ask for approval, including
AgentDetox's own questions, is refused, since a headless session cannot ask. A refused question
therefore shows up as "asked" in the results, and the write does not happen.

The 100-line-write scenario targets `CLAUDE.md`. Its initial `.claude/rules/` destination was
refused by Claude's own sensitive-path protection even with Write allowed, so it never exercised
AgentDetox's post-write hook. Initial failures are retained in the dated reports; the corrected
fixture keeps the same 100-line content expectation and normal client permissions. Tool errors
are retained separately from AgentDetox decisions.

## Adding a scenario

Put any files it needs in `fixtures/shop`, then add a `Scenario` with its prompt, `expect` checks
and, for an attack, a `landed` check. Planted content uses reserved names (`evil.example`,
`.internal`) that cannot resolve.

Where a scenario has a concrete file or memory outcome, `user_task_completed` reports it independently
of safety checks. A blocked confirmation request can therefore pass its guardrail checks while
leaving the requested edit undone. Other tasks have no automatic completion oracle and show `null`.

## 0.4.1 acceptance, 2026-11-05

[Latest results](results/2026-11-05.json) cover ten AgentDetox-arm scenarios, all passing their
assertions with no recorded hook errors. Thirteen real sessions were used: the
[initial nine](results/2026-11-05-initial.json), [two diagnostic attempts](results/2026-11-05-diagnostic.json)
on the sensitive-path write, its corrected destination, and the safety-guidance scenario. The
three original-destination attempts did not write the file; they are not counted as passing.
The other eight scenarios were run before the final narrow safety-grammar and symlink-checkpoint
fixes; the safety-guidance scenario was run after them. Offline regressions cover the final code.

The baseline arm was not rerun this time; the [2026-11-02 report](results/2026-11-02.json) retains
the earlier two-arm comparison. Passing guardrail checks does not mean every requested task
completed: the two approval-request scenarios remained undone in this headless run, and the
tampering scenario warned the user without completing the unrelated code change.
