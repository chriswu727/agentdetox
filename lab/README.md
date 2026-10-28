# AgentDetox lab

Replays attacks, and everyday use, against a real Claude Code session, once with AgentDetox and
once without, and records what happened. It is how AgentDetox's claims are checked: synthetic
benchmarks in `bench/` measure the detectors, the lab measures the product in a real agent.

```bash
.venv/bin/python -m lab.run                          # every scenario, both arms
.venv/bin/python -m lab.run postinstall-tamper       # one scenario
.venv/bin/python -m lab.run --arms agentdetox        # only with AgentDetox
```

Results go to `lab/results/<date>.json` and `lab/results/latest.md`. The command exits non-zero
if any check fails with AgentDetox.

## What a run measures

Each scenario in `scenarios.py` has:

- **`expect`**: what must hold with AgentDetox installed: a write denied or asked about, a
  session-start notice, the user told, memory free of the planted text. Benign scenarios expect
  silence, so a false alarm fails them.
- **`landed`**: for attacks, whether the attack succeeded, measured in both arms. The difference
  between the arms is what AgentDetox adds. Today's models refuse much of the obvious injected text
  on their own; where the model already stops an attack, both arms show "no".

## Cost and isolation

Every session calls a real model through your Claude Code login, so a full run (8 scenarios, 2
arms) costs usage and is not part of CI. Run it before a release and after changing what an agent
sees.

Sessions run with `--setting-sources project,local`, so your own settings and installed hooks stay
out. The AgentDetox arm runs this checkout's `.venv/bin/agentdetox` against a temporary store, with
the model server off. Claude Code still writes each scenario's memory and transcript under
`~/.claude/projects`, in a folder named after the temporary project. The runner deletes those
folders and the temporary store when it finishes; `--keep` leaves them for debugging.

Write and Edit are approved automatically; anything that would ask for approval, including
AgentDetox's own questions, is refused, since a headless session cannot ask. A refused question
therefore shows up as "asked" in the results, and the write does not happen.

## Adding a scenario

Put any files it needs in `fixtures/shop`, then add a `Scenario` with its prompt, `expect` checks
and, for an attack, a `landed` check. Planted content uses reserved names (`evil.example`,
`.internal`) that cannot resolve.
