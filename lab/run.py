"""Replay the lab's scenarios against a real Claude Code session, with and without AgentDetox.

    .venv/bin/python -m lab.run                     # every scenario, both arms
    .venv/bin/python -m lab.run remember --arms agentdetox

Each run calls a real model through your Claude Code login, so it costs usage and is not part of
CI. Sessions skip your user settings (so your installed hooks stay out of it); the AgentDetox arm
runs this checkout's code against a temporary store. Claude Code still writes each scenario's
memory and transcript under ~/.claude/projects, in a folder named after the temporary project;
the runner deletes those folders and the temporary store afterwards unless --keep is given.
"""

from __future__ import annotations

import argparse
import datetime
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentdetox.context import claude_dir, claude_memory_dir
from agentdetox.install import claude_code_settings

from .scenarios import SCENARIOS, Outcome, Scenario

LAB = Path(__file__).resolve().parent
AGENTDETOX = LAB.parent / ".venv" / "bin" / "agentdetox"
ARMS = ("agentdetox", "none")
MARKER = "agentdetox-lab-"


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="lab.run", description=__doc__.split("\n\n")[0])
    parser.add_argument("names", nargs="*", help="scenarios to run (default: all)")
    parser.add_argument("--arms", default=",".join(ARMS), help="agentdetox, none, or both (default)")
    parser.add_argument("--jobs", type=int, default=4, help="sessions to run at once")
    parser.add_argument("--keep", action="store_true", help="keep the temporary projects and Claude folders")
    args = parser.parse_args(argv)
    chosen = [s for s in SCENARIOS if not args.names or s.name in args.names]
    arms = [a for a in args.arms.split(",") if a in ARMS]
    if not chosen or not arms or not AGENTDETOX.exists():
        print("nothing to run (unknown scenario or arm, or no .venv/bin/agentdetox)", file=sys.stderr)
        return 2

    base = Path(tempfile.mkdtemp(prefix=MARKER))
    for arm in arms:
        hooks = claude_code_settings({}, f"{AGENTDETOX} hook claude-code")["hooks"] if arm == "agentdetox" else {}
        (base / f"settings-{arm}.json").write_text(json.dumps({"hooks": hooks}), encoding="utf-8")
    jobs = [(s, a) for s in chosen for a in arms]
    try:
        with ThreadPoolExecutor(args.jobs) as pool:
            rows = list(pool.map(lambda job: run_one(*job, base), jobs))
    finally:
        if not args.keep:
            cleanup(base, jobs)
    write_results(rows)
    return 0 if all(r["passed"] is not False for r in rows) else 1


def run_one(scenario: Scenario, arm: str, base: Path) -> dict:
    project = base / f"{scenario.name}-{arm}"
    shutil.copytree(LAB / "fixtures" / "shop", project)
    env = {**os.environ, "AGENTDETOX_HOME": str(base / f"store-{scenario.name}-{arm}"), "AGENTDETOX_NLI": "0"}
    env.pop("AGENTDETOX_USER_HOME", None)
    if arm == "agentdetox":  # the trusted baseline a real install would already have
        subprocess.run([str(AGENTDETOX), "agent", "snapshot", "--project", str(project)], env=env,
                       capture_output=True, check=True)
    if scenario.tamper:
        subprocess.run(["sh", str(project / "scripts" / "postinstall.sh")], check=True)
    command = ["claude", "-p", scenario.prompt, "--setting-sources", "project,local",
               "--settings", str(base / f"settings-{arm}.json"), "--permission-mode", "acceptEdits",
               "--permission-prompts", "none", "--allowedTools", "Read", "Glob", "Grep",
               "--output-format", "stream-json", "--verbose", "--include-hook-events", "--max-turns", "20"]
    if scenario.model:
        command += ["--model", scenario.model]
    start = time.monotonic()
    done = subprocess.run(command, cwd=project, env=env, stdin=subprocess.DEVNULL, capture_output=True,
                          text=True, timeout=900)
    seconds = round(time.monotonic() - start)
    outcome, model = parse(done.stdout, project)
    log = base / f"store-{scenario.name}-{arm}" / "ledger.jsonl"
    if log.exists():
        outcome.origins = [json.loads(line).get("origin", "") for line in log.read_text(encoding="utf-8").splitlines()]
    checks = [{"check": c.label, "ok": c.test(outcome)} for c in scenario.expect] if arm == "agentdetox" else []
    print(f"  {scenario.name} [{arm}] {seconds}s", file=sys.stderr)
    return {
        "scenario": scenario.name, "arm": arm, "model": model, "seconds": seconds,
        "passed": all(c["ok"] for c in checks) if checks else None, "checks": checks,
        "landed": scenario.landed.test(outcome) if scenario.landed else None,
        "decisions": [[a, _anonymise(r, project)[:240]] for a, r in outcome.decisions],
        "noticed": bool(outcome.notice), "exit": done.returncode,
    }


def parse(stream: str, project: Path) -> tuple[Outcome, str]:
    decisions, notice, commands, text, model = [], "", [], [], ""
    for line in stream.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if event.get("type") == "system" and event.get("subtype") == "init":
            model = event.get("model", "")
        elif event.get("type") == "system" and event.get("subtype") == "hook_response" and event.get("output"):
            try:
                spec = json.loads(event["output"]).get("hookSpecificOutput", {})
            except (ValueError, AttributeError):
                continue
            if spec.get("permissionDecision") in ("deny", "ask"):
                decisions.append((spec["permissionDecision"], spec.get("permissionDecisionReason", "")))
            notice += spec.get("additionalContext", "")
        elif event.get("type") == "assistant":
            for block in event["message"].get("content", []):
                if block.get("type") == "text":
                    text.append(block["text"])
                elif block.get("type") == "tool_use" and block.get("name") == "Bash":
                    commands.append(str(block.get("input", {}).get("command", "")))
    memory_dir = claude_memory_dir(project)
    memory = "\n".join(p.read_text(encoding="utf-8", errors="replace") for p in sorted(memory_dir.glob("*.md")))
    files = {str(p.relative_to(project)): p.read_text(encoding="utf-8", errors="replace")
             for p in project.rglob("*") if p.is_file()}
    return Outcome(decisions, notice, commands, "\n".join(text), memory, files), model


def cleanup(base: Path, jobs: list[tuple[Scenario, str]]) -> None:
    projects = claude_dir() / "projects"
    for scenario, arm in jobs:
        # Named after a project inside this run's fresh temporary folder, so no one else's.
        folder = claude_memory_dir(base / f"{scenario.name}-{arm}").parent
        if folder.parent == projects and folder.is_dir():
            shutil.rmtree(folder)
    shutil.rmtree(base, ignore_errors=True)


def write_results(rows: list[dict]) -> None:
    out = LAB / "results"
    out.mkdir(exist_ok=True)
    stamp = datetime.date.today().isoformat()
    day = out / f"{stamp}.json"
    if day.exists():  # a partial rerun replaces only its own rows
        ran = {(r["scenario"], r["arm"]) for r in rows}
        rows = [r for r in json.loads(day.read_text(encoding="utf-8")) if (r["scenario"], r["arm"]) not in ran] + rows
    day.write_text(json.dumps(rows, indent=1, ensure_ascii=False) + "\n", encoding="utf-8")
    lines = [f"# Lab results, {stamp}", "", "| Scenario | Arm | Model | Checks | Attack landed | Decisions | Time |",
             "|---|---|---|---|---|---|---|"]
    for r in sorted(rows, key=lambda r: (r["scenario"], r["arm"])):
        checks = "—" if r["passed"] is None else ("pass" if r["passed"] else
                                                 "FAIL: " + "; ".join(c["check"] for c in r["checks"] if not c["ok"]))
        landed = "—" if r["landed"] is None else ("yes" if r["landed"] else "no")
        decided = ", ".join(a for a, _ in r["decisions"]) or "—"
        lines.append(f"| {r['scenario']} | {r['arm']} | {r['model']} | {checks} | {landed} | {decided} | {r['seconds']}s |")
    (out / "latest.md").write_text("\n".join(lines) + "\n", encoding="utf-8")
    print("\n".join(lines))


def _anonymise(text: str, project: Path) -> str:
    text = text.replace(claude_memory_dir(project).parent.name, "<project>")
    for form in (os.path.realpath(project), str(project)):  # hooks see the physical path
        text = text.replace(form, "<project>")
    return text.replace(str(Path.home()), "~")


if __name__ == "__main__":
    sys.exit(main())
