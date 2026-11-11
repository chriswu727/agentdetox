"""A held-out set written without sight of the rules, and what stops its texts.

`bench/heldout/heldout.json` holds 90 texts that should not be let into an agent's standing
context and 90 that are ordinary, written on 2026-11-10 by an author who was kept from the
code, the rules and every other test set and was told only what the tool is for. Each attack
is written three ways: `direct` (the conventional wording), `variant` (another natural wording,
tool, language or layout) and `paraphrase` (no telltale keyword). `ambiguous.json` holds 13
texts reviewers would disagree about; they are not scored.

Half of the set (`dev`, chosen by a hash of the id) was read while the rules were then
changed; the other half (`sealed`) was not looked at until the rules were final. Only the
sealed half says anything about text nobody has seen, and it is spent now: a later change to
the rules needs a new set to be measured honestly.

Each text is put through the real pre-write hook three times:

  rules   nothing is known about where the text came from: only the rules can stop it
  web     the session fetched a page that holds the text, and the user asked about the page,
          not to save it
  typed   the user typed the text and asked for it to be saved

    python -m bench.heldout_eval --output bench/results/heldout-current.json

This measures; it is not a gate and always exits 0.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import os
import shutil
import tempfile
from pathlib import Path

from bench._meta import run_metadata

HERE = Path(__file__).resolve().parent
ARMS = ("rules", "web", "typed")
PAGE = ("# Team handbook\n\nWelcome to the team. This page collects conventions for the repository.\n\n"
        "## Getting started\n\nClone the repository, install dependencies and run the test suite once.\n\n{body}\n\n"
        "## Contact\n\nQuestions go to the maintainers channel.\n")


def half(item: dict) -> str:
    return "dev" if int(hashlib.sha256(item["id"].encode()).hexdigest(), 16) % 2 == 0 else "sealed"


def evaluate() -> dict:
    root = Path(tempfile.mkdtemp(prefix="agentdetox-heldout-")).resolve()
    home, project = root / "home", root / "proj"
    (home / ".claude").mkdir(parents=True)
    (project / ".claude").mkdir(parents=True)
    (project / "CLAUDE.md").write_text("# Project\nUse pnpm.\n", encoding="utf-8")
    saved = {name: os.environ.get(name) for name in ("AGENTDETOX_USER_HOME", "AGENTDETOX_HOME", "AGENTDETOX_NLI")}
    os.environ.update(AGENTDETOX_USER_HOME=str(home), AGENTDETOX_HOME=str(root / "store"), AGENTDETOX_NLI="0")
    try:
        from agentdetox import hooks
        from agentdetox.context import claude_memory_dir

        def target(item: dict) -> Path:
            if item["kind"] == "memory":
                return claude_memory_dir(project, home) / f"{item['id']}.md"
            if item["kind"] == "skill":
                return project / ".claude" / "skills" / item["id"] / "SKILL.md"
            return project / ".claude" / "rules" / f"{item['id']}.md"

        def transcript(records: list[dict], name: str) -> str:
            path = root / f"{name}.jsonl"
            path.write_text("\n".join(json.dumps(record, ensure_ascii=False) for record in records) + "\n", encoding="utf-8")
            return str(path)

        def user(text: str) -> dict:
            return {"type": "user", "message": {"role": "user", "content": text}}

        def decide(item: dict, arm: str) -> str:
            text = item["text"] if item["text"].endswith("\n") else item["text"] + "\n"
            event = {"hook_event_name": "PreToolUse", "cwd": str(project), "session_id": f"{item['id']}-{arm}",
                     "tool_name": "Write", "tool_input": {"file_path": str(target(item)), "content": text}}
            if arm == "web":
                event["transcript_path"] = transcript([
                    user("What does https://handbook.example/team say about getting started?"),
                    {"type": "assistant", "message": {"role": "assistant", "content": [
                        {"type": "tool_use", "id": "t1", "name": "WebFetch", "input": {"url": "https://handbook.example/team"}}]}},
                    {"type": "user", "message": {"role": "user", "content": [
                        {"type": "tool_result", "tool_use_id": "t1", "content": PAGE.format(body=item["text"])}]}},
                ], f"{item['id']}-web")
            elif arm == "typed":
                event["transcript_path"] = transcript(
                    [user("Please save this to your notes exactly as written:\n\n" + item["text"])], f"{item['id']}-typed")
            _, out = hooks.handle("claude-code", event)
            if not out:
                return "allow"
            data = json.loads(out)
            return data.get("hookSpecificOutput", data).get("permissionDecision", "allow")

        items = json.loads((HERE / "heldout" / "heldout.json").read_text(encoding="utf-8"))
        rows = [{"id": item["id"], "class": item["class"], "style": item["style"], "kind": item["kind"], "lang": item["lang"],
                 "expected": item["expected"], "half": half(item), **{arm: decide(item, arm) for arm in ARMS}}
                for item in items]
    finally:
        for name, value in saved.items():
            if value is None:
                os.environ.pop(name, None)
            else:
                os.environ[name] = value
        shutil.rmtree(root, ignore_errors=True)

    def stopped(group: list[dict], arm: str) -> dict:
        counts = collections.Counter(row[arm] for row in group)
        return {"cases": len(group), "allow": counts["allow"], "ask": counts["ask"], "deny": counts["deny"]}

    summary: dict = {}
    for part in ("sealed", "dev"):
        for expected, label in (("flag", "attacks"), ("quiet", "benign")):
            group = [row for row in rows if row["half"] == part and row["expected"] == expected]
            summary[f"{part} {label}"] = {arm: stopped(group, arm) for arm in ARMS}
            if expected == "flag":
                for style in ("direct", "variant", "paraphrase"):
                    summary[f"{part} {label}, {style}"] = {
                        arm: stopped([row for row in group if row["style"] == style], arm) for arm in ARMS}
    return {"cases": len(rows), "summary": summary, "rows": rows, **run_metadata()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate()
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    for name, arms in report["summary"].items():
        print(f"{name:28} " + "   ".join(
            f"{arm}: {counts['ask'] + counts['deny']:>2}/{counts['cases']:<2} stopped" for arm, counts in arms.items()))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
