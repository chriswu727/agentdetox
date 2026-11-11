"""What the model check makes of a set of texts, asked the way a hook asks it.

This makes real model calls, one per text, through the Claude Code on this machine: a few
seconds and a fraction of a cent each. It is not part of any gate and is run on purpose:

    python -m bench.judge_eval --output bench/results/judge-current.json
    python -m bench.judge_eval --set path/to/other-set.json --output ...

Each call is the one `agentdetox.judge` makes: a new session with no tools, no MCP servers,
no skills and no user settings, in an empty folder, nothing saved. A set is a JSON list of
objects with `id`, `kind`, `text` and `expected` ("flag" or "quiet"); other keys are kept.
"""

from __future__ import annotations

import argparse
import collections
import hashlib
import json
import statistics
import time
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from agentdetox import judge
from bench._meta import run_metadata

HERE = Path(__file__).resolve().parent
KEPT = ("id", "class", "style", "tactic", "kind", "lang", "expected")


def half(item: dict) -> str:
    return "dev" if int(hashlib.sha256(item["id"].encode()).hexdigest(), 16) % 2 == 0 else "sealed"


def ask(item: dict) -> dict:
    started = time.perf_counter()
    said = judge.opinion(item["text"] if item["text"].endswith("\n") else item["text"] + "\n", item["kind"])
    return {**{key: item[key] for key in KEPT if key in item}, "half": half(item),
            "judge": "none" if said.flag is None else "flag" if said.flag else "ok", "category": said.category,
            "error": said.error, "seconds": round(time.perf_counter() - started, 2)}


def evaluate(path: Path, workers: int) -> dict:
    items = json.loads(path.read_text(encoding="utf-8"))
    with ThreadPoolExecutor(workers) as pool:
        rows = list(pool.map(ask, items))
    summary: dict = {}
    groups: dict[str, list[dict]] = collections.defaultdict(list)
    for row in rows:
        kind = "attacks" if row["expected"] == "flag" else "ordinary"
        groups[kind].append(row)
        if path.name == "heldout.json":
            groups[f"{row['half']} {kind}"].append(row)
        for key in ("style", "tactic"):
            if key in row and row["expected"] == "flag":
                groups[f"attacks, {row[key]}"].append(row)
    for name, group in groups.items():
        counts = collections.Counter(row["judge"] for row in group)
        summary[name] = {"cases": len(group), "flag": counts["flag"], "ok": counts["ok"], "none": counts["none"]}
    seconds = sorted(row["seconds"] for row in rows if row["judge"] != "none")
    timing = {"median": round(statistics.median(seconds), 2), "p95": round(seconds[int(len(seconds) * 0.95) - 1], 2),
              "max": seconds[-1]} if seconds else {}
    return {"set": path.name, "cases": len(rows), "model": judge.MODEL, "workers": workers, "summary": summary,
            "seconds_per_call": timing, "rows": rows, **run_metadata()}


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--set", type=Path, default=HERE / "heldout" / "heldout.json")
    parser.add_argument("--workers", type=int, default=4)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate(args.set, args.workers)
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=1, ensure_ascii=True) + "\n", encoding="utf-8")
    for name, counts in report["summary"].items():
        print(f"{name:34} flagged {counts['flag']:>3}/{counts['cases']:<3}  ok {counts['ok']:>3}  no opinion {counts['none']}")
    print("seconds per call:", report["seconds_per_call"])
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
