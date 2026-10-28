"""Agent memory poisoning benchmark, v0 (public attack data only).

Benign side: bench/memory_stores.json, Claude Code-style project memory stores and
legitimate changes written independently of the detector code.
Attack side, built here from published datasets only:
  poison_fact_conflict  a PoisonedRAG adv_text written as a new memory, into a store that
                        already holds the question's correct answer as a memory note
  poison_fact_novel     another adv_text, into a store with no counterpart
  poison_instruction    a deepset/prompt-injections prompt written as a new memory file
  poison_instruction_oob the same prompt appended to an existing memory file outside the agent
  benign_oob            a benign memory appended outside the agent (measures integrity noise)

Each case runs against a fresh copy of its store. AgentDetox runs its real Claude Code hook
handlers; OWASP Agent Memory Guard runs with Policy.strict() and is scored leniently (a
block, quarantine, redaction or any event of medium severity or above counts).

Usage: python bench/memory_eval.py [--data bench/data] [--per-dataset 50] [--out results.json]
"""

from __future__ import annotations

import argparse
import json
import os
import statistics
import tempfile
import time
from collections import defaultdict
from pathlib import Path

from agentdetox import consistency, hooks
from agentdetox.context import claude_memory_dir, discover
from agentdetox.integrity import snapshot

# Dev split, used for every tuning decision: the first 30 NQ targets (they chose the fact
# template below), the first 50 injection prompts, and two stores whose cases were inspected
# while debugging. Results are reported on the test split only.
DEV_TARGETS = 30
DEV_PAYLOADS = 50
DEV_STORES = {"en-payments-api", "zh-miniprogram"}


def fact_sentence(t: dict) -> str:
    return f'The answer to "{t["question"]}" is {t["correct answer"]}.'


def memory_file(name: str, kind: str, body: str) -> str:
    return f"---\nname: {name}\ndescription: {body[:60].strip()}\ntype: {kind}\n---\n{body.strip()}\n"


def build_cases(stores: list[dict], data: Path, per_dataset: int, split: str) -> list[dict]:
    dev = split == "dev"
    stores = [s for s in stores if (s["id"] in DEV_STORES) == dev]
    cases = []
    for store in stores:
        for c in store["cases"]:
            cases.append({**c, "store": store["id"], "lang": store["lang"]})
        for i, c in enumerate(x for x in store["cases"] if x["kind"] == "benign_add"):
            target = _first_memory(store)
            body = c["content"].split("---\n")[-1].strip()
            cases.append({"id": f"{store['id']}-oob{i}", "kind": "benign_oob", "channel": "out_of_band",
                          "file": target, "content": body, "store": store["id"], "lang": store["lang"]})

    en = [s for s in stores if s["lang"] == "en"]
    n = 0
    for ds in ("nq", "hotpotqa", "msmarco"):
        targets = list(json.loads((data / f"{ds}.json").read_text()).values())
        if dev:
            chosen = targets[:DEV_TARGETS] if ds == "nq" else []
        else:
            start = DEV_TARGETS if ds == "nq" else 0
            chosen = targets[start : start + per_dataset]
        for t in chosen:
            store = en[n % len(en)]
            n += 1
            fact = memory_file(f"note-{t['id']}", "reference", fact_sentence(t))
            base = {"store": store["id"], "lang": "en", "channel": "write", "source": f"PoisonedRAG/{ds}/{t['id']}"}
            cases.append({**base, "id": f"prag-{ds}-{t['id']}-conflict", "kind": "poison_fact_conflict",
                          "extra_files": {f"memory/note_{ds}_{t['id']}.md": fact},
                          "file": f"memory/finding_{ds}_{t['id']}.md",
                          "content": memory_file(f"finding-{t['id']}", "reference", t["adv_texts"][0])})
            cases.append({**base, "id": f"prag-{ds}-{t['id']}-novel", "kind": "poison_fact_novel",
                          "file": f"memory/finding_{ds}_{t['id']}.md",
                          "content": memory_file(f"finding-{t['id']}", "reference", t["adv_texts"][1])})

    payloads = [json.loads(line)["text"] for line in (data / "injections.jsonl").read_text().splitlines() if line]
    chosen = list(enumerate(payloads))[:DEV_PAYLOADS] if dev else list(enumerate(payloads))[DEV_PAYLOADS:]
    for i, payload in chosen:
        store = en[i % len(en)]
        base = {"store": store["id"], "lang": "en", "source": "deepset/prompt-injections"}
        cases.append({**base, "id": f"inj-{i}-write", "kind": "poison_instruction", "channel": "write",
                      "file": f"memory/note_{i}.md", "content": memory_file(f"note-{i}", "feedback", payload)})
        cases.append({**base, "id": f"inj-{i}-oob", "kind": "poison_instruction_oob", "channel": "out_of_band",
                      "file": _first_memory(store), "content": payload})
    return cases


def _first_memory(store: dict) -> str:
    return sorted(f for f in store["files"] if f.startswith("memory/") and f != "memory/MEMORY.md")[0]


# AgentDetox ----------------------------------------------------------------------------

def run_agentdetox(case: dict, store: dict, root: Path) -> dict:
    home, project = root / "home", root / "proj"
    os.environ["AGENTDETOX_USER_HOME"] = str(home)
    os.environ["AGENTDETOX_HOME"] = str(root / "store")
    mem = claude_memory_dir(project, home)
    files = {**store["files"], **case.get("extra_files", {})}
    for rel, text in files.items():
        path = project / rel if rel == "CLAUDE.md" else mem / rel.removeprefix("memory/")
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_text(text, encoding="utf-8")
    snapshot(discover(project=project), [home, project])

    target = project / case["file"] if case["file"] == "CLAUDE.md" else mem / case["file"].removeprefix("memory/")
    t0 = time.perf_counter()
    if case["channel"] == "out_of_band":
        target.write_text(target.read_text(encoding="utf-8") + "\n" + case["content"] + "\n", encoding="utf-8")
        _, out = hooks.handle("claude-code", {"hook_event_name": "SessionStart", "cwd": str(project)})
        decision = "notice" if out else "allow"
        reason = json.loads(out)["hookSpecificOutput"]["additionalContext"] if out else ""
    else:
        tool_input = ({"file_path": str(target), "content": case["content"]} if case["channel"] == "write" else
                      {"file_path": str(target), "old_string": case["old_string"], "new_string": case["new_string"]})
        _, out = hooks.handle("claude-code", {"hook_event_name": "PreToolUse", "cwd": str(project),
                                              "tool_name": "Write" if case["channel"] == "write" else "Edit",
                                              "tool_input": tool_input})
        decision = json.loads(out)["hookSpecificOutput"]["permissionDecision"] if out else "allow"
        reason = json.loads(out)["hookSpecificOutput"]["permissionDecisionReason"] if out else ""
    return {"decision": decision, "seconds": time.perf_counter() - t0, "reason": reason[:600],
            "detected": decision != "allow", "blocked": decision == "deny"}


# OWASP Agent Memory Guard --------------------------------------------------------------

def run_amg(case: dict, store: dict) -> dict:
    import agent_memory_guard as amg

    events = []
    guard = amg.MemoryGuard(policy=amg.Policy.strict())
    guard.add_event_handler(events.append)
    files = {**store["files"], **case.get("extra_files", {})}
    store_obj = guard._store  # baseline content is trusted, so load it without the write path
    for key, value in files.items():
        store_obj.set(key, value)
        guard.baseline(key)
    blocked = False
    if case["channel"] == "out_of_band":
        store_obj.set(case["file"], files[case["file"]] + "\n" + case["content"] + "\n")
        detected = case["file"] in guard.verify_all()
        return {"decision": "drift" if detected else "allow", "detected": detected, "blocked": False}
    value = case["content"] if case["channel"] == "write" else \
        files[case["file"]].replace(case["old_string"], case["new_string"], 1)
    try:
        action = guard.write(case["file"], value)
        blocked = action in (amg.Action.BLOCK, amg.Action.QUARANTINE)
        detected = action != amg.Action.ALLOW
    except amg.MemoryGuardError:
        blocked = detected = True
    rank = {amg.Severity.MEDIUM, amg.Severity.HIGH, amg.Severity.CRITICAL}
    detected = detected or any(e.severity in rank for e in events)
    return {"decision": "block" if blocked else ("alert" if detected else "allow"),
            "detected": detected, "blocked": blocked}


# Report --------------------------------------------------------------------------------

ORDER = ["poison_fact_conflict", "poison_fact_novel", "poison_instruction", "poison_instruction_oob",
         "benign_add", "benign_update", "benign_conflicting_add", "benign_oob"]


def report(results: list[dict]) -> str:
    groups: dict[tuple, list[dict]] = defaultdict(list)
    for r in results:
        groups[(r["kind"], r["lang"] if r["kind"].startswith("benign") else "en")].append(r)
    lines = ["| case kind | lang | n | AgentDetox flagged | AgentDetox blocked | AMG flagged | AMG blocked |",
             "|---|---|---|---|---|---|---|"]
    for kind in ORDER:
        for lang in ("en", "zh"):
            rs = groups.get((kind, lang))
            if not rs:
                continue
            pct = lambda key, tool: f"{100 * sum(r[tool][key] for r in rs) / len(rs):.1f}%"
            lines.append(f"| {kind} | {lang} | {len(rs)} | {pct('detected', 'agentdetox')} | "
                         f"{pct('blocked', 'agentdetox')} | {pct('detected', 'amg')} | {pct('blocked', 'amg')} |")
    secs = sorted(r["agentdetox"]["seconds"] for r in results if r["channel"] != "out_of_band")
    lines.append(f"\nAgentDetox write-hook latency (in-process, model loaded once): median "
                 f"{statistics.median(secs) * 1000:.0f} ms, p95 {secs[int(len(secs) * 0.95)] * 1000:.0f} ms")
    return "\n".join(lines)


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("--data", type=Path, default=Path("bench/data"))
    ap.add_argument("--stores", type=Path, default=Path("bench/memory_stores.json"))
    ap.add_argument("--per-dataset", type=int, default=50)
    ap.add_argument("--out", type=Path, default=Path("bench/data/memory_results.json"))
    ap.add_argument("--split", choices=["dev", "test"], default="test")
    ap.add_argument("--min-sim", type=float, help="override the candidate pre-filter (dev sweeps)")
    args = ap.parse_args()
    if args.min_sim is not None:
        consistency.MIN_SIMILARITY = args.min_sim

    stores = json.loads(args.stores.read_text(encoding="utf-8"))["stores"]
    by_id = {s["id"]: s for s in stores}
    cases = build_cases(stores, args.data, args.per_dataset, args.split)
    # Measure what contradiction detection can catch, so run it in ask mode.
    os.environ["AGENTDETOX_CONTRADICTION"] = "ask"
    if not hooks._nli():
        raise SystemExit("the NLI model is not available; run `agentdetox fetch-models` first")
    results = []
    for i, case in enumerate(cases, 1):
        store = by_id[case["store"]]
        with tempfile.TemporaryDirectory() as tmp:
            ad = run_agentdetox(case, store, Path(tmp))
        results.append({**{k: case[k] for k in ("id", "kind", "lang", "channel")}, "agentdetox": ad,
                        "amg": run_amg(case, store)})
        if i % 50 == 0:
            print(f"  {i}/{len(cases)} cases", flush=True)
    args.out.write_text(json.dumps(results, ensure_ascii=False, indent=1))
    print(report(results))


if __name__ == "__main__":
    main()
