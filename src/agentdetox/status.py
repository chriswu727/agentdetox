"""`agentdetox status`: what is protected, how the checks are set, what happened lately."""

from __future__ import annotations

import time
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from . import __version__, allowlist, daemon, doctor, events, settings
from .consistency import NLI
from .context import home_dir
from .integrity import StoreError, baseline_entries, usage

ACTIVITY = ("blocked", "asked", "recorded", "contradictions", "notices")
_DECISIONS = {"deny": "blocked", "ask": "asked", "record": "recorded"}


def describe(row: dict) -> tuple[str, str, str]:
    """(what happened, what it was about, ids the user can allow) for one logged event."""
    event = row.get("event", "")
    flags = row.get("flags") or []
    ids = " ".join(dict.fromkeys(f.get("id", "") for f in flags)) or row.get("id", "")
    if event == "write_checked":
        label = _DECISIONS.get(row.get("decision", ""), row.get("decision", ""))
        text = "; ".join(f.get("what", "") for f in flags) or row.get("reason", "")
    elif event == "contradiction":
        label, text = "contradiction", f'"{row.get("new", "")}" vs "{row.get("existing", "")}"'
    elif event == "session_notice":
        label, text = "notice", " ".join(row.get("notice", "").splitlines()[1:])
    else:
        label, text = event, ""
    return label, " ".join(str(text).split()), ids


def _bucket(row: dict) -> str:
    if row.get("event") == "write_checked":
        return _DECISIONS.get(row.get("decision", ""), "")
    return {"contradiction": "contradictions", "session_notice": "notices"}.get(row.get("event", ""), "")


def collect(project: Path, days: int = 7) -> dict:
    problems = [c for c in doctor.run(project) if c.status != "ok"]
    try:
        files, store = baseline_entries(), usage()
    except StoreError:
        files, store = {}, None  # doctor's failure, shown under Health, says why
    current, _ = settings.load()
    rows = events.read(None)
    since = time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(time.time() - days * 86400))
    activity = Counter(_bucket(r) for r in rows if r.get("ts", "") >= since)
    return {
        "version": __version__,
        "health": [asdict(c) for c in problems],
        "watching": {
            "files": len(files),
            "by_kind": dict(Counter(e.get("kind", "?") for e in files.values()).most_common()),
            "last_snapshot": max((e.get("taken", "") for e in files.values()), default=""),
        },
        "checks": [asdict(s) for s in current],
        "contradiction_model": NLI.installed() and NLI().available(),
        "model_server": daemon.ping(),
        "store": store,
        "config_file": str(settings.config_path()) if settings.config_path().exists() else None,
        "allowed": len(allowlist.entries()),
        "days": days,
        "activity": {k: activity[k] for k in ACTIVITY},
        "recent": [dict(zip(("ts", "what", "about", "ids"), (r.get("ts", ""), *describe(r)))) for r in rows[-5:]],
    }


def render(data: dict) -> str:
    pad = " " * 15
    lines = [f"AgentDetox {data['version']}"]

    def row(label: str, *values: str) -> None:
        lines.append(f"  {label:<13}{values[0]}")
        lines.extend(pad + v for v in values[1:])

    health = data["health"]
    if not health:
        row("Health", "OK")
    else:
        fails = sum(h["status"] == "fail" for h in health)
        head = (f"{fails} failure(s), " if fails else "") + f"{len(health) - fails} warning(s); run `agentdetox doctor`"
        row("Health", head, *(f"- {h['message']}" for h in health))

    w = data["watching"]
    if w["files"]:
        kinds = ", ".join(f"{n} {k}" for k, n in w["by_kind"].items())
        row("Watching", f"{w['files']} context files ({kinds})", f"last snapshot {w['last_snapshot'].replace('T', ' ')}")
    else:
        row("Watching", "nothing yet; the snapshot is taken on install or at the first session")

    checks = ["clear-cut planted instructions: block"]
    for c in data["checks"]:
        source = (f" (AGENTDETOX_{c['key'].upper()})" if c["source"] == "env"
                  else " (config file)" if c["value"] != settings.DEFAULTS[c["key"]] else "")
        inactive = c["key"] == "contradiction" and c["value"] != "off" and not data["contradiction_model"]
        checks.append(f"{settings.LABELS[c['key']]}: {c['value']}{source}"
                      + (" (inactive: model not installed)" if inactive else ""))
    checks.append("change with `agentdetox config <key> <value>`")
    row("Checks", *checks)

    if data["contradiction_model"]:
        s = data["model_server"]
        row("Model server", f"running, pid {s['pid']}, model {'loaded' if s['model_loaded'] else 'not loaded yet'}, "
                            f"{s['jobs']} job(s), idle {s['idle_seconds'] // 60} min" if s else
                            "not running; starts on the next memory write with something to compare"
                            if daemon.SERVER else "not available on Windows yet; each check loads the model")
    st = data["store"]
    if st:
        row("Store", f"{st['bytes'] / 1e6:.1f} MB in {st['objects']} snapshot copies"
                     + (f" ({st['unreferenced']} superseded, cleaned daily)" if st["unreferenced"] else "")
                     + f", {st['quarantined']} quarantined file(s)")

    row("Allowlist", f"{data['allowed']} id(s)" + (" (`agentdetox allow --list`)" if data["allowed"] else ""))
    a = data["activity"]
    row(f"Last {data['days']} days", f"{a['blocked']} blocked, {a['asked']} asked, {a['recorded']} recorded, "
                                     f"{a['contradictions']} contradiction(s), {a['notices']} session notice(s)")
    if data["recent"]:
        recent = [f"{r['ts'][5:16].replace('T', ' ')}  {r['what']:<13} {r['about'][:90]}"
                  + (f" [{r['ids']}]" if r["ids"] else "") for r in data["recent"]]
        row("Recent", *recent, "`agentdetox events` for more")
    home = str(home_dir())
    return "\n".join(line.replace(home, "~") for line in lines)
