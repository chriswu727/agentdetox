"""`agentdetox agent inspect`: the session-start check, run by hand and for chosen clients.

A scan only reads. This records: every file with a finding gets a review item bound to
the exact version found (a C id that `review`, `clean` and `review accept` take), and
every file without a clear-cut finding gets a recovery checkpoint. It is the way to a
cleanup for a client with no hook (OpenClaw), for a hook that is not installed or
trusted, and for text that was there before AgentDetox was.

A checkpoint is something to restore to, not an acceptance. A file with a clear-cut
(high) finding open gets none and keeps whatever checkpoint it had; a file with only
lesser findings is checkpointed, as at session start, with those findings left open for
review. Nothing is allowed. Files outside the chosen clients are not read, recorded or
re-trusted, with one exception that is listed in the result: a context file that is a
symbolic link is read through the link, as the client reads it, wherever it points.
"""

from __future__ import annotations

import hashlib
import os
from pathlib import Path

from . import allowlist, engine, events, ledger, review, storage
from .agentscan import scan_stored, scan_text
from .context import ContextFile, Survey, classify, survey, watched_roots
from .findings import Finding, finding_id
from .integrity import baseline_entries, object_text, snapshot, store_lock
from .persistence import guarded_sections

_ATTRIBUTION = "present when inspected; when and by what it was written is unknown"


def run(agents: list[str] | None, project: Path | None) -> dict:
    found = survey(agents, project)
    roots = watched_roots(project)
    accepted, handled = review.accepted_versions(), review.handled_findings()
    read: list[tuple[ContextFile, bytes, str, str, list[Finding]]] = []
    unread: list[dict] = []
    linked: list[dict] = []
    for cf in found.files:
        try:
            data = cf.path.read_bytes()
        except OSError as error:
            unread.append({"path": str(cf.path), "error": type(error).__name__})
            continue
        if cf.path.is_symlink():
            linked.append({"path": str(cf.path), "target": os.path.realpath(cf.path)})
        digest = hashlib.sha256(data).hexdigest()
        # Scan the bytes that were hashed, with universal newlines as a text read gives.
        text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
        name = str(cf.path)
        flagged = [f for f in allowlist.unsuppressed(scan_stored(scan_text, name, name, text, cf.kind))
                   if f.severity in ("medium", "high") and accepted.get(name) != digest
                   and (name, digest, finding_id(f)) not in handled]
        read.append((cf, data, digest, text, flagged))
    items: list[dict] = []
    trusted: list[ContextFile] = []
    digests: dict[str, str | None] = {}
    with store_lock(), storage.connection(write=True) as db:
        for cf, data, digest, text, flagged in read:
            name = str(cf.path)
            if _digest(cf.path) != digest:
                # Written while it was being inspected: left for the next run, not recorded half-read.
                unread.append({"path": name, "error": "changed while it was inspected"})
                continue
            known = engine.previous_version(name)
            recorded = []
            if known is not None and known != digest:
                before = object_text(known)
                if cf.kind != "config" or guarded_sections(cf.path, before) != guarded_sections(cf.path, text):
                    entry = ledger.record(cf.path, "external", known, data, findings=engine.changed_findings(cf, before, text),
                                          method="comparison",
                                          attribution="found changed by `agentdetox agent inspect`; writer unknown")
                    if entry is not None:
                        recorded.append(entry.id)
            attached = {row["flag_id"] for row in db.execute(
                "SELECT f.flag_id FROM findings f JOIN changes c ON c.id=f.change_id WHERE c.path=? AND c.after_hash=?",
                (name, digest))}
            uncovered = [f for f in flagged if finding_id(f) not in attached]
            if uncovered:
                entry = ledger.record(cf.path, "inspected", digest, data, findings=uncovered, method=review.INSPECTION,
                                      actor="agentdetox agent inspect", attribution=_ATTRIBUTION)
                if entry is not None:
                    recorded.append(entry.id)
            pending = [dict(row) for row in db.execute(
                "SELECT c.id AS change, f.id AS finding, f.flag_id, f.severity, f.reason FROM findings f "
                "JOIN changes c ON c.id=f.change_id WHERE c.path=? AND c.after_hash=? AND f.status='pending' "
                "AND f.severity IN ('medium', 'high') ORDER BY c.id DESC, f.id", (name, digest))]
            if not any(row["severity"] == "high" for row in pending):
                trusted.append(cf)
                digests[name] = digest
            if pending or recorded:
                where = review.finding_lines(text, flagged)
                items.append({
                    "path": name, "agent": cf.agent, "kind": cf.kind,
                    "state": "review" if pending else "changed",
                    "changes": [f"C{i}" for i in sorted({row["change"] for row in pending} | set(recorded), reverse=True)],
                    "new": bool(recorded),
                    "findings": [{"id": f"F{row['finding']}", "flag": row["flag_id"], "severity": row["severity"],
                                  "reason": row["reason"], "line": where.get(row["flag_id"])} for row in pending],
                })
        for name, checkpoint in baseline_entries().items():
            path = Path(name)
            if (os.path.lexists(path) or not any(name.startswith(str(r) + os.sep) for r in roots)
                    or classify(path, agents, project) is None):
                continue
            latest = ledger.entries(name, limit=1)
            if latest and latest[-1].after is None:
                change = latest[-1].id
            else:
                removed = ledger.record(path, "external", engine.previous_version(name), None, method="comparison",
                                        attribution="found missing by `agentdetox agent inspect`; writer unknown")
                change = removed.id if removed is not None else 0
            items.append({"path": name, "agent": checkpoint.get("agent", ""), "kind": checkpoint.get("kind", ""),
                          "state": "deleted", "changes": [f"C{change}"], "new": not latest or latest[-1].id != change,
                          "findings": []})
        snapshot(trusted, roots, expected=digests)
        review_ids = [c for item in items if item["state"] == "review" for c in item["changes"]]
        events.record("context_inspected", agents=agents or [], project=str(project) if project else "",
                      files=len(read), review=review_ids)
    return {"files": len(read), "trusted": len(trusted), "items": items, "unread": unread, "linked": linked,
            "survey": found}


def _digest(path: Path) -> str | None:
    try:
        return hashlib.sha256(path.read_bytes()).hexdigest()
    except OSError:
        return None


def coverage(found: Survey) -> list[dict]:
    """The survey as plain data, for JSON output."""
    return [{"agent": c.agent, "verified": c.verified, "roots": c.roots, "files": c.files, "limits": c.limits,
             "problems": c.problems} for c in found.clients]


def render_coverage(found: Survey, short=str) -> list[str]:
    """Which folders were looked in for each client, and what was not looked at."""
    lines = ["Looked in:"]
    for c in found.clients:
        roots = ", ".join(f"{short(r['path'])}" + ("" if r["source"] in ("default", "default location", "project")
                                                  else f" ({r['source']})")
                          + ("" if r["exists"] else " [not present]") for r in c.roots)
        label = c.agent + ("" if c.verified else " (unverified)")
        lines.append(f"  {label:<24} {c.files} file(s) · {roots}")
    if found.problems:
        lines.append("Not resolved (these were asked for and could not be looked at):")
        lines += [f"  {problem}" for problem in found.problems]
    present = [c for c in found.clients if c.files or any(r["exists"] for r in c.roots if r["scope"] == "user")]
    limits = [f"  {c.agent}: {limit}" for c in present for limit in c.limits]
    absent = [c.agent for c in found.clients if c not in present and c.limits]
    if limits or absent:
        lines.append("Not covered by any file check:")
        lines += limits
    if absent:
        lines.append(f"  ({', '.join(absent)}: not found on this machine; `--format json` lists the limits of each)")
    return lines
