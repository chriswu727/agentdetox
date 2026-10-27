"""Snapshots of an agent's persistent context, tamper detection, and restore.

Out-of-band writes (an npm postinstall script, a compromised extension) never pass
through the agent's tool hooks, so the only way to see them is to compare what is on
disk now with what was there before.
"""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import shutil
import time
from dataclasses import dataclass
from pathlib import Path

from .agentscan import read_text, scan_text
from .context import ContextFile
from .findings import Finding
from .persistence import guarded_sections

# Matches our hook command however the executable path was quoted
# ("/x/agentdetox" hook, '/a b/agentdetox' hook, python -m agentdetox hook).
_SELF_RE = re.compile(r"agentdetox['\"]?\s+hook\b")


def is_self_hook(text: str) -> bool:
    return bool(_SELF_RE.search(text))


def store_dir() -> Path:
    return Path(os.environ.get("AGENTDETOX_HOME") or Path.home() / ".agentdetox")


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def _load_baseline() -> dict:
    path = store_dir() / "baseline.json"
    return json.loads(path.read_text()) if path.exists() else {"files": {}}


def baseline_paths() -> set[str]:
    return set(_load_baseline()["files"])


def _save_baseline(baseline: dict) -> None:
    store_dir().mkdir(parents=True, exist_ok=True)
    tmp = store_dir() / "baseline.json.tmp"
    tmp.write_text(json.dumps(baseline, indent=1, sort_keys=True))
    tmp.replace(store_dir() / "baseline.json")


def snapshot(files: list[ContextFile], roots: list[Path]) -> int:
    """Record the current state of `files` as trusted. Entries under `roots` that no
    longer exist are dropped; entries for other projects are kept."""
    baseline = _load_baseline()
    objects = store_dir() / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    root_strs = [str(r) + os.sep for r in roots]
    baseline["files"] = {
        p: e for p, e in baseline["files"].items()
        if not any(p.startswith(r) for r in root_strs) or Path(p).exists()
    }
    for cf in files:
        data = cf.path.read_bytes()
        digest = _sha(data)
        obj = objects / digest
        if not obj.exists():
            obj.write_bytes(data)
        text = data.decode("utf-8", errors="replace")
        baseline["files"][str(cf.path)] = {
            "sha256": digest,
            "agent": cf.agent,
            "kind": cf.kind,
            "scope": cf.scope,
            "sections": guarded_sections(cf.path, text) if cf.kind == "config" else {},
            "taken": time.strftime("%Y-%m-%dT%H:%M:%S"),
        }
    _save_baseline(baseline)
    return len(files)


@dataclass
class Change:
    path: str
    status: str  # "added", "modified", "deleted"
    kind: str


def verify(files: list[ContextFile], roots: list[Path]) -> tuple[list[Change], list[Finding]]:
    baseline = _load_baseline()["files"]
    changes: list[Change] = []
    findings: list[Finding] = []
    current = {str(cf.path): cf for cf in files}

    for path, cf in current.items():
        entry = baseline.get(path)
        text = read_text(cf.path)
        if entry is None:
            changes.append(Change(path, "added", cf.kind))
            findings.extend(scan_text(path, path, text, cf.kind))
            continue
        if _sha(cf.path.read_bytes()) == entry["sha256"]:
            continue
        if cf.kind == "config":
            # Agent configs churn constantly (counters, caches); only the
            # security-relevant sections count as a change.
            if guarded_sections(cf.path, text) == entry.get("sections", {}):
                continue
            changes.append(Change(path, "modified", cf.kind))
            findings.extend(_config_changes(path, cf.path, text, entry.get("sections", {})))
            findings.extend(scan_text(path, path, text, cf.kind))
        else:
            changes.append(Change(path, "modified", cf.kind))
            old = _object_text(entry["sha256"])
            # Only newly added lines can carry a new payload; scanning just those keeps
            # long-lived benign content from re-alerting on every edit.
            added = "\n".join(
                line[1:] for line in difflib.unified_diff(old.splitlines(), text.splitlines(), lineterm="", n=0)
                if line.startswith("+") and not line.startswith("+++")
            )
            for f in scan_text(path, path, added, cf.kind):
                f.message = f"{f.message} (added since snapshot)"
                findings.append(f)

    root_strs = [str(r) + os.sep for r in roots]
    for path, entry in baseline.items():
        if path not in current and any(path.startswith(r) for r in root_strs) and not Path(path).exists():
            changes.append(Change(path, "deleted", entry["kind"]))
            if entry["kind"] == "config" and is_self_hook(json.dumps(entry.get("sections", {}))):
                findings.append(Finding(path, path, "self-protection", "high",
                                        "a config file that registered AgentDetox hooks was deleted"))
    return changes, findings


def _config_changes(doc_id: str, path: Path, new: str, old_sections: dict) -> list[Finding]:
    new_sections = guarded_sections(path, new)
    findings = []
    for key in sorted(set(old_sections) | set(new_sections)):
        before, after = old_sections.get(key), new_sections.get(key)
        if before == after:
            continue
        if before and is_self_hook(before) and (after is None or not is_self_hook(after)):
            findings.append(Finding(doc_id, str(path), "self-protection", "high",
                                    f"AgentDetox hooks were removed from {key}", ""))
        else:
            verb = "added" if before is None else "removed" if after is None else "changed"
            findings.append(Finding(doc_id, str(path), "config-change", "medium",
                                    f"{key} {verb} since snapshot", (after or "")[:200]))
    return findings


def _object_text(digest: str) -> str:
    obj = store_dir() / "objects" / digest
    return obj.read_text(encoding="utf-8", errors="replace") if obj.exists() else ""


def restore(path: Path) -> Path | None:
    """Put the snapshotted version back. The current version is moved to quarantine,
    never deleted. Returns the quarantine location, or None if nothing was on disk."""
    entry = _load_baseline()["files"].get(str(path))
    if entry is None:
        raise KeyError(f"{path} is not in the snapshot")
    obj = store_dir() / "objects" / entry["sha256"]
    quarantined = None
    if path.exists():
        qdir = store_dir() / "quarantine" / time.strftime("%Y%m%d-%H%M%S")
        qdir.mkdir(parents=True, exist_ok=True)
        quarantined = qdir / str(path).lstrip(os.sep).replace(os.sep, "__")
        shutil.move(str(path), quarantined)
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(obj, path)
    return quarantined
