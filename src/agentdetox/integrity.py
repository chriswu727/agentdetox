"""Snapshots of an agent's persistent context, tamper detection, and restore.

Out-of-band writes (an npm postinstall script, a compromised extension) never pass
through the agent's tool hooks, so the only way to see them is to compare what is on
disk now with what was there before.
"""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import shutil
import threading
import time
from dataclasses import dataclass
from pathlib import Path

from .agentscan import read_text, scan_text
from .compat import release, try_lock
from .context import ContextFile
from .findings import Finding
from .persistence import guarded_sections

# Matches our hook command however the executable path was quoted
# ("/x/agentdetox" hook, '/a b/agentdetox' hook, "C:\x\agentdetox.EXE" hook, python -m agentdetox hook).
# The optional backslash: snapshots keep config sections JSON-encoded, where a Windows hook
# command's double quote around the executable becomes \".
_SELF_RE = re.compile(r"agentdetox(?:\.exe)?\\?['\"]?\s+hook\b", re.IGNORECASE)


def is_self_hook(text: str) -> bool:
    return bool(_SELF_RE.search(text))


def store_dir() -> Path:
    return Path(os.environ.get("AGENTDETOX_HOME") or Path.home() / ".agentdetox")


def private_dir(path: Path) -> Path:
    # Snapshots copy files such as ~/.claude.json and settings.json that can hold
    # tokens or API keys; the copies must not be more readable than the originals.
    path.mkdir(parents=True, exist_ok=True, mode=0o700)
    os.chmod(path, 0o700)
    return path


def write_private(path: Path, data: bytes) -> None:
    # O_BINARY: without it Windows opens the descriptor in text mode and turns every "\n"
    # of a snapshot copy into "\r\n", so a restore would not give back the original.
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | getattr(os, "O_BINARY", 0), 0o600)
    with os.fdopen(fd, "wb") as f:
        f.write(data)


def _sha(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


# 0: 0.1.0 before versioning (same layout, no "version" key). 1: adds "version" and "last_gc".
SCHEMA_VERSION = 1
GC_INTERVAL = 24 * 3600
LOCK_TIMEOUT = 10.0


class StoreError(RuntimeError):
    """The store cannot be trusted as it is. Starting over silently would accept
    whatever is on disk now, tampered files included, so this is reported instead."""


_LOCK = threading.RLock()
_lock_depth = 0


@contextlib.contextmanager
def store_lock(timeout: float = LOCK_TIMEOUT):
    """Serialise read-modify-write of the store across hooks, the model server and the
    CLI; parallel tool calls otherwise lose each other's snapshot entries. Re-entrant
    within a process (flock on a second descriptor would wait for ourselves)."""
    global _lock_depth
    with _LOCK:
        if _lock_depth:
            _lock_depth += 1
            try:
                yield
            finally:
                _lock_depth -= 1
            return
        fd = os.open(private_dir(store_dir()) / "store.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            deadline = time.monotonic() + timeout
            while not try_lock(fd):
                if time.monotonic() > deadline:
                    raise TimeoutError(f"{store_dir()} is locked by another process")
                time.sleep(0.01)
            _lock_depth = 1
            try:
                yield
            finally:
                _lock_depth = 0
        finally:
            release(fd)


_RESET_HINT = ("Check the agent's memory, rules and config, then run `agentdetox agent snapshot --reset` "
               "to trust them as they are now.")


def _load_baseline() -> dict:
    path = store_dir() / "baseline.json"
    if not path.exists():
        objects = store_dir() / "objects"
        if objects.is_dir() and any(objects.iterdir()):
            raise StoreError(f"{path} is missing although snapshot copies exist, so it may have been deleted "
                             f"to hide changes. {_RESET_HINT}")
        return {"version": SCHEMA_VERSION, "files": {}}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as e:
        raise StoreError(f"{path} is damaged ({e}). {_RESET_HINT}") from None
    version = data.get("version", 0) if isinstance(data, dict) else -1
    if not isinstance(data, dict) or not isinstance(data.get("files"), dict):
        raise StoreError(f"{path} does not look like an AgentDetox snapshot list")
    if version > SCHEMA_VERSION:
        raise StoreError(f"{path} was written by a newer AgentDetox (store version {version}, this one "
                         f"reads up to {SCHEMA_VERSION}); upgrade agentdetox")
    data["version"] = SCHEMA_VERSION
    return data


def baseline_paths() -> set[str]:
    return set(_load_baseline()["files"])


def baseline_entries() -> dict[str, dict]:
    return _load_baseline()["files"]


def _save_baseline(baseline: dict) -> None:
    baseline["version"] = SCHEMA_VERSION
    tmp = private_dir(store_dir()) / "baseline.json.tmp"
    write_private(tmp, json.dumps(baseline, indent=1, sort_keys=True).encode())
    tmp.replace(store_dir() / "baseline.json")


def reset_baseline() -> Path | None:
    """Start a new snapshot list after the old one was damaged or deleted. The old file is
    kept beside it; returns where, or None if there was none."""
    with store_lock():
        path = store_dir() / "baseline.json"
        kept = None
        if path.exists():
            kept = path.with_name(f"baseline.json.broken-{time.strftime('%Y%m%d-%H%M%S')}")
            path.replace(kept)
        _save_baseline({"version": SCHEMA_VERSION, "files": {}})
    return kept


def snapshot(files: list[ContextFile], roots: list[Path]) -> int:
    """Record the current state of `files` as trusted. Entries under `roots` that no
    longer exist are dropped; entries for other projects are kept."""
    with store_lock():
        return _snapshot(files, roots)


def _snapshot(files: list[ContextFile], roots: list[Path]) -> int:
    baseline = _load_baseline()
    private_dir(store_dir())
    objects = private_dir(store_dir() / "objects")
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
            write_private(obj, data)
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


def snapshot_text(path: str) -> str | None:
    entry = _load_baseline()["files"].get(path)
    return None if entry is None else _object_text(entry["sha256"])


def _object_text(digest: str) -> str:
    obj = store_dir() / "objects" / digest
    return obj.read_text(encoding="utf-8", errors="replace") if obj.exists() else ""


def restore(path: Path) -> Path | None:
    """Put the snapshotted version back. The current version is moved to quarantine,
    never deleted. Returns the quarantine location, or None if nothing was on disk."""
    with store_lock():
        return _restore(path)


def _restore(path: Path) -> Path | None:
    entry = _load_baseline()["files"].get(str(path))
    if entry is None:
        raise KeyError(f"{path} is not in the snapshot")
    obj = store_dir() / "objects" / entry["sha256"]
    quarantined = None
    if path.exists():
        private_dir(store_dir() / "quarantine")
        qdir = private_dir(store_dir() / "quarantine" / time.strftime("%Y%m%d-%H%M%S"))
        # Flattening the full path overflows the 255-byte name limit for deep paths
        # such as Claude Code's per-project memory dirs, so use a short hashed name and
        # record the original location in a manifest.
        quarantined = qdir / f"{_sha(str(path).encode())[:12]}-{path.name}"
        shutil.move(str(path), quarantined)
        os.chmod(quarantined, 0o600)
        manifest = qdir / "manifest.json"
        entries = json.loads(manifest.read_text(encoding="utf-8")) if manifest.exists() else {}
        entries[quarantined.name] = str(path)
        write_private(manifest, json.dumps(entries, indent=1).encode())
    path.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(obj, path)
    return quarantined


def gc(force: bool = False) -> dict | None:
    """Delete snapshot copies no entry refers to any more (each trusted write leaves the
    previous version behind) and job files a crashed model server never picked up.
    Quarantine is never touched: it holds the user's own files. Without `force`, runs
    at most once per GC_INTERVAL and returns None when skipped."""
    with store_lock():
        baseline = _load_baseline()
        now = time.time()
        if not force and now - baseline.get("last_gc", 0) < GC_INTERVAL:
            return None
        referenced = {e["sha256"] for e in baseline["files"].values()}
        removed = freed = 0
        objects = store_dir() / "objects"
        for obj in objects.iterdir() if objects.is_dir() else []:
            if obj.name not in referenced:
                freed += obj.stat().st_size
                obj.unlink()
                removed += 1
        pending = store_dir() / "pending"
        for job in pending.iterdir() if pending.is_dir() else []:
            if now - job.stat().st_mtime > GC_INTERVAL:
                job.unlink()
        baseline["last_gc"] = now
        _save_baseline(baseline)
    return {"objects": removed, "bytes": freed}


def usage() -> dict:
    """Sizes for `agentdetox status`."""
    files = _load_baseline()["files"]
    referenced = {e["sha256"] for e in files.values()}
    objects = [p for p in (store_dir() / "objects").iterdir()] if (store_dir() / "objects").is_dir() else []
    quarantine = store_dir() / "quarantine"
    return {
        "tracked": len(files),
        "objects": len(objects),
        "unreferenced": sum(p.name not in referenced for p in objects),
        "bytes": sum(p.stat().st_size for p in objects),
        "quarantined": sum(1 for p in quarantine.rglob("*") if p.is_file() and p.name != "manifest.json")
        if quarantine.is_dir() else 0,
    }
