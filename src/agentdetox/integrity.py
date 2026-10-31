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
import stat
import tempfile
import threading
import time
import uuid
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
SCHEMA_VERSION = 2
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
    from . import storage

    return storage.baseline() or _load_legacy_baseline()


def _load_legacy_baseline() -> dict:
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
    from . import storage

    storage.save_baseline(baseline)


def reset_baseline() -> Path | None:
    """Start a new snapshot list after the old one was damaged or deleted. The old file is
    kept beside it; returns where, or None if there was none."""
    from . import storage

    kept: Path | None = None
    with store_lock():
        import sqlite3

        if storage.path().exists():
            with contextlib.closing(sqlite3.connect(storage.path())) as probe:
                incomplete = probe.execute("PRAGMA user_version").fetchone()[0] == 0
            if incomplete:
                storage.path().unlink()
        if storage.exists():

            kept = store_dir() / f"state.sqlite3.backup-{uuid.uuid4().hex}"
            with storage.connection(write=True) as db:
                with contextlib.closing(sqlite3.connect(kept)) as backup:
                    # Backup on a separate read connection avoids waiting on our own write transaction.
                    with contextlib.closing(sqlite3.connect(storage.path())) as reader:
                        reader.backup(backup)
                os.chmod(kept, 0o600)
                db.execute('UPDATE files SET checkpoint=NULL')
            return kept
        path = store_dir() / "baseline.json"
        kept = None
        if path.exists():
            kept = path.with_name(f"baseline.json.broken-{uuid.uuid4().hex}")
            path.replace(kept)
        _save_baseline({"version": SCHEMA_VERSION, "files": {}})
        return kept


def snapshot(files: list[ContextFile], roots: list[Path]) -> int:
    """Record recovery checkpoints without forgetting deleted files."""
    with store_lock():
        return _snapshot(files, roots)


def _snapshot(files: list[ContextFile], roots: list[Path]) -> int:
    baseline = _load_baseline()
    private_dir(store_dir())
    private_dir(store_dir() / "objects")
    for cf in files:
        data = cf.path.read_bytes()
        digest = _sha(data)
        store_object(data)
        previous = baseline["files"].get(str(cf.path))
        if previous and previous["sha256"] == digest and previous.get("mode") == stat.S_IMODE(cf.path.stat().st_mode):
            continue
        text = data.decode("utf-8", errors="replace")
        baseline["files"][str(cf.path)] = {
            "sha256": digest,
            "mode": stat.S_IMODE(cf.path.stat().st_mode),
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
            old = object_text(entry["sha256"])
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
            if entry["kind"] == "config" and any(is_self_hook(value) for value in entry.get("sections", {}).values()):
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
        if key == "disableAllHooks" and after == "true":
            findings.append(Finding(doc_id, str(path), "self-protection", "high",
                                    "all non-managed hooks were disabled", "disableAllHooks: true"))
        elif before and is_self_hook(before) and (after is None or not is_self_hook(after)):
            findings.append(Finding(doc_id, str(path), "self-protection", "high",
                                    f"AgentDetox hooks were removed from {key}", ""))
        else:
            verb = "added" if before is None else "removed" if after is None else "changed"
            findings.append(Finding(doc_id, str(path), "config-change", "medium",
                                    f"{key} {verb} since snapshot", (after or "")[:200]))
    return findings


def snapshot_text(path: str) -> str | None:
    entry = _load_baseline()["files"].get(path)
    return None if entry is None else object_text(entry["sha256"])


def snapshot_digest(path: str) -> str | None:
    """Which stored copy is the trusted version of `path`."""
    entry = _load_baseline()["files"].get(path)
    return None if entry is None else entry["sha256"]


def store_object(data: bytes) -> str:
    """Keep a copy of `data` in the store, named by its hash, and return the name."""
    private_dir(store_dir())
    digest = _sha(data)
    obj = private_dir(store_dir() / "objects") / digest
    if obj.exists():
        if _sha(obj.read_bytes()) != digest:
            raise StoreError(f"Stored object {digest} is corrupt; recovery data was not overwritten")
        return digest
    fd, name = tempfile.mkstemp(prefix=".object-", dir=obj.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        tmp.replace(obj)
    finally:
        tmp.unlink(missing_ok=True)
    return digest


def object_text(digest: str) -> str:
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
    return restore_object(path, entry["sha256"], entry.get("mode", 0o600))


def restore_object(path: Path, digest: str, mode: int = 0o600, expected: str | None | bool = False,
                   quarantine_dir: Path | None = None) -> Path | None:
    if path.is_symlink():
        raise StoreError(f"Cannot restore a symbolic link: {path}")
    if expected is not False:
        actual = _sha(path.read_bytes()) if path.exists() else None
        if actual != expected:
            raise StoreError(f"{path} changed since review; recovery was not applied")
    obj = store_dir() / "objects" / digest
    try:
        data = obj.read_bytes()
    except OSError as e:
        raise StoreError(f"Cannot read recovery copy for {path}: {e}") from e
    if _sha(data) != digest:
        raise StoreError(f"Recovery copy for {path} failed its integrity check")
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, name = tempfile.mkstemp(prefix=".agentdetox-restore-", dir=path.parent)
    tmp = Path(name)
    quarantined = None
    try:
        with os.fdopen(fd, "wb") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.chmod(tmp, mode & 0o777)
        if path.exists():
            current = path.read_bytes()
            qdir = private_dir(quarantine_dir or store_dir() / "quarantine" / uuid.uuid4().hex)
            quarantined = qdir / "content"
            write_private(quarantined, current)
            with quarantined.open("r+b") as f:
                os.fsync(f.fileno())
            if quarantined.read_bytes() != current:
                raise StoreError(f"Could not verify quarantine copy for {path}")
            write_private(qdir / "manifest.json", json.dumps({"content": str(path)}).encode())
            if path.is_symlink() or path.read_bytes() != current:
                raise StoreError(f"{path} changed during restore; review it again")
        if path.is_symlink():
            raise StoreError(f"{path} became a symbolic link during recovery")
        if expected is not False and (_sha(path.read_bytes()) if path.exists() else None) != expected:
            raise StoreError(f"{path} changed during recovery; original was left in place")
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
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
        referenced = {e["sha256"] for e in baseline["files"].values()} | _ledger_refs()
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


def _ledger_refs() -> set[str]:
    # Earlier versions the ledger points at stay, so history can be replayed.
    from .ledger import referenced

    return referenced()


def usage() -> dict:
    """Sizes for `agentdetox status`."""
    files = _load_baseline()["files"]
    referenced = {e["sha256"] for e in files.values()} | _ledger_refs()
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
