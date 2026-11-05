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
import stat
import sys
import tempfile
import threading
import time
import uuid
from dataclasses import dataclass
from pathlib import Path

from .agentscan import read_text, scan_text
from .compat import hook_executable, quote_executable, release, try_lock
from .context import ContextFile, is_hook_script
from .findings import Finding
from .persistence import RUNS_CODE, WHOLE_FILE, guarded_sections, is_claude_config, leaves

# Matches our hook command however the executable path was quoted
# ("/x/agentdetox" hook, '/a b/agentdetox' hook, "C:\x\agentdetox.EXE" hook, python -m agentdetox hook).
# The optional backslash: snapshots keep config sections JSON-encoded, where a Windows hook
# command's double quote around the executable becomes \".
_SELF_RE = re.compile(r"agentdetox(?:\.exe)?\\?['\"]?\s+hook\b", re.IGNORECASE)


def is_self_hook(text: str) -> bool:
    return bool(_SELF_RE.search(text))


_HOOK_AGENTS = ("claude-code", "codex", "cursor")
# The plugin from this repository's marketplace; a plugin of the same name from another
# marketplace is someone else's code.
OWN_PLUGIN = "agentdetox@agentdetox"


def is_own_hook(command: str) -> bool:
    """A hook command that is exactly how `install` runs this AgentDetox installation.
    A look-alike (`/tmp/x/agentdetox hook claude-code`) or our command with anything
    appended (`...; sh payload.sh`) does not count."""
    if not is_self_hook(command):
        return False
    try:
        exe = hook_executable(command)
        resolved = Path(exe).resolve()
    except (ValueError, IndexError, OSError):
        return False
    python = Path(sys.executable)
    agentdetox = python.with_name("agentdetox.exe" if os.name == "nt" else "agentdetox")
    which = shutil.which("agentdetox")
    if resolved in {agentdetox.resolve(), *([Path(which).resolve()] if which else [])}:
        exact = {f"{quote_executable(exe)} hook {agent}" for agent in _HOOK_AGENTS}
    elif resolved == python.resolve():
        exact = {f"{quote_executable(exe)} -I -m agentdetox hook {agent}" for agent in _HOOK_AGENTS}
    else:
        return False
    return command in exact


def _without_own(key: str, section: str) -> str:
    """A guarded section without AgentDetox's own hooks and plugin, so installing or
    upgrading AgentDetox is not reported as a new thing that runs."""
    name = key.rsplit(".", 1)[-1]
    data = json.loads(section)
    if name == "hooks" and isinstance(data, dict):
        for event, groups in list(data.items()):
            if not isinstance(groups, list):
                continue
            kept = []
            for g in groups:
                if isinstance(g, dict) and isinstance(g.get("hooks"), list):
                    hooks = [h for h in g["hooks"]
                             if not (isinstance(h, dict) and is_own_hook(str(h.get("command", ""))))]
                    if hooks:
                        kept.append({**g, "hooks": hooks})
                else:
                    kept.append(g)
            data[event] = kept
    elif name == "enabledPlugins" and isinstance(data, dict):
        data = {k: v for k, v in data.items() if k != OWN_PLUGIN}
    return json.dumps(data, sort_keys=True, ensure_ascii=False)


def _execution_section(path: Path | None, key: str, section: str) -> str:
    section = _without_own(key, section)
    if path is None or not is_claude_config(path):
        return section
    data = json.loads(section)
    if not isinstance(data, dict):
        return section
    name = key.rsplit(".", 1)[-1]
    if name == "mcpServers":
        runtime = {"type", "command", "args", "url", "env", "headers", "headersHelper", "oauth", "cwd"}
        data = {name: {k: v for k, v in server.items() if k in runtime}
                if isinstance(server, dict) else server for name, server in data.items()}
    elif name == "hooks":
        runtime = {"type", "if", "timeout", "once", "command", "args", "async", "asyncRewake", "shell", "onFailure",
                   "url", "headers", "allowedEnvVars", "server", "tool", "input", "prompt", "model"}
        projected = {}
        for event, groups in data.items():
            if not isinstance(groups, list):
                projected[event] = groups
                continue
            kept = []
            for group in groups:
                if not isinstance(group, dict):
                    kept.append(group)
                    continue
                value = {k: v for k, v in group.items() if k in runtime or k == "matcher"}
                if isinstance(group.get("hooks"), list):
                    value["hooks"] = [{k: v for k, v in handler.items() if k in runtime}
                                      if isinstance(handler, dict) else handler for handler in group["hooks"]]
                kept.append(value)
            projected[event] = kept
        data = projected
    return json.dumps(data, sort_keys=True)


def runs_code_added(key: str, before: str | None, after: str | None, path: Path | None = None) -> list[str]:
    """What a change to a guarded config section added that runs on this machine: a hook,
    helper command, MCP server, environment variable or plugin, other than AgentDetox's own."""
    name = key.rsplit(".", 1)[-1]
    if after is None or name not in RUNS_CODE:
        return []
    try:
        if name == "enableAllProjectMcpServers" and json.loads(after) is not True:
            return []
        old = leaves({key: _execution_section(path, key, before)}, ordered=True) if before else set()
        new = leaves({key: _execution_section(path, key, after)}, ordered=True)
    except ValueError:
        return []
    # Of a status line, only its command runs; padding and the like do not.
    return [f"{k}: {v}" for k, v in sorted(new - old)
            if name != "statusLine" or k.split("[")[0].endswith(".command") or k == key]


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


class StoreLocked(StoreError, TimeoutError):
    """Another process held the store lock too long. Holding it on purpose is a way to blind
    AgentDetox, so this is reported like a damaged store, not passed over."""


_LOCK = threading.RLock()
_lock_depth = 0


@contextlib.contextmanager
def store_lock(timeout: float | None = None):
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
            deadline = time.monotonic() + (LOCK_TIMEOUT if timeout is None else timeout)
            while not try_lock(fd):
                if time.monotonic() > deadline:
                    raise StoreLocked(f"{store_dir()} is locked by another process")
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


def snapshot(files: list[ContextFile], roots: list[Path], expected: dict[str, str | None] | None = None) -> int:
    """Record recovery checkpoints without forgetting deleted files. With `expected`, a file
    whose content is no longer the version that was checked is left out, not trusted unread."""
    with store_lock():
        return _snapshot(files, roots, expected)


def _snapshot(files: list[ContextFile], roots: list[Path], expected: dict[str, str | None] | None = None) -> int:
    baseline = _load_baseline()
    private_dir(store_dir())
    objects = private_dir(store_dir() / "objects")
    for cf in files:
        try:
            data = cf.path.read_bytes()
            mode = stat.S_IMODE(cf.path.stat().st_mode)
        except FileNotFoundError:
            if expected is None:
                raise
            continue                        # deleted since it was checked; the next check sees it
        digest = _sha(data)
        if expected is not None and expected.get(str(cf.path)) != digest:
            continue
        previous = baseline["files"].get(str(cf.path))
        # Most files are unchanged at every session: their copy is already stored. Its content
        # is verified in full by the daily cleanup, not on every session.
        obj = objects / digest
        if (previous and previous["sha256"] == digest and previous.get("mode") == mode and obj.exists()
                and obj.stat().st_size == len(data)):
            continue
        store_object(data)
        if previous and previous["sha256"] == digest and previous.get("mode") == mode:
            continue
        text = data.decode("utf-8", errors="replace")
        baseline["files"][str(cf.path)] = {
            "sha256": digest,
            "mode": mode,
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
    root_strs = [str(r) + os.sep for r in roots]
    known = {r for r in root_strs if any(p.startswith(r) for p in baseline)}

    for path, cf in current.items():
        entry = baseline.get(path)
        text = read_text(cf.path)
        if entry is None:
            changes.append(Change(path, "added", cf.kind))
            findings.extend(scan_text(path, path, text, cf.kind))
            # A config file that appeared where AgentDetox has looked before is checked like a
            # change; a project seen for the first time is its own, which the agent asks to trust.
            if cf.kind == "config" and max((r for r in root_strs if path.startswith(r)), key=len, default=None) in known:
                findings.extend(_config_changes(path, cf.path, text, {}))
            continue
        if _sha(cf.path.read_bytes()) == entry["sha256"]:
            continue
        if cf.kind == "config":
            # Agent configs churn constantly (counters, caches); only the
            # security-relevant sections count as a change.
            old_sections = _snapshot_sections(cf.path, entry)
            if guarded_sections(cf.path, text) == old_sections:
                continue
            changes.append(Change(path, "modified", cf.kind))
            findings.extend(_config_changes(path, cf.path, text, old_sections))
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

    for path, entry in baseline.items():
        if path not in current and any(path.startswith(r) for r in root_strs) and not Path(path).exists():
            changes.append(Change(path, "deleted", entry["kind"]))
            if entry["kind"] == "config" and any(is_self_hook(value) for value in entry.get("sections", {}).values()):
                findings.append(Finding(path, path, "self-protection", "high",
                                        "a config file that registered AgentDetox hooks was deleted"))
    return changes, findings


def _snapshot_sections(path: Path, entry: dict) -> dict:
    """The guarded sections of the snapshotted version, from its stored copy when there is
    one: sections saved by an older version miss keys guarded since, which would otherwise
    look newly added."""
    obj = store_dir() / "objects" / entry["sha256"]
    return guarded_sections(path, object_text(entry["sha256"])) if obj.exists() else entry.get("sections", {})


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
            runs = _runs_finding(doc_id, path, key, before, after)
            findings.append(runs or Finding(doc_id, str(path), "config-change", "medium",
                                            f"{key} {verb} since snapshot", (after or "")[:200]))
    return findings


_RUNS_LABEL = {"hooks": "hook", "statusLine": "status line command", "mcpServers": "MCP server",
               "mcp": "MCP server", "mcp_servers": "MCP server", "notify": "notify command",
               "env": "environment variable", "enabledPlugins": "plugin",
               "enableAllProjectMcpServers": "automatic approval of project MCP servers",
               "enabledMcpjsonServers": "approved project MCP server", "extraKnownMarketplaces": "plugin marketplace"}
# Variables that make the programs the agent runs load other code, or send their traffic
# elsewhere. Any other variable is worth recording but does not run anything.
_RISKY_ENV = re.compile(r"NODE_OPTIONS|BASH_ENV|ENV|ZDOTDIR|PATH|LD_\w+|DYLD_\w+|PYTHON(PATH|STARTUP|HOME)|"
                        r"PERL5?(OPT|LIB)|RUBY(OPT|LIB)|JAVA_TOOL_OPTIONS|_JAVA_OPTIONS|GIT_\w+|\w*_BASE_URL|"
                        r"\w*_PROXY|NODE_EXTRA_CA_CERTS|SSL_CERT_\w+|REQUESTS_CA_BUNDLE|CURL_CA_BUNDLE|"
                        r"NPM_CONFIG_\w+|PIP_\w+|UV_\w+|NODE_PATH|CLASSPATH", re.IGNORECASE)


def _runs_finding(doc_id: str, path: Path, key: str, before: str | None, after: str | None) -> Finding | None:
    """A finding naming what a guarded section now runs that it did not before (the MCP
    server, hook event, plugin or variable), or None when it runs nothing new."""
    name = key.rsplit(".", 1)[-1]
    if key == WHOLE_FILE and after is not None and is_hook_script(path):
        return Finding(doc_id, str(path), "config-change", "high",
                       f"hook script {'added' if before is None else 'changed'}: {path.name}")
    runs = runs_code_added(key, before, after, path)
    if not runs:
        return None
    old = json.loads(_execution_section(path, key, before)) if before else None
    new = json.loads(_execution_section(path, key, after or "null"))
    names: list[str] = []
    if isinstance(new, dict) and name != "statusLine":
        old = old if isinstance(old, dict) else {}
        names = [k for k, v in new.items() if v != old.get(k) and (name != "enabledPlugins" or v)]
        if name == "enabledPlugins" and not names:
            return None  # only disabled
    elif isinstance(new, list):
        names = [str(v) for v in new if v not in (old if isinstance(old, list) else [])]
    added = before is None or (isinstance(old, dict) and all(k not in old for k in names))
    severity = "medium" if name == "env" and not any(_RISKY_ENV.fullmatch(n) for n in names) else "high"
    label = _RUNS_LABEL.get(name, f"{name} helper command")
    message = f"{label} {'added' if added else 'changed'} ({name})" + (f": {', '.join(names)}" if names else "")
    evidence = "; ".join(r.removeprefix(key + ".").removeprefix(key) for r in runs)
    return Finding(doc_id, str(path), "config-change", severity, message[:200], evidence[:200])


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
        corrupt = []
        objects = store_dir() / "objects"
        for obj in objects.iterdir() if objects.is_dir() else []:
            if obj.name not in referenced:
                freed += obj.stat().st_size
                obj.unlink()
                removed += 1
            elif _sha(obj.read_bytes()) != obj.name:
                corrupt.append(obj.name)
        if corrupt:
            from . import events
            # Shown by doctor and status: a restore from these copies would fail.
            events.record("hook_error", stage="store-integrity",
                          error=f"{len(corrupt)} recovery copies are corrupt, e.g. {corrupt[0]}")
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
