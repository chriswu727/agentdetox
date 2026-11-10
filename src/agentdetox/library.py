"""Inspection of a folder of memory files the user names: inventory, scan, review.

A large existing library needs looking at, not only watching for changes. This module
walks one explicitly chosen folder, records every file it sees, and runs the per-file
rules on the candidate files. Nothing here says a file is clean: a file is inspected at
exact bytes by an exact detector, or it is visibly something else (queued, not inspected,
failed, stale, missing).

State lives in library.sqlite3, apart from state.sqlite3: every write there takes the store
lock hooks wait on, and a scan commits thousands of batches. A scan never takes that lock,
never copies file content into the store and never records a checkpoint.

A run is durable. Folders still to list and files still to verify are rows, so a killed
process loses at most the batch in hand, and relisting or rereading is idempotent. One
runner at a time holds library.lock. Whether a file changed is decided by reading and
hashing it on every run; modification times are never trusted.
"""

from __future__ import annotations

import contextlib
import functools
import hashlib
import json
import os
import re
import sqlite3
import subprocess
import sys
import time
from collections import Counter
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from pathlib import Path

from . import __version__, allowlist, cleanup, compat, safefs
from .agentscan import scan_text
from .context import home_dir, short_path
from .findings import SEVERITY_ORDER, finding_id, printable
from .hidden import normalize
from .integrity import StoreError, private_dir, store_dir, write_private

VERSION = 1
SUFFIXES = (".md", ".markdown", ".mdc", ".txt")
# What is read and how it is judged, besides the rules themselves. A change makes earlier
# conclusions stale and an unfinished run unresumable.
PROFILE = "memory-text-1:" + ",".join(SUFFIXES)
MAX_BYTES = cleanup.MAX_BYTES
MAX_FINDINGS = 50
MAX_DEPTH = 64
MAX_REL = 4096
BATCH_FILES = 200
BATCH_BYTES = 16_000_000
BATCH_SECONDS = 2.0
DIR_CHUNK = 500
GROUP_SECONDS = 0.5
EXT_KINDS = 20
CANCEL_POLL = 0.25
START_TIMEOUT = 15.0
# How long a scan waits for the runner lock: a status check holds it for an instant.
LOCK_PATIENCE = 1.0
STATES = ("suspicious", "low", "stale", "queued", "uninspected", "failed", "missing", "inspected")

_SCHEMA = (
    """CREATE TABLE roots (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL UNIQUE,
       dev TEXT NOT NULL, ino TEXT NOT NULL, created TEXT NOT NULL)""",
    """CREATE TABLE runs (id INTEGER PRIMARY KEY AUTOINCREMENT, root_id INTEGER NOT NULL REFERENCES roots(id),
       mode TEXT NOT NULL, state TEXT NOT NULL, phase TEXT NOT NULL, detector TEXT NOT NULL, profile TEXT NOT NULL,
       started TEXT NOT NULL, heartbeat TEXT NOT NULL, finished TEXT, cancel INTEGER NOT NULL DEFAULT 0,
       starts INTEGER NOT NULL DEFAULT 0, working INTEGER NOT NULL DEFAULT 0, pid INTEGER, error TEXT)""",
    "CREATE INDEX runs_root ON runs(root_id, id DESC)",
    """CREATE TABLE dirs (root_id INTEGER NOT NULL, rel TEXT NOT NULL, parent TEXT, state TEXT NOT NULL,
       todo INTEGER NOT NULL DEFAULT 0, seen_run INTEGER NOT NULL, listed_run INTEGER, error TEXT,
       excluded INTEGER NOT NULL DEFAULT 0, links INTEGER NOT NULL DEFAULT 0, special INTEGER NOT NULL DEFAULT 0,
       exts TEXT NOT NULL DEFAULT '{}', PRIMARY KEY(root_id, rel)) WITHOUT ROWID""",
    "CREATE INDEX dirs_todo ON dirs(root_id, todo, rel)",
    "CREATE INDEX dirs_parent ON dirs(root_id, parent)",
    """CREATE TABLE files (id INTEGER PRIMARY KEY AUTOINCREMENT, root_id INTEGER NOT NULL, rel TEXT NOT NULL,
       parent TEXT NOT NULL, state TEXT NOT NULL, reason TEXT, sha256 TEXT, size INTEGER, detector TEXT,
       todo INTEGER NOT NULL DEFAULT 0, seen_run INTEGER NOT NULL, verified_run INTEGER, inspected_run INTEGER,
       cleanup_run INTEGER,
       high INTEGER NOT NULL DEFAULT 0, medium INTEGER NOT NULL DEFAULT 0, low INTEGER NOT NULL DEFAULT 0,
       truncated INTEGER NOT NULL DEFAULT 0, UNIQUE(root_id, rel))""",
    "CREATE INDEX files_todo ON files(root_id, todo, id)",
    "CREATE INDEX files_parent ON files(root_id, parent)",
    "CREATE INDEX files_state ON files(root_id, state)",
    """CREATE TABLE findings (file_id INTEGER NOT NULL REFERENCES files(id), flag_id TEXT NOT NULL,
       sha256 TEXT NOT NULL, detector TEXT NOT NULL, rule TEXT NOT NULL, severity TEXT NOT NULL,
       message TEXT NOT NULL, evidence TEXT NOT NULL, lines TEXT NOT NULL DEFAULT '',
       PRIMARY KEY(file_id, flag_id)) WITHOUT ROWID""",
)

_REASONS = {
    "too-large": f"larger than {MAX_BYTES // 1000:,} kB", "not-utf8": "not UTF-8 text", "binary": "binary content",
    "symlink": "symbolic link, not followed", "not-regular": "not a regular file",
    "unreadable": "could not be read", "changed-during-read": "changed while being read",
    "vanished": "disappeared before it was read", "path-escape": "its folder became a link",
    "invalid-path": "has a path AgentDetox will not use",
}


class RootReplaced(StoreError):
    """The folder at a library's path is not the folder that was registered."""


def db_path() -> Path:
    return store_dir() / "library.sqlite3"


def marker_path() -> Path:
    """Left beside the inventory once it exists, so that a deleted or emptied inventory is
    reported as lost, not read as "nothing was ever scanned"."""
    return store_dir() / "library.inventory"


def _lost() -> StoreError:
    return StoreError(f"The library inventory {_shown(db_path())} is missing or empty although libraries were "
                      "scanned before, so findings may have been removed with it. Restore it from a backup; or, to "
                      f"start over knowing nothing of earlier inspections, delete {_shown(marker_path())} and scan again")


def _now() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S")


# Everything that decides what a library file's bytes are and what is said about them: the
# rules, and this module with the file access it reads through. Their source is the
# fingerprint, so a change to any of it, with or without a new release, is a new detector.
_SOURCES = ("agentscan.py", "findings.py", "hidden.py", "persistence.py", "library.py", "safefs.py")


@functools.cache
def detector_id() -> str:
    """Changes whenever a file could be judged differently: the release, the limits, or the
    source of the rules and of this implementation. Conclusions are bound to it. Only the
    text of the source counts (not its timestamps, nor how a checkout ends its lines), so
    reinstalling the same code keeps earlier conclusions."""
    digest = hashlib.sha256(f"{PROFILE}\0{__version__}\0{MAX_BYTES}\0{MAX_FINDINGS}".encode())
    for name in _SOURCES:
        source = (Path(__file__).parent / name).read_bytes().replace(b"\r\n", b"\n")
        digest.update(name.encode() + b"\0" + hashlib.sha256(source).digest())
    return digest.hexdigest()[:16]


@contextlib.contextmanager
def connect(*, write: bool = False) -> Iterator[sqlite3.Connection | None]:
    """The inventory database; None for a reader when there is none yet. Statements run in
    explicit transactions (see _tx), never under the store lock."""
    path = db_path()
    existed = marker_path().exists()
    if not path.exists():
        if existed:
            raise _lost()
        if not write:
            yield None
            return
        private_dir(store_dir())
        write_private(path, b"")
    try:
        db = (sqlite3.connect(path, timeout=30, isolation_level=None) if write else
              sqlite3.connect(path.as_uri() + "?mode=ro", uri=True, timeout=30, isolation_level=None))
    except sqlite3.Error as e:
        raise StoreError(f"The library inventory is unavailable: {e}") from e
    try:
        db.row_factory = sqlite3.Row
        version = db.execute("PRAGMA user_version").fetchone()[0]
        if version > VERSION:
            raise StoreError("The library inventory was written by a newer AgentDetox; upgrade before opening it")
        if version == 0:
            if existed:
                raise _lost()
            if not write:
                yield None
                return
            db.execute("BEGIN IMMEDIATE")
            if db.execute("PRAGMA user_version").fetchone()[0] == 0:
                for statement in _SCHEMA:
                    db.execute(statement)
                db.execute(f"PRAGMA user_version={VERSION}")
            db.execute("COMMIT")
        if write and not existed:
            write_private(marker_path(), b"1\n")
        yield db
    except sqlite3.Error as e:
        raise StoreError(f"The library inventory is unavailable or damaged: {e}") from e
    finally:
        db.close()


@contextlib.contextmanager
def _tx(db: sqlite3.Connection) -> Iterator[None]:
    db.execute("BEGIN IMMEDIATE")
    try:
        yield
    except BaseException:
        db.execute("ROLLBACK")
        raise
    db.execute("COMMIT")


@contextlib.contextmanager
def runner_lock(wait: float = 0.0) -> Iterator[bool]:
    """Held by the one process that may prepare or work on a run; False if another has it
    for longer than `wait` (a status check holds it for an instant to see whether a worker
    lives). The system drops it when its process dies, however it dies."""
    fd = os.open(private_dir(store_dir()) / "library.lock", os.O_RDWR | os.O_CREAT, 0o600)
    deadline = time.monotonic() + wait
    while not compat.try_lock(fd):
        if time.monotonic() >= deadline:
            os.close(fd)
            yield False
            return
        time.sleep(0.05)
    try:
        yield True
    finally:
        compat.release(fd)


def worker_alive() -> bool:
    with runner_lock() as held:
        return not held


def _parts(rel: str) -> list[str]:
    """The components of a relative path read from the inventory, refused unless every one
    is a plain name: a damaged or planted row must not name anything outside its root."""
    parts = rel.split("/")
    foreign = [sep for sep in (os.sep, os.altsep) if sep and sep != "/"] + ([":"] if os.name == "nt" else [])
    if (not rel or len(rel) > MAX_REL or len(parts) > MAX_DEPTH or os.path.isabs(rel)
            or any(p in ("", ".", "..") or "\0" in p or any(sep in p for sep in foreign) for p in parts)):
        raise ValueError(f"Invalid relative path in the library inventory: {rel[:80]!r}")
    return parts


def _shown(path: Path | str) -> str:
    """A path inside a message: a folder name can hold line breaks and terminal controls."""
    return printable(str(path))


def _identity(found: os.stat_result) -> tuple[str, str]:
    return str(found.st_dev), str(found.st_ino)


def _canonical(directory: Path | str) -> Path:
    return Path(os.path.realpath(os.path.abspath(Path(directory).expanduser())))


def _check_scope(root: Path) -> None:
    store = Path(os.path.realpath(store_dir()))
    if root == Path(root.anchor) or root == Path(os.path.realpath(home_dir())):
        raise ValueError(f"Choose the folder that holds the memory files, not {_shown(root)}: a library is one "
                         "explicit folder, never a whole disk or home folder")
    if root == store or store.is_relative_to(root) or root.is_relative_to(store):
        raise ValueError(f"{_shown(root)} overlaps AgentDetox's own store ({_shown(store)}); choose a folder "
                         "that does not")


class _Root:
    """An opened library root. Everything below it is reached through the open folder, one
    component at a time, with no link followed. Where the system cannot do that (Windows)
    each component is checked for links before and after use instead: best effort."""

    def __init__(self, row) -> None:
        self.id: int = row["id"]
        self.path = Path(row["path"])
        self._expected = (row["dev"], row["ino"])
        self.fd: int | None = None

    def open(self, *, rebind: bool = False) -> _Root:
        if safefs.PINNED:
            try:
                fd = safefs.open_path(self.path, system_links=False, listable=True)
            except safefs.UnsafePath as e:
                raise RootReplaced(f"{_shown(self.path)} is now reached through a symbolic link ({e}); "
                                   + self._hint()) from None
            if fd is None:
                raise StoreError(f"{_shown(self.path)} no longer exists")
            self.fd = fd
            found = _identity(os.fstat(fd))
        else:
            if os.path.normcase(os.path.realpath(self.path)) != os.path.normcase(str(self.path)) or not self.path.is_dir():
                raise RootReplaced(f"{_shown(self.path)} no longer is a real folder at this path; " + self._hint())
            found = _identity(os.stat(self.path))
        if rebind:
            self._expected = found
        elif found != self._expected:
            self.close()
            raise RootReplaced(f"The folder at {_shown(self.path)} is not the one that was registered: it was "
                               "replaced or recreated. " + self._hint())
        return self

    def _hint(self) -> str:
        return ("Earlier conclusions do not apply to it. To inspect what is there now, discarding them, run "
                f"`agentdetox library scan {f'L{self.id}' if self.id else _shown(self.path)} --restart`")

    @property
    def identity(self) -> tuple[str, str]:
        return self._expected

    def close(self) -> None:
        if self.fd is not None:
            os.close(self.fd)
            self.fd = None

    def _checked(self, parts: list[str]) -> Path:
        path = self.path
        for name in parts:
            path = path / name
            if safefs.is_link(path):
                raise safefs.UnsafePath(f"{_shown(path)} is a symbolic link or junction")
        return path

    def folder(self, parts: list[str]) -> int | Path:
        if self.fd is not None:
            return safefs.open_beneath(self.fd, parts, listable=True)
        return self._checked(parts)

    def verify(self) -> None:
        """Refuse once the path no longer names the folder that was opened: what is read
        through the open folder is then not what the user sees at that path."""
        if self.fd is None:
            self.close()
            self.open()
            return
        try:
            now = safefs.open_path(self.path, system_links=False)
        except (OSError, StoreError):
            now = None
        try:
            if now is None or not os.path.samestat(os.fstat(now), os.fstat(self.fd)):
                raise RootReplaced(f"The folder at {_shown(self.path)} was moved or replaced while AgentDetox worked in it. "
                                   + self._hint())
        finally:
            if now is not None:
                os.close(now)

    @contextlib.contextmanager
    def file(self, parts: list[str]) -> Iterator[tuple[int, Callable[[], os.stat_result]]]:
        """An open regular file below the root, and a function that looks its name up again."""
        if self.fd is not None:
            folder = safefs.open_beneath(self.fd, parts[:-1])
            try:
                fd = safefs.open_regular(parts[-1], folder)
                try:
                    yield fd, lambda: os.stat(parts[-1], dir_fd=folder, follow_symlinks=False)
                finally:
                    os.close(fd)
            finally:
                os.close(folder)
        else:
            path = self._checked(parts[:-1]) / parts[-1]
            fd = safefs.open_regular(path)
            try:
                yield fd, lambda: os.lstat(self._checked(parts))
            finally:
                os.close(fd)

    def pin(self, parts: list[str]):
        """A pin on a file below the root that never reads more than a scan would."""
        if self.fd is not None:
            return safefs.pinned_beneath(self.fd, self.path, parts, MAX_BYTES)
        self._checked(parts[:-1])
        return safefs.pinned(self.path.joinpath(*parts), MAX_BYTES)


def _root_row(db: sqlite3.Connection, target: Path | str):
    text = str(target)
    if re.fullmatch(r"[Ll][1-9][0-9]*", text):
        return db.execute("SELECT * FROM roots WHERE id=?", (int(text[1:]),)).fetchone()
    return db.execute("SELECT * FROM roots WHERE path=?", (str(_canonical(target)),)).fetchone()


def _known_root(db: sqlite3.Connection | None, target: Path | str):
    row = _root_row(db, target) if db is not None else None
    if row is None:
        raise ValueError(f"{_shown(target)} is not a library AgentDetox has scanned; start with "
                         "`agentdetox library scan <folder>`")
    return row


def _latest_run(db: sqlite3.Connection, root_id: int):
    return db.execute("SELECT * FROM runs WHERE root_id=? ORDER BY id DESC LIMIT 1", (root_id,)).fetchone()


# Preparing and running ----------------------------------------------------------------

def prepare(target: Path | str, *, full: bool = False, restart: bool = False) -> dict:
    """Save the run a scan of `target` will work on, before any work: the unfinished run
    when there is one (its mode and detector are part of it and are not changed), else a
    new one. With `restart`, an unfinished run is abandoned and nothing it verified counts
    for the new run. The caller holds the runner lock."""
    with connect(write=True) as db:
        assert db is not None
        with _tx(db):
            row = _root_row(db, target)
            if row is None:
                if re.fullmatch(r"[Ll][1-9][0-9]*", str(target)):
                    raise ValueError(f"Unknown library {target}")
                path = _canonical(target)
                if not path.is_dir():
                    raise ValueError(f"{_shown(path)} is not a folder")
                _check_scope(path)
                handle = _Root({"id": 0, "path": str(path), "dev": "", "ino": ""}).open(rebind=True)
                handle.close()
                db.execute("INSERT INTO roots(path, dev, ino, created) VALUES (?, ?, ?, ?)",
                           (str(path), *handle.identity, _now()))
                row = _root_row(db, path)
            _check_scope(Path(row["path"]))
            root_id = row["id"]
            try:
                _Root(row).open().close()
            except RootReplaced:
                if not restart:
                    raise
                handle = _Root(row).open(rebind=True)
                handle.close()
                db.execute("DELETE FROM findings WHERE file_id IN (SELECT id FROM files WHERE root_id=?)", (root_id,))
                db.execute("DELETE FROM files WHERE root_id=?", (root_id,))
                db.execute("DELETE FROM dirs WHERE root_id=?", (root_id,))
                db.execute("UPDATE roots SET dev=?, ino=? WHERE id=?", (*handle.identity, root_id))
            unfinished = db.execute("SELECT * FROM runs WHERE root_id=? AND state IN ('active', 'cancelled') "
                                    "ORDER BY id DESC LIMIT 1", (root_id,)).fetchone()
            if unfinished is not None and not restart:
                again = f"`agentdetox library scan L{root_id} --restart`"
                if full and unfinished["mode"] != "full":
                    raise ValueError(f"Run {unfinished['id']} of this library is an unfinished incremental scan. "
                                     "Continue it without --full, or discard it and start a full one with " + again)
                if unfinished["detector"] != detector_id() or unfinished["profile"] != PROFILE:
                    raise ValueError(f"Run {unfinished['id']} of this library was started by a different detector "
                                     "version and cannot be continued by this one. Start over with " + again)
                db.execute("UPDATE runs SET state='active', cancel=0, pid=NULL, error=NULL, heartbeat=? WHERE id=?",
                           (_now(), unfinished["id"]))
                return {"run": unfinished["id"], "root": f"L{root_id}", "path": row["path"],
                        "mode": unfinished["mode"], "resumed": True, "phase": unfinished["phase"]}
            if unfinished is not None:
                db.execute("UPDATE runs SET state='abandoned', finished=? WHERE id=?", (_now(), unfinished["id"]))
            # What an earlier completed run reported missing has been shown; it is dropped now.
            db.execute("DELETE FROM findings WHERE file_id IN (SELECT id FROM files WHERE root_id=? "
                       "AND state='missing')", (root_id,))
            db.execute("DELETE FROM files WHERE root_id=? AND state='missing'", (root_id,))
            db.execute("DELETE FROM dirs WHERE root_id=? AND state='missing'", (root_id,))
            mode = "full" if full else "incremental"
            run = db.execute("INSERT INTO runs(root_id, mode, state, phase, detector, profile, started, heartbeat) "
                             "VALUES (?, ?, 'active', 'enumerate', ?, ?, ?, ?)",
                             (root_id, mode, detector_id(), PROFILE, _now(), _now())).lastrowid
            db.execute("UPDATE dirs SET todo=0 WHERE root_id=?", (root_id,))
            db.execute("UPDATE files SET todo=0 WHERE root_id=?", (root_id,))
            db.execute("INSERT INTO dirs(root_id, rel, parent, state, todo, seen_run) VALUES (?, '', NULL, 'pending', 1, ?) "
                       "ON CONFLICT(root_id, rel) DO UPDATE SET todo=1, seen_run=excluded.seen_run", (root_id, run))
            return {"run": run, "root": f"L{root_id}", "path": row["path"], "mode": mode, "resumed": False,
                    "phase": "enumerate"}


@dataclass
class _Result:
    id: int
    action: str                      # "verified", "inspected", "state" (content known gone), "failed"
    state: str = "inspected"
    reason: str | None = None
    sha256: str | None = None
    size: int = 0
    findings: list[tuple] = field(default_factory=list)
    counts: tuple[int, int, int] = (0, 0, 0)
    truncated: int = 0
    seen: str | None = None          # the version recorded when this file was picked up


def _read(fd: int, limit: int) -> bytes:
    chunks = []
    left = limit
    while left > 0:
        chunk = os.read(fd, min(left, 1 << 20))
        if not chunk:
            break
        chunks.append(chunk)
        left -= len(chunk)
    return b"".join(chunks)


def _capture(root: _Root, parts: list[str]) -> tuple[str, str | None, bytes | None]:
    """(state, reason, bytes): the bytes one read captured, or why there are none. Size is
    checked before reading; after it, the open file's size and times, and that its name
    still is this file. A file rewritten in place, or replaced by another (how editors
    save), is then not passed off as the version at that path."""
    try:
        with root.file(parts) as (fd, lookup):
            before = os.fstat(fd)
            if before.st_size > MAX_BYTES:
                return "uninspected", "too-large", None
            data = _read(fd, MAX_BYTES + 1)
            after = os.fstat(fd)
            same = all(getattr(before, key) == getattr(after, key)
                       for key in ("st_size", "st_mtime_ns", "st_ctime_ns", "st_ino", "st_dev"))
            try:
                same = same and os.path.samestat(lookup(), after)
            except OSError:
                same = False
            if not same or len(data) != after.st_size:
                return "failed", "changed-during-read", None
            return "inspected", None, data
    except FileNotFoundError:
        return "failed", "vanished", None
    except safefs.UnsafePath as e:
        if e.kind in ("symlink", "not-regular"):
            return "uninspected", e.kind, None
        return "failed", "path-escape", None
    except OSError:
        return "failed", "unreadable", None


def _comparable(line: str) -> str:
    return " ".join(normalize(line).split())


def _line_hint(lines: list[str], anchor: str) -> str:
    """Where the flagged text is in the inspected version, as line numbers a cleanup takes.
    A hint for the reader: a cleanup removes the lines chosen, whatever this says."""
    wanted = [text for text in map(_comparable, anchor.split("\n")) if text]
    if not wanted:
        return ""
    spans = [i for i in range(len(lines) - len(wanted) + 1) if lines[i:i + len(wanted)] == wanted]
    if not spans and len(wanted) == 1:
        spans = [i for i, line in enumerate(lines) if wanted[0] in line]
    shown = [str(i + 1) if len(wanted) == 1 else f"{i + 1}-{i + len(wanted)}" for i in spans[:3]]
    return ", ".join(shown) + (f" (+{len(spans) - 3} more)" if len(spans) > 3 else "")


def judge(label: str, data: bytes) -> _Result:
    """What the rules say about `data`, read as memory text."""
    digest = hashlib.sha256(data).hexdigest()
    if b"\0" in data:
        return _Result(0, "state", "uninspected", "binary", digest, len(data))
    try:
        text = data.decode("utf-8")
    except UnicodeDecodeError:
        return _Result(0, "state", "uninspected", "not-utf8", digest, len(data))
    found: dict[str, tuple] = {}
    lines: list[str] | None = None
    for f in scan_text(label, label, text.replace("\r\n", "\n").replace("\r", "\n"), "memory"):
        flag = finding_id(f)
        if flag in found and SEVERITY_ORDER[found[flag][2]] >= SEVERITY_ORDER[f.severity]:
            continue
        found[flag] = (flag, f.detector, f.severity, f.message[:200], " ".join(f.evidence.split())[:200], f.anchor)
    ordered = sorted(found.values(), key=lambda row: (-SEVERITY_ORDER[row[2]], row[0]))
    counts = Counter(row[2] for row in ordered)
    kept = []
    for flag, rule, severity, message, evidence, anchor in ordered[:MAX_FINDINGS]:
        if lines is None:
            # Numbered as cleanup numbers them: split on LF only.
            lines = [_comparable(line) for line in text.split("\n")]
        kept.append((flag, rule, severity, message, evidence, _line_hint(lines, anchor or evidence)))
    return _Result(0, "inspected", "inspected", None, digest, len(data), kept,
                   (counts["high"], counts["medium"], counts["low"]), len(ordered) - len(kept))


def _errname(error: OSError) -> str:
    import errno

    return errno.errorcode.get(error.errno or 0, type(error).__name__)


class _Runner:
    def __init__(self, db: sqlite3.Connection, root: _Root, run, progress, stop) -> None:
        self.db, self.root, self.run = db, root, run["id"]
        self.full = run["mode"] == "full"
        self.detector = run["detector"]
        self.progress = progress or (lambda **_: None)
        self.stop = stop or (lambda: False)
        self._checked = 0.0
        self._cancel = False
        self._saved = 0
        try:
            self._store: tuple[str, str] | None = _identity(os.stat(store_dir()))
        except OSError:
            self._store = None

    def stopping(self) -> bool:
        if self.stop():
            return True
        now = time.monotonic()
        if now - self._checked >= CANCEL_POLL:
            self._checked = now
            self._cancel = bool(self.db.execute("SELECT cancel FROM runs WHERE id=?", (self.run,)).fetchone()[0])
        return self._cancel

    # Listing folders: the frontier is the dirs rows with todo=1.

    def enumerate(self) -> bool:
        """Small folders share a transaction (a commit per folder would cost a disk flush
        each); a folder is still marked listed in the transaction that saves its last entry."""
        db, root = self.db, self.root.id
        listed = 0
        while True:
            if self.stopping():
                return False
            db.execute("BEGIN IMMEDIATE")
            try:
                self._saved, started, row = 0, time.monotonic(), None
                while self._saved < DIR_CHUNK and time.monotonic() - started < GROUP_SECONDS:
                    row = db.execute("SELECT rel FROM dirs WHERE root_id=? AND todo=1 ORDER BY rel LIMIT 1",
                                     (root,)).fetchone()
                    if row is None:
                        break
                    if not self._list(row["rel"]):
                        db.execute("COMMIT")
                        return False
                    listed += 1
                self.root.verify()
                db.execute("UPDATE runs SET heartbeat=? WHERE id=?", (_now(), self.run))
            except BaseException:
                if db.in_transaction:
                    db.execute("ROLLBACK")
                raise
            db.execute("COMMIT")
            self.progress(phase="enumerate", folders=listed)
            if row is None:
                return True

    def _folder_state(self, rel: str, state: str, error: str | None) -> None:
        self._saved += 1
        self.db.execute("UPDATE dirs SET state=?, todo=0, error=? WHERE root_id=? AND rel=?",
                        (state, error, self.root.id, rel))

    def _list(self, rel: str) -> bool:
        """List one folder inside the open transaction. Every DIR_CHUNK entries, whatever
        they are, what was found is committed and a request to stop is heeded. The folder
        counts as listed, and its counters are saved, only with its last entry, so a listing
        cut short is done again from the start and nothing is counted twice. False when
        told to stop part-way."""
        try:
            parts = _parts(rel) if rel else []
            handle = self.root.folder(parts)
        except ValueError:
            self._folder_state(rel, "failed", "invalid-path")
            return True
        except safefs.UnsafePath:
            self._folder_state(rel, "symlink", None)
            return True
        except OSError as e:
            self._folder_state(rel, "failed", _errname(e))
            return True
        counts: Counter = Counter()
        exts: Counter = Counter()
        pending: list[tuple[str, str]] = []
        try:
            with os.scandir(handle) as entries:
                for seen, entry in enumerate(entries, 1):
                    op = self._entry(rel, len(parts), entry, counts, exts)
                    if op is not None:
                        pending.append(op)
                    if seen % DIR_CHUNK == 0:
                        self._save(rel, pending)
                        pending = []
                        self.db.execute("COMMIT")
                        self.db.execute("BEGIN IMMEDIATE")
                        if self.stopping():
                            return False
        except OSError as e:
            self._folder_state(rel, "failed", _errname(e))
            return True
        finally:
            if isinstance(handle, int):
                os.close(handle)
        self._save(rel, pending)
        self._saved += 1
        self.db.execute("UPDATE dirs SET state='listed', todo=0, listed_run=?, error=NULL, excluded=?, links=?, "
                        "special=?, exts=? WHERE root_id=? AND rel=?",
                        (self.run, counts["excluded"], counts["links"], counts["special"],
                         json.dumps(exts, ensure_ascii=False), self.root.id, rel))
        return True

    def _entry(self, rel: str, depth: int, entry: os.DirEntry, counts: Counter, exts: Counter) -> tuple[str, str] | None:
        def excluded(kind: str) -> None:
            # A fixed number of kinds per folder, whatever the folder holds.
            counts["excluded"] += 1
            exts[kind[:32] if kind in exts or len(exts) < EXT_KINDS else "(other)"] += 1

        name = entry.name
        child = f"{rel}/{name}" if rel else name
        try:
            name.encode("utf-8")
            _parts(child)
        except (UnicodeEncodeError, ValueError):
            counts["special"] += 1
            return None
        try:
            if entry.is_symlink() or getattr(entry, "is_junction", lambda: False)():
                counts["links"] += 1
                return "link", child
            if entry.is_dir(follow_symlinks=False):
                if self._store is not None and _identity(entry.stat(follow_symlinks=False)) == self._store:
                    excluded("(agentdetox store)")
                    return None
                return ("deep" if depth + 2 > MAX_DEPTH else "dir"), child
            if entry.is_file(follow_symlinks=False):
                suffix = os.path.splitext(name)[1].lower()
                if suffix in SUFFIXES:
                    return "file", child
                excluded(suffix[:32] or "(none)")
                return None
        except OSError:
            pass
        counts["special"] += 1
        return None

    def _save(self, parent: str, ops: list[tuple[str, str]]) -> None:
        db, root, run = self.db, self.root.id, self.run
        self._saved += len(ops)
        for kind, rel in ops:
            if kind == "file":
                db.execute("INSERT INTO files(root_id, rel, parent, state, todo, seen_run) VALUES (?, ?, ?, 'new', 1, ?) "
                           "ON CONFLICT(root_id, rel) DO UPDATE SET todo=1, seen_run=excluded.seen_run, "
                           "state=CASE WHEN files.state='missing' THEN 'new' ELSE files.state END",
                           (root, rel, parent, run))
            elif kind == "dir":
                db.execute("INSERT INTO dirs(root_id, rel, parent, state, todo, seen_run) VALUES (?, ?, ?, 'pending', 1, ?) "
                           "ON CONFLICT(root_id, rel) DO UPDATE SET seen_run=excluded.seen_run, "
                           "todo=CASE WHEN dirs.listed_run=excluded.seen_run THEN dirs.todo ELSE 1 END",
                           (root, rel, parent, run))
            elif kind == "deep":
                db.execute("INSERT INTO dirs(root_id, rel, parent, state, todo, seen_run, error) "
                           "VALUES (?, ?, ?, 'failed', 0, ?, 'too-deep') ON CONFLICT(root_id, rel) DO UPDATE SET "
                           "state='failed', todo=0, seen_run=excluded.seen_run, error='too-deep'", (root, rel, parent, run))
            else:
                # A link where a file or folder was inspected before: say so, not "missing".
                db.execute("UPDATE files SET state='uninspected', reason='symlink', todo=0, seen_run=?, verified_run=?, "
                           "sha256=NULL, detector=NULL, inspected_run=NULL, cleanup_run=NULL, high=0, medium=0, low=0, "
                           "truncated=0 WHERE root_id=? AND rel=?",
                           (run, run, root, rel))
                db.execute("DELETE FROM findings WHERE file_id IN (SELECT id FROM files WHERE root_id=? AND rel=?)",
                           (root, rel))
                db.execute("UPDATE dirs SET state='symlink', todo=0, seen_run=?, error=NULL WHERE root_id=? AND rel=?",
                           (run, root, rel))

    # Verifying files: the queue is the files rows with todo=1.

    def inspect(self) -> bool:
        db, root = self.db, self.root.id
        total = db.execute("SELECT count(*) FROM files WHERE root_id=? AND todo=1", (root,)).fetchone()[0]
        done = cursor = 0
        while True:
            rows = db.execute("SELECT id, rel, state, sha256, detector FROM files WHERE root_id=? AND todo=1 AND id>? "
                              "ORDER BY id LIMIT ?", (root, cursor, BATCH_FILES)).fetchall()
            if not rows:
                return True
            results: list[_Result] = []
            size, started, stopped = 0, time.monotonic(), False
            for row in rows:
                if self.stopping():
                    stopped = True
                    break
                result = self._examine(row)
                results.append(result)
                cursor = row["id"]
                size += result.size
                if size >= BATCH_BYTES or time.monotonic() - started >= BATCH_SECONDS:
                    break
            # Nothing read through a root that is no longer at its path is recorded.
            self.root.verify()
            self._commit(results)
            done += len(results)
            self.progress(phase="inspect", done=done, total=total)
            if stopped:
                return False

    def _examine(self, row) -> _Result:
        result = self._judged(row)
        result.id, result.seen = row["id"], row["sha256"]
        return result

    def _judged(self, row) -> _Result:
        try:
            parts = _parts(row["rel"])
        except ValueError:
            return _Result(0, "failed", "failed", "invalid-path")
        state, reason, data = _capture(self.root, parts)
        if data is None:
            return _Result(0, "failed" if state == "failed" else "state", state, reason)
        digest = hashlib.sha256(data).hexdigest()
        if (not self.full and row["state"] == "inspected" and row["sha256"] == digest
                and row["detector"] == self.detector):
            return _Result(0, "verified", sha256=digest, size=len(data))
        return judge(str(self.root.path.joinpath(*parts)), data)

    def _commit(self, results: list[_Result]) -> None:
        """Record a batch. A row is written only if it still waits and still holds the
        version seen when it was picked up: a cleanup that finished meanwhile recorded newer
        bytes, and what this batch read before it is out of date."""
        db, run = self.db, self.run
        with _tx(db):
            for r in results:
                if r.action == "verified":
                    db.execute("UPDATE files SET todo=0, verified_run=? WHERE id=? AND todo=1 AND sha256 IS ?",
                               (run, r.id, r.seen))
                    continue
                if r.action == "failed":
                    # Not read: the last inspected version and its findings stay for review.
                    db.execute("UPDATE files SET state='failed', reason=?, todo=0, verified_run=? WHERE id=? AND todo=1 "
                               "AND sha256 IS ?", (r.reason, run, r.id, r.seen))
                    continue
                inspected = r.action == "inspected"
                changed = db.execute(
                    "UPDATE files SET state=?, reason=?, sha256=?, size=?, detector=?, todo=0, verified_run=?, "
                    "inspected_run=?, cleanup_run=NULL, high=?, medium=?, low=?, truncated=? "
                    "WHERE id=? AND todo=1 AND sha256 IS ?",
                    (r.state, r.reason, r.sha256, r.size or None, self.detector if inspected else None, run,
                     run if inspected else None, *r.counts, r.truncated, r.id, r.seen)).rowcount
                if changed:
                    _replace_findings(db, r, self.detector)
            db.execute("UPDATE runs SET heartbeat=? WHERE id=?", (_now(), run))

    # What a completed listing proves is gone.

    def reconcile(self) -> bool:
        """Only a folder listed to its end in this run proves an entry absent. Files below a
        folder that could not be listed, or became a link, keep their rows and their age.
        Vanished folders are handled a batch per transaction and a request to stop is heeded
        between them; what is already marked stays marked, and the rest is done on resuming."""
        db, root, run = self.db, self.root.id, self.run
        if self.stopping():
            return False
        self.root.verify()
        while True:
            with _tx(db):
                gone = db.execute(
                    "SELECT d.rel FROM dirs d JOIN dirs p ON p.root_id=d.root_id AND p.rel=d.parent WHERE d.root_id=? "
                    "AND d.seen_run<? AND d.state!='missing' AND p.listed_run=? LIMIT ?", (root, run, run, BATCH_FILES)).fetchall()
                stopped = False
                for row in gone:
                    low, high = row["rel"] + "/", row["rel"] + "0"   # "0" follows "/": every path below
                    db.execute("UPDATE dirs SET state='missing', todo=0, excluded=0, links=0, special=0, exts='{}' "
                               "WHERE root_id=? AND (rel=? OR (rel>=? AND rel<?))", (root, row["rel"], low, high))
                    db.execute("UPDATE files SET state='missing', reason=NULL, todo=0, verified_run=? "
                               "WHERE root_id=? AND rel>=? AND rel<? AND state!='missing'", (run, root, low, high))
                    if self.stopping():
                        stopped = True
                        break
            if stopped:
                return False
            if not gone:
                break
        with _tx(db):
            db.execute(
                "UPDATE files SET state='missing', reason=NULL, todo=0, verified_run=? WHERE root_id=? AND seen_run<? "
                "AND state!='missing' AND EXISTS (SELECT 1 FROM dirs p WHERE p.root_id=files.root_id "
                "AND p.rel=files.parent AND p.listed_run=?)", (run, root, run, run))
            db.execute("DELETE FROM findings WHERE file_id IN (SELECT id FROM files WHERE root_id=? AND state='missing')",
                       (root,))
        return True


def _replace_findings(db: sqlite3.Connection, result: _Result, detector: str) -> None:
    db.execute("DELETE FROM findings WHERE file_id=?", (result.id,))
    db.executemany("INSERT INTO findings(file_id, flag_id, sha256, detector, rule, severity, message, evidence, lines) "
                   "VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)",
                   [(result.id, flag, result.sha256, detector, rule, severity, message, evidence, lines)
                    for flag, rule, severity, message, evidence, lines in result.findings])


def run(run_id: int, *, progress: Callable | None = None, stop: Callable[[], bool] | None = None) -> str:
    """Work on a prepared run until it completes or is told to stop; returns its state.
    The caller holds the runner lock."""
    with connect(write=True) as db:
        assert db is not None
        row = db.execute("SELECT * FROM runs WHERE id=?", (run_id,)).fetchone()
        if row is None:
            raise ValueError(f"Unknown library run {run_id}")
        if row["state"] != "active":
            raise StoreError(f"Library run {run_id} is {row['state']}; start it with `agentdetox library scan`")
        if row["detector"] != detector_id() or row["profile"] != PROFILE:
            raise StoreError(f"Library run {run_id} belongs to a different detector version; scan with --restart")
        with _tx(db):
            # The lock holder works on exactly one run; any other run marked so was left by a dead worker.
            db.execute("UPDATE runs SET working=0 WHERE working=1")
            taken = db.execute("UPDATE runs SET working=1, pid=?, starts=starts+1, heartbeat=?, error=NULL "
                               "WHERE id=? AND state='active'", (os.getpid(), _now(), run_id)).rowcount
        if not taken:
            raise StoreError(f"Library run {run_id} was stopped before this worker could take it")
        root = _Root(db.execute("SELECT * FROM roots WHERE id=?", (row["root_id"],)).fetchone())
        try:
            root.open()
            runner = _Runner(db, root, row, progress, stop)
            phase = row["phase"]
            # Looked up when called: each step is a method of the runner.
            for name, following in (("enumerate", "inspect"), ("inspect", "reconcile"), ("reconcile", "done")):
                if phase != name:
                    continue
                if not getattr(runner, name)():
                    with _tx(db):
                        db.execute("UPDATE runs SET state='cancelled', working=0, heartbeat=? WHERE id=?",
                                   (_now(), run_id))
                    return "cancelled"
                phase = following
                with _tx(db):
                    db.execute("UPDATE runs SET phase=?, heartbeat=? WHERE id=?", (phase, _now(), run_id))
            with _tx(db):
                db.execute("UPDATE runs SET state='completed', working=0, finished=?, heartbeat=? WHERE id=?",
                           (_now(), _now(), run_id))
            return "completed"
        except (OSError, StoreError, sqlite3.Error) as e:
            with contextlib.suppress(sqlite3.Error):
                if db.in_transaction:
                    db.execute("ROLLBACK")
                with _tx(db):
                    db.execute("UPDATE runs SET error=?, working=0 WHERE id=?",
                               (f"{type(e).__name__}: {e}"[:300], run_id))
            raise
        finally:
            root.close()


def cancel(target: Path | str, wait: float = 15.0) -> str:
    """Ask the worker of the unfinished run to stop after the file in hand, and wait for it."""
    with connect() as reader:
        root = _known_root(reader, target)
    with connect(write=True) as db:
        assert db is not None
        latest = _latest_run(db, root["id"])
        if latest is None or latest["state"] != "active":
            return f"No scan of {short_path(root['path'])} is in progress."
        with _tx(db):
            db.execute("UPDATE runs SET cancel=1 WHERE id=? AND state='active'", (latest["id"],))
            # A run no worker is on stops here; a worker takes a run only while it is active.
            db.execute("UPDATE runs SET state='cancelled' WHERE id=? AND state='active' AND working=0", (latest["id"],))
        done = (f"Run {latest['id']} of {short_path(root['path'])} is cancelled; what it verified is kept. "
                f"Continue it with `agentdetox library scan L{root['id']}`.")
        deadline = time.monotonic() + wait
        while True:
            if db.execute("SELECT state FROM runs WHERE id=?", (latest["id"],)).fetchone()[0] != "active":
                return done
            with runner_lock() as held:
                if held:
                    # No worker is left to see the request: the run stops here.
                    with _tx(db):
                        db.execute("UPDATE runs SET state='cancelled', working=0 WHERE id=? AND state='active'",
                                   (latest["id"],))
                    return done
            if time.monotonic() > deadline:
                return (f"Cancellation of run {latest['id']} was requested; its worker (pid {latest['pid']}) is "
                        "still finishing. Check `agentdetox library status`.")
            time.sleep(0.2)


def start_background(run_id: int, timeout: float = START_TIMEOUT) -> tuple[bool, str]:
    """Start a detached worker for a prepared run and wait until it has taken the run.
    (False, why) when it did not: the run stays saved and can be continued."""
    store = private_dir(store_dir())
    log = store / "library.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if log.exists() and log.stat().st_size > 1_000_000:
        flags |= os.O_TRUNC
    with connect() as db:
        before = db.execute("SELECT starts FROM runs WHERE id=?", (run_id,)).fetchone()[0] if db else 0
    fd = os.open(log, flags, 0o600)
    offset = os.fstat(fd).st_size
    if compat.WINDOWS:
        detach: dict = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                        | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    else:
        detach = {"start_new_session": True}
    try:
        # -I keeps the current directory and PYTHON* variables out of the import path.
        process = subprocess.Popen([sys.executable, "-I", "-m", "agentdetox", "library", "_worker", str(run_id)],
                                   stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=fd, cwd=store, **detach)
    finally:
        os.close(fd)
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with connect() as db:
            row = db.execute("SELECT starts, state FROM runs WHERE id=?", (run_id,)).fetchone() if db else None
        if row is not None and row["starts"] > before:
            return True, f"pid {process.pid}"
        code = process.poll()
        if code is not None:
            with log.open("rb") as file:
                file.seek(offset)
                said = file.read(65536)[-1500:].decode("utf-8", errors="replace").strip()
            return False, (f"The background worker exited with status {code} before starting"
                           + (f": {printable(' | '.join(said.splitlines()[-4:]))}" if said else "")
                           + f" (log: {_shown(log)})")
        time.sleep(0.05)
    return False, (f"The background worker (pid {process.pid}) did not report within {timeout:.0f} s "
                   f"(log: {_shown(log)})")


# Reading the inventory ----------------------------------------------------------------

def _allowed(db: sqlite3.Connection) -> None:
    db.execute("CREATE TEMP TABLE IF NOT EXISTS allowed (id TEXT PRIMARY KEY)")
    db.execute("DELETE FROM temp.allowed")
    db.executemany("INSERT OR IGNORE INTO temp.allowed VALUES (?)", [(i,) for i in allowlist.entries()])


# One row per inspected file that has findings: its worst open severity, and how many of
# its findings the allowlist hides.
_PER_FILE = """per AS (SELECT f.id, f.truncated,
    max(CASE WHEN a.id IS NULL AND n.severity='high' THEN 1 ELSE 0 END) AS h,
    max(CASE WHEN a.id IS NULL AND n.severity='medium' THEN 1 ELSE 0 END) AS m,
    max(CASE WHEN a.id IS NULL AND n.severity='low' THEN 1 ELSE 0 END) AS l,
    sum(CASE WHEN a.id IS NOT NULL THEN 1 ELSE 0 END) AS hidden
    FROM files f JOIN findings n ON n.file_id=f.id LEFT JOIN temp.allowed a ON a.id=n.flag_id
    WHERE f.root_id=:root AND f.state='inspected' GROUP BY f.id)"""
_SUSPICIOUS = "(per.h OR per.m OR per.truncated>0)"


def _root_status(db: sqlite3.Connection, root, alive: bool) -> dict:
    root_id = root["id"]
    latest = _latest_run(db, root_id)
    args = {"root": root_id, "detector": detector_id(), "run": latest["id"] if latest else None}
    states: Counter = Counter()
    reasons: dict[str, Counter] = {"uninspected": Counter(), "failed": Counter()}
    for row in db.execute("SELECT state, reason, count(*) AS n FROM files WHERE root_id=? GROUP BY state, reason",
                          (root_id,)):
        states[row["state"]] += row["n"]
        if row["state"] in reasons:
            reasons[row["state"]][row["reason"] or "unknown"] += row["n"]
    stale = db.execute("SELECT count(*) FROM files WHERE root_id=:root AND state='inspected' "
                       "AND (detector IS NOT :detector OR verified_run IS NOT :run)", args).fetchone()[0]
    todo = db.execute("SELECT count(*) FROM files WHERE root_id=? AND todo=1", (root_id,)).fetchone()[0]
    sev = db.execute(f"""WITH {_PER_FILE} SELECT
        coalesce(sum({_SUSPICIOUS}), 0) AS suspicious, coalesce(sum(per.h), 0) AS high,
        coalesce(sum(NOT {_SUSPICIOUS} AND per.l), 0) AS low_only, coalesce(sum(per.hidden), 0) AS hidden,
        coalesce(sum(per.hidden>0), 0) AS hidden_files,
        coalesce(sum(NOT {_SUSPICIOUS} AND NOT per.l), 0) AS hidden_only FROM per""", {"root": root_id}).fetchone()
    folders = {row["state"]: row["n"] for row in db.execute(
        "SELECT state, count(*) AS n FROM dirs WHERE root_id=? GROUP BY state", (root_id,))}
    other = db.execute("SELECT coalesce(sum(excluded), 0) AS excluded, coalesce(sum(links), 0) AS links, "
                       "coalesce(sum(special), 0) AS special FROM dirs WHERE root_id=? AND state='listed'",
                       (root_id,)).fetchone()
    exts = [(row[0], row[1]) for row in db.execute(
        "SELECT j.key, sum(j.value) AS n FROM dirs d, json_each(d.exts) j WHERE d.root_id=? AND d.state='listed' "
        "GROUP BY j.key ORDER BY n DESC, j.key LIMIT 8", (root_id,))]
    run = None
    if latest is not None:
        state = latest["state"]
        if state == "active":
            # The one live worker says which run it works on; another library's run is not it.
            state = "running" if alive and latest["working"] else "interrupted"
        run = {"id": latest["id"], "mode": latest["mode"], "state": state, "phase": latest["phase"],
               "started": latest["started"], "finished": latest["finished"], "heartbeat": latest["heartbeat"],
               "pid": latest["pid"], "error": latest["error"], "detector": latest["detector"],
               "folders_to_list": db.execute("SELECT count(*) FROM dirs WHERE root_id=? AND todo=1",
                                             (root_id,)).fetchone()[0],
               "files_to_verify": todo}
    inspected = states["inspected"]
    return {
        "id": f"L{root_id}", "path": root["path"], "detector": detector_id(), "suffixes": list(SUFFIXES), "run": run,
        "candidates": sum(states.values()) - states["missing"],
        "inspected": inspected, "stale": stale,
        "suspicious": sev["suspicious"], "high": sev["high"], "low_only": sev["low_only"],
        "allowlisted_only": sev["hidden_only"], "allowlisted_findings": sev["hidden"],
        "allowlisted_files": sev["hidden_files"],
        "no_findings": inspected - sev["suspicious"] - sev["low_only"] - sev["hidden_only"],
        "queued": states["new"], "uninspected": states["uninspected"], "uninspected_reasons": dict(reasons["uninspected"]),
        "failed": states["failed"], "failed_reasons": dict(reasons["failed"]), "missing": states["missing"],
        "excluded": other["excluded"], "excluded_extensions": exts, "links": other["links"], "special": other["special"],
        "folders": {"listed": folders.get("listed", 0), "failed": folders.get("failed", 0),
                    "links": folders.get("symlink", 0), "to_list": folders.get("pending", 0),
                    "missing": folders.get("missing", 0)},
    }


def status(target: Path | str | None = None) -> list[dict]:
    """Coverage of each library, or of one. Counts only: no file row is loaded."""
    alive = worker_alive()
    with connect() as db:
        if db is None:
            if target is not None:
                _known_root(None, target)
            return []
        roots = [_known_root(db, target)] if target is not None else db.execute("SELECT * FROM roots ORDER BY id").fetchall()
        _allowed(db)
        return [_root_status(db, root, alive) for root in roots]


def summary() -> dict | None:
    """A few totals for `agentdetox status`; None when no library was ever scanned."""
    rows = status()
    if not rows:
        return None
    return {"libraries": len(rows), "candidates": sum(r["candidates"] for r in rows),
            "suspicious": sum(r["suspicious"] for r in rows), "stale": sum(r["stale"] for r in rows),
            "unverified": sum(r["queued"] + r["uninspected"] + r["failed"] for r in rows),
            "unfinished": sum(1 for r in rows if r["run"] and r["run"]["state"] in ("running", "interrupted", "cancelled")),
            "running": any(r["run"] and r["run"]["state"] == "running" for r in rows)}


def _n(value: int, word: str, plural: str | None = None) -> str:
    return f"{value:,} {word if value == 1 else plural or word + 's'}"


def _reasons(counts: dict) -> str:
    return ", ".join(f"{n:,} {_REASONS.get(reason, reason)}" for reason, n in sorted(counts.items(), key=lambda kv: -kv[1]))


def render_status(rows: list[dict]) -> str:
    if not rows:
        return ("No library has been scanned. Choose a folder of memory files: `agentdetox library scan <folder>`.")
    out: list[str] = []
    for r in rows:
        out.append(f"Library {r['id']} · {short_path(r['path'])}")
        run = r["run"]
        if run:
            when = {"completed": f"completed {str(run['finished']).replace('T', ' ')}",
                    "running": f"running (pid {run['pid']}), last progress {run['heartbeat'].replace('T', ' ')}",
                    "interrupted": f"interrupted; continue it with `agentdetox library scan {r['id']}`",
                    "cancelled": f"cancelled; continue it with `agentdetox library scan {r['id']}`",
                    "abandoned": "abandoned"}[run["state"]]
            out.append(f"  Run {run['id']} ({run['mode']}): {when}")
            if run["state"] != "completed":
                out.append(f"    still to do: {_n(run['folders_to_list'], 'folder')} to list, "
                           f"{_n(run['files_to_verify'], 'file')} to verify"
                           + (f"; last error: {printable(run['error'])}" if run["error"] else ""))
        out.append(f"  Candidates   {_n(r['candidates'], 'file')} ending in {' '.join(r['suffixes'])}")
        out.append(f"  Inspected    {r['inspected']:,}"
                   + (f", of which {r['stale']:,} stale (not verified by the latest run, or judged by an "
                      "older detector)" if r["stale"] else ""))
        out.append(f"                 {r['suspicious']:,} suspicious: high or medium findings ({r['high']:,} with high)")
        out.append(f"                 {r['low_only']:,} with low-severity findings only")
        if r["allowlisted_only"]:
            out.append(f"                 {r['allowlisted_only']:,} whose findings are all hidden by your allowlist")
        out.append(f"                 {r['no_findings']:,} with no findings recorded")
        out.append(f"  Queued       {r['queued']:,} seen, not inspected yet")
        out.append(f"  Not inspected {r['uninspected']:,}" + (f": {_reasons(r['uninspected_reasons'])}" if r["uninspected"] else ""))
        out.append(f"  Failed       {r['failed']:,}" + (f": {_reasons(r['failed_reasons'])}" if r["failed"] else ""))
        out.append(f"  Missing      {r['missing']:,} inspected earlier, absent from a complete listing")
        kinds = ", ".join(f"{printable(ext)} {n:,}" for ext, n in r["excluded_extensions"])
        out.append(f"  Not candidates  {_n(r['excluded'], 'file')} excluded by extension" + (f" ({kinds})" if kinds else "")
                   + f"; {_n(r['links'], 'symbolic link')} not followed; {_n(r['special'], 'other entry', 'other entries')}")
        f = r["folders"]
        out.append(f"  Folders      {f['listed']:,} listed"
                   + (f"; {f['failed']:,} could not be listed and {f['links']:,} became links: files below them are "
                      "unverified, not deleted" if f["failed"] or f["links"] else ""))
        if r["allowlisted_findings"]:
            out.append(f"  Allowlist    {_n(r['allowlisted_findings'], 'finding')} in {_n(r['allowlisted_files'], 'file')} "
                       "hidden by ids you allowed (`agentdetox allow --list`)")
        out.append(f"  Review: agentdetox library review {r['id']}")
    out.append("\"No findings recorded\" means the deterministic rules matched nothing in the bytes read. It is not a "
               "verdict that a file is clean or true: paraphrased instructions and plausible false facts pass.")
    return "\n".join(out)


def page(target: Path | str, state: str = "suspicious", page_number: int = 1, page_size: int = 20) -> dict:
    if state not in STATES:
        raise ValueError("Choose a state: " + ", ".join(STATES))
    if page_number < 1 or not 1 <= page_size <= 200:
        raise ValueError("Page must be positive; page size must be between 1 and 200")
    with connect() as db:
        root = _known_root(db, target)
        assert db is not None
        _allowed(db)
        latest = _latest_run(db, root["id"])
        args: dict = {"root": root["id"], "detector": detector_id(), "run": latest["id"] if latest else None,
                      "limit": page_size, "offset": (page_number - 1) * page_size}
        columns = "f.id, f.rel, f.state, f.reason, f.sha256, f.size, f.detector, f.verified_run, f.truncated"
        if state in ("suspicious", "low"):
            where = _SUSPICIOUS if state == "suspicious" else f"NOT {_SUSPICIOUS} AND per.l"
            source = f"WITH {_PER_FILE} SELECT {{}} FROM per JOIN files f ON f.id=per.id WHERE {where}"
            order = " ORDER BY per.h DESC, per.m DESC, f.id"
        else:
            where = {"stale": "f.state='inspected' AND (f.detector IS NOT :detector OR f.verified_run IS NOT :run)",
                     "queued": "f.state='new'", "inspected": "f.state='inspected'"}.get(state, f"f.state='{state}'")
            source = f"SELECT {{}} FROM files f WHERE f.root_id=:root AND {where}"
            order = " ORDER BY f.id"
        total = db.execute(source.format("count(*)"), args).fetchone()[0]
        rows = [dict(row) for row in db.execute(source.format(columns) + order + " LIMIT :limit OFFSET :offset", args)]
        for row in rows:
            row["stale"] = row["state"] == "inspected" and (row["detector"] != args["detector"]
                                                            or row["verified_run"] != args["run"])
            top = db.execute("SELECT n.severity, n.message, n.lines, n.flag_id FROM findings n LEFT JOIN temp.allowed a "
                             "ON a.id=n.flag_id WHERE n.file_id=? AND a.id IS NULL ORDER BY CASE n.severity "
                             "WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, n.flag_id LIMIT 1", (row["id"],)).fetchone()
            row["finding"] = dict(top) if top else None
        return {"library": f"L{root['id']}", "path": root["path"], "state": state, "page": page_number,
                "page_size": page_size, "pages": (total + page_size - 1) // page_size, "total": total, "rows": rows}


def render_page(data: dict) -> str:
    lines = [f"Library {data['library']} · {short_path(data['path'])}: {_n(data['total'], 'file')} {data['state']}."]
    if not data["total"]:
        lines.append("Nothing in this state. Other states: --state " + "|".join(s for s in STATES if s != data["state"]))
        return "\n".join(lines)
    lines.append(f"Page {data['page']} of {data['pages']}")
    for row in data["rows"]:
        what = row["state"] + (f" ({_REASONS.get(row['reason'], row['reason'])})" if row["reason"] else "")
        lines.append(f"M{row['id']}  {printable(row['rel'])}  [{what}{', STALE' if row['stale'] else ''}]")
        top = row["finding"]
        if top:
            lines.append(f"    {top['severity'].upper()}: {printable(top['message'])}"
                         + (f" (line {top['lines']})" if top["lines"] else "") + f" [id {top['flag_id']}]")
    if data["page"] < data["pages"]:
        lines.append(f"Next page: repeat with --page {data['page'] + 1}.")
    lines.append("Open one file: agentdetox library review M<ID>.")
    return "\n".join(lines)


def _file_row(db: sqlite3.Connection | None, file_ref: str):
    if not re.fullmatch(r"[Mm][1-9][0-9]*", file_ref):
        raise ValueError("Expected a library file id, such as M42")
    row = db.execute("SELECT f.*, r.path AS root_path, r.dev, r.ino FROM files f JOIN roots r ON r.id=f.root_id "
                     "WHERE f.id=?", (int(file_ref[1:]),)).fetchone() if db is not None else None
    if row is None:
        raise ValueError(f"Unknown library file {file_ref}")
    return row


def _on_disk(row) -> str:
    """How the file is now, against the version recorded for it. Reads one file."""
    try:
        root = _Root({"id": row["root_id"], "path": row["root_path"], "dev": row["dev"], "ino": row["ino"]}).open()
    except (OSError, StoreError) as e:
        return f"unknown: {e}"
    try:
        state, reason, data = _capture(root, _parts(row["rel"]))
    except ValueError as e:
        return f"unknown: {e}"
    finally:
        root.close()
    if data is None:
        return _REASONS.get(reason or "", reason or state)
    return "unchanged" if hashlib.sha256(data).hexdigest() == row["sha256"] else "changed"


def detail(file_ref: str) -> dict:
    with connect() as db:
        row = _file_row(db, file_ref)
        assert db is not None
        _allowed(db)
        latest = _latest_run(db, row["root_id"])
        findings = [dict(f) for f in db.execute(
            "SELECT n.flag_id, n.rule, n.severity, n.message, n.evidence, n.lines, n.sha256, n.detector, "
            "a.id IS NOT NULL AS allowed FROM findings n LEFT JOIN temp.allowed a ON a.id=n.flag_id WHERE n.file_id=? "
            "ORDER BY CASE n.severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END, n.flag_id", (row["id"],))]
    stale = row["state"] == "inspected" and (row["detector"] != detector_id()
                                             or row["verified_run"] != (latest["id"] if latest else None))
    return {"id": f"M{row['id']}", "library": f"L{row['root_id']}", "path": str(Path(row["root_path"], *row["rel"].split("/"))),
            "root": row["root_path"], "state": row["state"], "reason": row["reason"], "sha256": row["sha256"],
            "size": row["size"], "detector": row["detector"], "current_detector": detector_id(), "stale": stale,
            "inspected_run": row["inspected_run"], "verified_run": row["verified_run"],
            "inspected_by": ("cleanup" if row["cleanup_run"] is not None else "scan") if row["state"] == "inspected" else None,
            "cleanup_run": row["cleanup_run"],
            "latest_run": latest["id"] if latest else None, "truncated": row["truncated"],
            "on_disk": _on_disk(row) if row["sha256"] else None, "findings": findings}


def render_detail(d: dict) -> str:
    what = d["state"] + (f" ({_REASONS.get(d['reason'], d['reason'])})" if d["reason"] else "")
    lines = [f"{d['id']} · {short_path(d['path'])} · {what}"]
    if d["sha256"]:
        lines.append(f"Version sha256 {d['sha256']} · {d['size'] or 0:,} bytes")
    if d["state"] == "inspected" and d["inspected_by"] == "cleanup":
        read = (f"a scan last verified them by hash in run {d['verified_run']}" if d["verified_run"] != d["cleanup_run"]
                else "no scan run has read them yet")
        lines.append(f"Inspected by detector {d['detector']} right after a cleanup produced these bytes (while run "
                     f"{d['cleanup_run']} was the latest), not by a scan run; {read} (latest run: {d['latest_run']}).")
    elif d["state"] == "inspected":
        lines.append(f"Inspected in run {d['inspected_run']} by detector {d['detector']}; content last verified by hash "
                     f"in run {d['verified_run']} (latest run: {d['latest_run']}).")
    elif d["findings"]:
        lines.append("The findings below are for the last version that was inspected, which could not be read again.")
    if d["stale"]:
        lines.append("STALE: this conclusion was not verified by the latest run, or was made by an older detector.")
    if d["on_disk"] == "changed":
        lines.append("CHANGED: the file no longer is this version. Scan again before acting on these findings: "
                     f"agentdetox library scan {d['library']}")
    elif d["on_disk"] not in (None, "unchanged"):
        lines.append(f"The file on disk now: {d['on_disk']}.")
    shown = [f for f in d["findings"] if not f["allowed"]]
    for f in shown:
        lines.append(f"{f['severity'].upper():<6} {f['rule']}: {printable(f['message'])}"
                     + (f" · line {f['lines']}" if f["lines"] else "") + f" [id {f['flag_id']}]")
        if f["evidence"]:
            lines.append(f"       > {printable(f['evidence'][:160])}")
    hidden = len(d["findings"]) - len(shown)
    if hidden:
        lines.append(f"{_n(hidden, 'finding')} hidden by ids you allowed: "
                     + " ".join(f["flag_id"] for f in d["findings"] if f["allowed"]))
    if d["truncated"]:
        lines.append(f"{_n(d['truncated'], 'more finding')} in this file were not stored.")
    if d["state"] == "inspected" and not d["findings"]:
        lines.append("No findings recorded for these bytes. That is not a verdict that the file is clean or true.")
    if d["state"] == "inspected" and d["findings"]:
        lines += [f"List its lines and choose what to remove: agentdetox clean {d['id']}",
                  "A rule names its first match in a file; cleaning it can reveal a later one.",
                  "False positive everywhere: agentdetox allow <id> (a lasting exception for that text in every check)."]
    return "\n".join(lines)


# Cleanup -------------------------------------------------------------------------------

def clean(file_ref: str, lines: str | None = None, *, apply: bool = False, expected_hash: str | None = None) -> dict:
    """Preview or apply the removal of chosen lines from a library file, through the same
    journalled recovery as `clean C<ID>`. Only the exact inspected version can be cleaned:
    after any edit the file is scanned again first."""
    from . import review

    label = file_ref.upper()
    with connect() as db:
        row = _file_row(db, file_ref)
    path = Path(row["root_path"], *_parts(row["rel"]))
    again = f"scan again with `agentdetox library scan L{row['root_id']}`, then review {label}"
    if row["state"] != "inspected":
        raise StoreError(f"{label} is {row['state']}" + (f" ({_REASONS.get(row['reason'], row['reason'])})" if row["reason"] else "")
                         + f", not an inspected version; {again}")
    if row["detector"] != detector_id():
        raise StoreError(f"{label} was inspected by a different detector version; {again}")
    if apply and not safefs.PINNED:
        raise StoreError("Applying a library cleanup is not supported on this system: AgentDetox cannot hold the "
                         "file's folder open here, so it cannot rule out the write being redirected through a "
                         "replaced folder. The preview shows the lines; remove them with an editor, then scan again")
    root = _Root({"id": row["root_id"], "path": row["root_path"], "dev": row["dev"], "ino": row["ino"]}).open()
    try:
        def versions(current: bytes) -> tuple[bytes, bytes]:
            if hashlib.sha256(current).hexdigest() != row["sha256"]:
                raise StoreError(f"{_shown(path)} changed since {label} was inspected, so its findings and line numbers "
                                 f"no longer describe it; {again}")
            return b"", current

        def recheck() -> None:
            with connect() as db:
                now = _file_row(db, file_ref)
            if (now["sha256"], now["state"], now["detector"]) != (row["sha256"], row["state"], row["detector"]):
                raise StoreError(f"{label} was scanned again meanwhile; preview the cleanup again")
            root.verify()

        with root.pin(_parts(row["rel"])) as pin:
            result = review.clean_version(pin, "memory", versions, label, {"change": None, "library": label}, lines,
                                          apply=apply, expected_hash=expected_hash, recheck=recheck)
            result["library"] = True
            if result["applied"]:
                cleaned = pin.read()
                result["warning"] += _rebind(row, path, cleaned)
    finally:
        root.close()
    return result


def _rebind(row, path: Path, data: bytes | None) -> str:
    """Record the cleaned file as the version now inspected, with what the rules still find.
    No scan run read these bytes: the row says a cleanup inspected them (`cleanup_run`, the
    latest run, for which the conclusion counts as current) and names no inspecting run. It
    also stops waiting, so a scan batch that read the earlier bytes cannot write over it."""
    if data is None:
        return ""
    try:
        result = judge(str(path), data)
        result.id = row["id"]
        with connect(write=True) as db:
            assert db is not None
            latest = _latest_run(db, row["root_id"])
            current = latest["id"] if latest else None
            with _tx(db):
                inspected = result.action == "inspected"
                changed = db.execute(
                    "UPDATE files SET state=?, reason=?, sha256=?, size=?, detector=?, todo=0, verified_run=?, "
                    "inspected_run=NULL, cleanup_run=?, high=?, medium=?, low=?, truncated=? WHERE id=? AND sha256=?",
                    (result.state, result.reason, result.sha256, result.size or None,
                     detector_id() if inspected else None, current, current if inspected else None, *result.counts,
                     result.truncated, row["id"], row["sha256"])).rowcount
                if changed:
                    _replace_findings(db, result, detector_id())
        left = sum(result.counts)
        return (f"\n{_n(left, 'finding')} remain in the cleaned file: agentdetox library review M{row['id']}" if left else "")
    except (OSError, StoreError, sqlite3.Error) as e:
        return (f"\nThe file was cleaned, but the library inventory could not be updated ({e}); "
                f"scan again with `agentdetox library scan L{row['root_id']}`.")
