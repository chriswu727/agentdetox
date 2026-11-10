"""Background contradiction checks that have not finished, kept as files so that no
worker's crash or exit takes one with it.

A hook saves its job here, complete and under its final name, before it wakes or starts a
worker. From then on only the process holding the daemon lock rewrites or removes it, and
removes it only after the engine has recorded the result. A job is the dict the engine
queued (path, project, old, content_hex) plus a "queue" entry kept here: the attempts
started, the name of the last error, whether it waits for the model. One that used up its
attempts is renamed *.failed and kept, still runnable, for KEEP_SECONDS.

Earlier versions queued in pending/, which integrity.gc empties of anything a day old.
A job must be able to wait longer than that, so the queue has a folder of its own and
jobs found in pending/ are moved into it as they are.
"""

from __future__ import annotations

import contextlib
import errno
import json
import os
import tempfile
import time
from pathlib import Path

from .integrity import private_dir, store_dir

MAX_ATTEMPTS = 3
KEEP_SECONDS = 7 * 86400
STALLED_AFTER = 600.0
# Each job holds a copy of the file it is about; a queue nothing drains must not grow without end.
QUEUE_LIMIT = 500
_ABANDONED_PART = 3600


def queue_dir() -> Path:
    return store_dir() / "background"


def queued() -> list[Path]:
    """Jobs in the queue, oldest first."""
    return sorted(queue_dir().glob("*.json"))


def legacy() -> list[Path]:
    return sorted((store_dir() / "pending").glob("*.json"))


def failed() -> list[Path]:
    return sorted(queue_dir().glob("*.failed"))


def _new_name() -> str:
    # Sorts by the time it was queued, which is also how its age is read back.
    return f"{time.time_ns():020d}-{os.urandom(4).hex()}.json"


def queued_at(path: Path) -> float:
    try:
        return int(path.name.split("-", 1)[0]) / 1e9
    except ValueError:
        pass
    try:
        return path.stat().st_mtime
    except OSError:
        return time.time()


def _write(path: Path, job: dict) -> None:
    fd, part = tempfile.mkstemp(dir=path.parent, suffix=".part")
    try:
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            json.dump(job, f, ensure_ascii=False)
            f.flush()
            os.fsync(f.fileno())
        # Renamed only once complete: nothing reading the queue may find half a job.
        os.replace(part, path)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(part)
        raise
    _sync_dir(path.parent)


def _sync_dir(directory: Path) -> None:
    # The new name has to reach the disk as well. Windows cannot open a directory for this.
    if os.name == 'nt':
        return
    try:
        fd = os.open(directory, os.O_RDONLY)
        try:
            os.fsync(fd)
        finally:
            os.close(fd)
    except OSError as error:
        if error.errno not in {errno.EINVAL, errno.ENOTSUP}:
            raise


def enqueue(job: dict) -> Path | None:
    """Save a job durably and return its file; None, saving nothing, when the queue is
    full. Failed jobs count: they hold copies too."""
    private_dir(store_dir())
    directory = private_dir(queue_dir())
    if len(queued()) + len(failed()) >= QUEUE_LIMIT:
        return None
    path = directory / _new_name()
    _write(path, {**job, "queue": {"attempts": 0}})
    return path


def adopt(path: Path) -> None:
    """Move a job file from outside the queue into it: one an earlier version left in
    pending/, or one handed to `_daemon --job`. Its content is not touched; a job without
    a "queue" entry reads as not yet attempted."""
    try:
        if os.path.realpath(path.parent) == os.path.realpath(queue_dir()):
            return
        stamp = path.stat().st_mtime_ns
    except OSError:
        return
    private_dir(store_dir())
    target = private_dir(queue_dir()) / f"{stamp:020d}-{os.urandom(4).hex()}.json"
    # Taken by another worker meanwhile, or held open: then it stays where it is, still counted by status().
    with contextlib.suppress(OSError):
        os.replace(path, target)
        os.chmod(target, 0o600)
        _sync_dir(target.parent)


def load(path: Path) -> dict:
    """The job in `path`; ValueError if it does not hold one."""
    job = json.loads(path.read_text(encoding="utf-8"))
    if not (isinstance(job, dict) and isinstance(job.get("path"), str) and isinstance(job.get("project"), str)):
        raise ValueError("not a contradiction-check job")
    meta = job.get("queue")
    meta = dict(meta) if isinstance(meta, dict) else {}
    if not isinstance(meta.get("attempts"), int):
        meta["attempts"] = 0
    job["queue"] = meta
    return job


def claim(path: Path, job: dict) -> int:
    """Count an attempt before it starts, so that one which ends with the process is
    still counted. Returns the attempts started so far."""
    meta = job["queue"]
    meta["attempts"] += 1
    meta.pop("error", None)
    meta.pop("waiting", None)
    _write(path, job)
    return meta["attempts"]


def wait_for_model(path: Path, job: dict) -> None:
    """Give back the attempt just counted: without the model nothing was tried."""
    job["queue"]["attempts"] -= 1
    job["queue"]["waiting"] = "model"
    _write(path, job)


def retry_later(path: Path, job: dict, error: str) -> None:
    job["queue"]["error"] = error
    _write(path, job)


def fail(path: Path, job: dict | None, error: str) -> None:
    """Set a job aside where status() reports it and retry_failed() finds it. `job` is
    None for a file that could not be read, which is kept byte for byte."""
    if job is not None:
        # Saved under the queued name first: if the rename below never happens, the next
        # worker finds the attempts used up and this error, and sets it aside itself.
        job["queue"]["error"] = error
        _write(path, job)
    os.replace(path, path.with_suffix(".failed"))
    _sync_dir(path.parent)


def done(path: Path) -> bool:
    """Remove a finished job; False if the file could not be removed."""
    try:
        path.unlink()
    except FileNotFoundError:
        pass
    except OSError:
        return False
    return True


def retry_failed() -> int:
    """Queue failed jobs again with a fresh set of attempts; how many."""
    count = 0
    for path in failed():
        try:
            job = load(path)
        except (OSError, ValueError):
            continue  # nothing in it to run; it expires with the rest
        job["queue"] = {"attempts": 0}
        _write(path.with_name(_new_name()), job)
        with contextlib.suppress(OSError):
            path.unlink()
        count += 1
    return count


def prune(now: float | None = None) -> int:
    """Remove what has been kept past KEEP_SECONDS, and partial writes nobody finished.
    Returns how many checks that had not run were dropped."""
    now = time.time() if now is None else now
    directory = queue_dir()
    dropped = 0
    for path in sorted(directory.iterdir()) if directory.is_dir() else []:
        try:
            if path.suffix == ".json":
                expired = now - queued_at(path) > KEEP_SECONDS
            elif path.suffix == ".failed":
                expired = now - path.stat().st_mtime > KEEP_SECONDS
            else:
                expired = path.suffix == ".part" and now - path.stat().st_mtime > _ABANDONED_PART
            if expired:
                path.unlink()
                dropped += path.suffix == ".json"
        except OSError:
            continue
    return dropped


def _stamp(when: float) -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(when))


def status(now: float | None = None) -> dict:
    """What waits and what failed, for doctor and status. Reads only: it creates nothing."""
    now = time.time() if now is None else now
    jobs = legacy() + queued()
    waiting = stalled = 0
    for path in jobs:
        try:
            meta = load(path)["queue"]
        except (OSError, ValueError):
            meta = {}
        if meta.get("waiting") == "model":
            waiting += 1
        elif now - queued_at(path) > STALLED_AFTER:
            stalled += 1
    failures = []
    for path in failed():
        try:
            when = path.stat().st_mtime
        except OSError:
            continue
        try:
            job = load(path)
        except (OSError, ValueError):
            job = {"path": "", "queue": {"error": "InvalidJob", "attempts": 0}}
        failures.append({"ts": _stamp(when), "path": job["path"], "error": str(job["queue"].get("error") or "unknown"),
                         "attempts": job["queue"]["attempts"]})
    return {
        "queued": len(jobs) - waiting,
        "stalled": stalled,
        "waiting_model": waiting,
        "failed": len(failures),
        "oldest": _stamp(min(queued_at(p) for p in jobs)) if jobs else None,
        "last_failure": max(failures, key=lambda f: f["ts"]) if failures else None,
        "directory": str(queue_dir()),
    }
