"""A resident process that keeps the contradiction model loaded.

Loading the NLI model costs about 6 s and 1 GB, too much for every hook process (and
several at once after a session start that finds many changed files). Hooks hand the
work to this process and return at once. It loads the model on first use, runs jobs
one at a time, and exits after IDLE_SECONDS without work. A lock held for its whole life
makes it the only one per store, so concurrent hooks may start it without coordinating.

A record job is saved in the queue (background.py) before anyone is told of it; the Unix
socket inside the store, which only the user can reach, carries just the wake-up. The job
stays saved until its check has been recorded, so whoever holds the lock next, after a
crash, a stop or an update, finds it there. A check that raises is tried again a bounded
number of times and then set aside for doctor and status to report; one that only lacks
the optional model waits for it instead.

Windows has no Unix sockets, so there is no server there yet: each record job starts a
worker, workers take turns on the same lock, and the one holding it runs every queued
job (see _work_queue). Checks that must answer inside the hook load the model there.
"""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import socket
import socketserver
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path
from typing import Any

from . import __version__, background, compat, events
from .integrity import StoreError, private_dir, store_dir

SERVER = os.name == "posix" and hasattr(socket, "AF_UNIX")
IDLE_SECONDS = 30 * 60
CONNECT_TIMEOUT = 0.5
START_TIMEOUT = 10.0
# How long a connected client may take to send its request.
REQUEST_TIMEOUT = 30.0
QUEUE_WAIT = 600.0
# Seconds before a failed check's second and third attempt.
RETRY_DELAYS = (5.0, 60.0)
_MAX_SOCKET_PATH = 100  # sun_path is 104 bytes on macOS


def idle_seconds() -> float:
    return float(os.environ.get("AGENTDETOX_DAEMON_IDLE") or IDLE_SECONDS)


def socket_path() -> Path:
    path = store_dir() / "nli.sock"
    # The limit is in bytes: a store path with non-ASCII names is longer than it looks.
    if len(os.fsencode(path)) <= _MAX_SOCKET_PATH:
        return path
    if sys.platform == "win32":
        raise OSError("no model server on Windows")
    # A deep custom store overflows sun_path. The per-user temp dir on macOS is private;
    # elsewhere the 0700 directory below is, once it is known to be a real folder of this
    # user's. Looked at without following a link: in a shared /tmp another user could have
    # put one there, and a folder it points to must not be re-permissioned or used.
    base = Path(tempfile.gettempdir()) / f"agentdetox-{os.getuid()}"
    try:
        os.mkdir(base, 0o700)
    except FileExistsError:
        pass
    found = os.lstat(base)
    if not stat.S_ISDIR(found.st_mode) or found.st_uid != os.getuid():
        raise PermissionError(f"{base} is not a folder of this user's")
    if stat.S_IMODE(found.st_mode) != 0o700:
        os.chmod(base, 0o700)
    return base / (hashlib.sha256(str(store_dir()).encode()).hexdigest()[:16] + ".sock")


def code_id() -> str:
    """Changes whenever the installed code does, so a server left running across an
    update is replaced instead of serving old logic."""
    h = hashlib.sha256(__version__.encode())
    for p in sorted(Path(__file__).parent.glob("*.py")):
        st = p.stat()
        h.update(f"{p.name}:{st.st_size}:{st.st_mtime_ns}".encode())
    return h.hexdigest()[:12]


# Client -------------------------------------------------------------------------------

def request(message: dict, timeout: float = 5.0) -> dict | None:
    """One request to the running server; None if no server answered."""
    if not SERVER or sys.platform == "win32":
        return None
    s = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    try:
        s.settimeout(CONNECT_TIMEOUT)
        s.connect(str(socket_path()))
        s.settimeout(timeout)
        s.sendall((json.dumps({"code": code_id(), **message}, ensure_ascii=False) + "\n").encode())
        data = b""
        while not data.endswith(b"\n"):
            chunk = s.recv(65536)
            if not chunk:
                break
            data += chunk
        return json.loads(data) if data else None
    except (OSError, ValueError):
        return None
    finally:
        s.close()


def submit(job: dict) -> None:
    """Save a record job where it outlives any process, then wake the server, starting
    one if needed. Never waits for the work."""
    job_file = background.enqueue(job)
    if job_file is None:
        # Raising would cost the hook its remaining bookkeeping for a check that is optional.
        events.record("hook_error", stage="background-queue",
                      error=f"QueueFull: {background.QUEUE_LIMIT} contradiction checks already wait or failed")
        return
    _wake(str(job_file))


def _wake(job_file: str | None) -> None:
    reply = request({"op": "wake"}, timeout=2.0)
    if not (reply and reply.get("ok")):
        _spawn(job_file)


def retry() -> tuple[int, int]:
    """Queue failed checks again and start the worker on everything that waits. Returns
    how many had failed and how many wait now."""
    requeued = background.retry_failed()
    waiting = len(background.legacy()) + len(background.queued())
    if waiting:
        # A live worker can have set an I/O-blocked job aside for its lifetime.
        stop()
        _wake(None)
    return requeued, waiting


def contradiction(pairs: list[tuple[str, str]], timeout: float = 120.0) -> list[float] | None:
    """Scores from the server, starting it and waiting for it if needed; None on failure."""
    if not SERVER:
        return None
    reply = request({"op": "contradiction", "pairs": pairs}, timeout)
    if reply and reply.get("error") == "model unavailable":
        return None
    if not (reply and reply.get("ok")):
        _spawn(None)
        deadline = time.monotonic() + START_TIMEOUT
        while time.monotonic() < deadline and not ping():
            time.sleep(0.05)
        reply = request({"op": "contradiction", "pairs": pairs}, timeout)
    return reply["probs"] if reply and reply.get("ok") else None


def ping() -> dict | None:
    reply = request({"op": "ping"}, timeout=2.0)
    return reply if reply and reply.get("ok") else None


def stop(timeout: float = 10.0) -> bool:
    """Ask the server to exit after its current work; True once it has."""
    if request({"op": "stop"}) is None:
        return True
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        with _try_lock() as held:
            if held:
                return True
        time.sleep(0.05)
    return False


def _spawn(job_file: str | None) -> None:
    store = private_dir(store_dir())
    log = store / "daemon.log"
    flags = os.O_WRONLY | os.O_CREAT | os.O_APPEND
    if log.exists() and log.stat().st_size > 1_000_000:
        flags |= os.O_TRUNC
    fd = os.open(log, flags, 0o600)
    if compat.WINDOWS:
        # No console window, and out of the hook's process group so it outlives the hook.
        detach: dict[str, Any] = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
                                  | getattr(subprocess, "CREATE_NEW_PROCESS_GROUP", 0x200)}
    else:
        detach = {"start_new_session": True}
    try:
        # -I keeps the current directory and PYTHON* variables out of the import path.
        subprocess.Popen([sys.executable, "-I", "-m", "agentdetox", "_daemon"] + (["--job", job_file] if job_file else []),
                         stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=fd, cwd=store, **detach)
    finally:
        os.close(fd)


@contextlib.contextmanager
def _try_lock():
    fd = os.open(private_dir(store_dir()) / "daemon.lock", os.O_RDWR | os.O_CREAT, 0o600)
    if not compat.try_lock(fd):
        os.close(fd)
        yield None
        return
    try:
        yield fd
    finally:
        compat.release(fd)


# Server -------------------------------------------------------------------------------

def _local_nli():
    from .consistency import NLI

    nli = NLI()
    return nli if nli.available() else None


class ModelUnavailable(Exception):
    """The optional model is not installed or not downloaded. Nothing failed: the check waits."""


def _record(job: dict, nli) -> None:
    from .engine import record_contradictions

    content = bytes.fromhex(job["content_hex"]) if "content_hex" in job else None
    record_contradictions(Path(job["path"]), Path(job["project"]), job.get("old", ""), nli, content=content)


def _log(message: str) -> None:
    print(f"{time.strftime('%H:%M:%S')} {message}", file=sys.stderr, flush=True)


def _error_name(e: BaseException) -> str:
    """What may be written down about an error. An exception's text can quote the memory
    it was working on, so only AgentDetox's own store errors, which name paths, keep theirs."""
    name = type(e).__name__
    return f"{name}: {str(e)[:200]}" if isinstance(e, StoreError) else name


def _where(e: BaseException) -> str:
    frames = []
    tb = e.__traceback__
    while tb is not None:
        code = tb.tb_frame.f_code
        frames.append(f"{Path(code.co_filename).name}:{tb.tb_lineno} in {code.co_name}")
        tb = tb.tb_next
    return " < ".join(reversed(frames[-3:]))


class _Drainer:
    """Runs the queue for the process that holds the daemon lock. A job is tried when it
    is due and at most background.MAX_ATTEMPTS times in all. What this process cannot get
    further with (no model, a job file a virus scanner holds open) it leaves for the next
    process instead of running it over and over."""

    def __init__(self, nli, lock=None) -> None:
        self._nli = nli
        self._lock = lock if lock is not None else contextlib.nullcontext()
        self._retry_at: dict[str, float] = {}
        self._left: set[str] = set()
        self.completed = 0

    def _model(self):
        nli = self._nli()
        if nli is None:
            raise ModelUnavailable
        return nli

    def run_due(self, stop=None) -> float | None:
        """Run every job that is due, those queued meanwhile included, unless `stop` says
        to leave them. Returns the seconds until the next retry, None if there is none."""
        for path in background.legacy():
            background.adopt(path)
        expired = background.prune()
        if expired:
            days = int(background.KEEP_SECONDS // 86400)
            events.record("background_check_expired", count=expired, days=days)
            _log(f"{expired} background check(s) expired without running after {days} days")
        ran = True
        while ran:
            ran = False
            for path in background.queued():
                if stop is not None and stop():
                    return None
                if path.name in self._left or self._retry_at.get(path.name, 0.0) > time.monotonic():
                    continue
                self._run(path)
                ran = True
        # A job that expired or was removed meanwhile must not leave a retry that is forever due.
        still_queued = {path.name for path in background.queued()}
        self._retry_at = {name: at for name, at in self._retry_at.items() if name in still_queued}
        if not self._retry_at:
            return None
        return max(0.0, min(self._retry_at.values()) - time.monotonic())

    def _run(self, path: Path) -> None:
        self._retry_at.pop(path.name, None)
        try:
            self._attempt(path)
        except OSError as e:
            # The queue itself could not be updated; trying again at once would spin.
            self._left.add(path.name)
            _log(f"background check {path.stem} left queued: {type(e).__name__}")

    def _attempt(self, path: Path) -> None:
        try:
            job = background.load(path)
        except FileNotFoundError:
            return
        except ValueError:
            return self._set_aside(path, None, "InvalidJob", 0)
        meta = job["queue"]
        if meta["attempts"] >= background.MAX_ATTEMPTS:
            # Counted before each start: attempts that left no error ended with the process.
            return self._set_aside(path, job, meta.get("error") or "Interrupted", meta["attempts"])
        if meta.get("waiting") == "model" and not self._has_model():
            self._left.add(path.name)
            return
        attempts = background.claim(path, job)
        try:
            with self._lock:
                _record(job, self._model)
        except ModelUnavailable:
            background.wait_for_model(path, job)
            self._left.add(path.name)
            _log(f"background check {path.stem} waits for the contradiction model")
        except Exception as e:  # noqa: BLE001
            error = _error_name(e)
            _log(f"background check {path.stem} failed, attempt {attempts} of {background.MAX_ATTEMPTS}: "
                 f"{error} ({_where(e)})")
            if attempts >= background.MAX_ATTEMPTS:
                return self._set_aside(path, job, error, attempts)
            background.retry_later(path, job, error)
            self._retry_at[path.name] = time.monotonic() + RETRY_DELAYS[min(attempts, len(RETRY_DELAYS)) - 1]
        else:
            if not background.done(path):
                self._left.add(path.name)
            self.completed += 1

    def _has_model(self) -> bool:
        with self._lock:
            return self._nli() is not None

    def _set_aside(self, path: Path, job: dict | None, error: str, attempts: int) -> None:
        background.fail(path, job, error)
        events.record("background_check_failed", job=path.stem, path=job["path"] if job else "", error=error,
                      attempts=attempts)
        _log(f"background check {path.stem} set aside after {attempts} attempt(s): {error}")


class _State:
    def __init__(self, server: socketserver.BaseServer, nli_factory, idle: float) -> None:
        self.server = server
        self.idle = idle
        self.code = code_id()
        self.started = time.time()
        self.last = time.monotonic()
        self.busy = 0
        self.work = threading.Lock()
        self.count = threading.Lock()
        self.stopping = threading.Event()
        self.wake = threading.Event()
        self.finish_queue = False
        self._factory = nli_factory or _local_nli
        self._nli = None
        self._loaded = False
        self.drainer = _Drainer(self.nli, self.work)

    def nli(self):
        """Called only while holding `work`, so the model loads once."""
        if not self._loaded:
            self._nli = self._factory()
            self._loaded = True
        return self._nli

    @contextlib.contextmanager
    def active(self):
        with self.count:
            self.busy += 1
        try:
            yield
        finally:
            with self.count:
                self.busy -= 1
                self.last = time.monotonic()

    def stop(self, finish_queue: bool = False) -> None:
        """`finish_queue` for an exit the server decided on itself: a job saved while it
        was deciding is still run before the lock is let go. When told to stop, it leaves
        the queue, as it is on disk, to the next server."""
        with self.count:
            if self.stopping.is_set():
                return
            self.stopping.set()
            self.finish_queue = finish_queue
        self.wake.set()
        threading.Thread(target=self.server.shutdown, daemon=True).start()

    def wake_up(self) -> bool:
        """False once stopping, so the sender starts a server instead of counting on this one."""
        with self.count:
            if self.stopping.is_set():
                return False
            self.wake.set()
            return True

    def run_queue(self) -> None:
        try:
            while not self.stopping.is_set():
                with self.active():
                    delay = self.drainer.run_due(self.stopping.is_set)
                self.wake.wait(delay)
                self.wake.clear()
        except Exception as e:  # noqa: BLE001
            # A server that answers wake-ups but runs nothing would hide the queue's state.
            _log(f"background worker stopped: {_error_name(e)} ({_where(e)})")
            self.stop()

    def info(self) -> dict:
        return {"ok": True, "pid": os.getpid(), "version": __version__, "code": self.code,
                "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started)),
                "model_loaded": self._nli is not None, "jobs": self.drainer.completed, "busy": self.busy,
                "idle_seconds": round(time.monotonic() - self.last)}


class _Handler(socketserver.StreamRequestHandler):
    # A client that connects and sends nothing must not count as work in progress for ever:
    # the server would never see itself idle, and would keep the model loaded.
    timeout = REQUEST_TIMEOUT

    def handle(self) -> None:
        state: _State = self.server.state       # type: ignore[attr-defined]  # set by _run
        with state.active():
            try:
                msg = json.loads(self.rfile.readline())
            except (ValueError, OSError):
                return
            if not isinstance(msg, dict):
                return
            op = msg.get("op")
            if op == "ping":
                return self._reply(state.info())
            if op == "stop":
                self._reply({"ok": True})
                return state.stop()
            if msg.get("code") != state.code:
                # The client runs newer code: make way for a server running it too.
                self._reply({"ok": False, "error": "stale"})
                return state.stop()
            if op == "wake":
                return self._reply({"ok": state.wake_up()})
            if op == "contradiction":
                with state.work:
                    nli = state.nli()
                    if nli is None:
                        return self._reply({"ok": False, "error": "model unavailable"})
                    probs = nli.contradiction([tuple(p) for p in msg.get("pairs", [])])
                return self._reply({"ok": True, "probs": probs})
            self._reply({"ok": False, "error": f"unknown op {op!r}"})

    def _reply(self, data: dict) -> None:
        with contextlib.suppress(OSError):
            self.wfile.write((json.dumps(data) + "\n").encode())


if sys.platform == "win32":
    _Server: Any  # declared only: the name stays unbound where there is no server
elif SERVER:
    class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True
        state: _State


def serve(job_file: str | None = None, nli_factory=None, idle: float | None = None) -> int:
    """Run the server, working through the queue, until it is idle for `idle` seconds or
    asked to stop. If another server holds the store, wake it and return. `job_file` is a
    job saved outside the queue, as earlier versions did; it is moved in first."""
    if job_file:
        background.adopt(Path(job_file))
    if not SERVER:
        return _work_queue(nli_factory)
    # With jobs saved, outwait a server that is finishing its last one before it steps down.
    waiting = bool(background.queued() or background.legacy())
    deadline = time.monotonic() + (QUEUE_WAIT if waiting else START_TIMEOUT)
    while True:
        with _try_lock() as held:
            if held is not None:
                return _run(held, nli_factory, idle_seconds() if idle is None else idle)
        # Another server owns the store. It may still be binding or just shutting down.
        reply = request({"op": "wake"}, timeout=2.0)
        if reply and reply.get("ok"):
            return 0
        if time.monotonic() > deadline:
            return 1
        time.sleep(0.1)


def _run(lock_fd: int, nli_factory, idle: float) -> int:
    path = socket_path()
    path.unlink(missing_ok=True)  # we hold the lock, so any socket left here is stale
    server = _Server(str(path), _Handler)
    os.chmod(path, 0o600)
    state = _State(server, nli_factory, idle)
    server.state = state
    if nli_factory is None and _local_nli() is None:
        state.stop(finish_queue=True)  # no model to serve: mark what waits for it, then leave
    worker = threading.Thread(target=state.run_queue, daemon=True)
    worker.start()

    def watchdog() -> None:
        while not state.stopping.wait(min(5.0, max(idle / 4, 0.05))):
            with state.count:
                idle_for = time.monotonic() - state.last if state.busy == 0 else 0
            if idle_for >= idle:
                state.stop(finish_queue=True)
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        deadline = time.monotonic() + 120
        while state.busy and time.monotonic() < deadline:
            time.sleep(0.05)  # finish the job in hand before letting go of the lock
        worker.join(max(0.0, deadline - time.monotonic()))
        try:
            if state.finish_queue and not state.busy and not worker.is_alive():
                # A wake-up acknowledged just before stopping was decided has had no pass yet.
                # Its job was saved before it was sent, so one pass now, with the socket closed, finds it.
                state.drainer.run_due()
        finally:
            path.unlink(missing_ok=True)
    return 0


def _work_queue(nli_factory=None, wait: float = QUEUE_WAIT) -> int:
    """Without a server, every record job starts one of these. Workers take turns on the
    lock and the one holding it runs every queued job, so a burst of writes loads the
    model once rather than once per write, and never in several processes at a time. A
    worker that waits past `wait` can leave: the holder drains the queue before letting
    go, so its job is not lost."""
    deadline = time.monotonic() + wait
    while True:
        with _try_lock() as held:
            if held is not None:
                _drain(nli_factory or _local_nli)
                return 0
        if time.monotonic() > deadline:
            return 1
        time.sleep(0.2)


def _drain(nli_factory) -> int:
    loaded: list = []

    def nli():
        if not loaded:
            loaded.append(nli_factory())
        return loaded[0]

    drainer = _Drainer(nli)
    while (delay := drainer.run_due()) is not None:
        time.sleep(delay)  # a retry is due later; the attempts are bounded, so this ends
    return drainer.completed
