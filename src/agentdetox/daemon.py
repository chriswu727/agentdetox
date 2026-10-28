"""A resident process that keeps the contradiction model loaded.

Loading the NLI model costs about 6 s and 1 GB, too much for every hook process (and
several at once after a session start that finds many changed files). Hooks hand the
work to this process over a Unix socket inside the store, which only the user can
reach, and return at once. It loads the model on first use, runs jobs one at a time,
and exits after IDLE_SECONDS without work. A lock held for its whole life makes it
the only one per store, so concurrent hooks may start it without coordinating.

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
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

from . import __version__, compat
from .integrity import private_dir, store_dir

SERVER = os.name == "posix" and hasattr(socket, "AF_UNIX")
IDLE_SECONDS = 30 * 60
CONNECT_TIMEOUT = 0.5
START_TIMEOUT = 10.0
QUEUE_WAIT = 600.0
_MAX_SOCKET_PATH = 100  # sun_path is 104 bytes on macOS


def idle_seconds() -> float:
    return float(os.environ.get("AGENTDETOX_DAEMON_IDLE") or IDLE_SECONDS)


def socket_path() -> Path:
    path = store_dir() / "nli.sock"
    if len(str(path)) <= _MAX_SOCKET_PATH:
        return path
    # A deep custom store overflows sun_path. The per-user temp dir on macOS is private;
    # elsewhere the 0700 directory below is, once its owner is checked.
    base = Path(tempfile.gettempdir()) / f"agentdetox-{os.getuid()}"
    private_dir(base)
    if base.stat().st_uid != os.getuid():
        raise PermissionError(f"{base} belongs to another user")
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
    if not SERVER:
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
    """Hand a record job to the server, starting one if needed. Never waits for the work."""
    reply = request({"op": "record", **job}, timeout=2.0)
    if reply and reply.get("ok"):
        return
    pending = private_dir(store_dir() / "pending")
    fd, part = tempfile.mkstemp(dir=pending, suffix=".part")
    with os.fdopen(fd, "w", encoding="utf-8") as f:
        json.dump(job, f, ensure_ascii=False)
    # Renamed only once complete: a Windows worker draining the queue must not read it half-written.
    job_file = part[:-len(".part")] + ".json"
    os.replace(part, job_file)
    _spawn(job_file)


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
        detach = {"creationflags": getattr(subprocess, "CREATE_NO_WINDOW", 0x08000000)
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


def _record(job: dict, nli) -> None:
    from .hooks import record_contradictions

    try:
        record_contradictions(Path(job["path"]), Path(job["project"]), job.get("old", ""), nli)
    except Exception as e:  # noqa: BLE001
        print(f"{time.strftime('%H:%M:%S')} record job failed: {type(e).__name__}: {e}", file=sys.stderr, flush=True)


class _State:
    def __init__(self, server: socketserver.BaseServer, nli_factory, idle: float) -> None:
        self.server = server
        self.idle = idle
        self.code = code_id()
        self.started = time.time()
        self.last = time.monotonic()
        self.jobs = 0
        self.busy = 0
        self.work = threading.Lock()
        self.count = threading.Lock()
        self.stopping = threading.Event()
        self._factory = nli_factory or _local_nli
        self._nli = None
        self._loaded = False

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

    def stop(self) -> None:
        if not self.stopping.is_set():
            self.stopping.set()
            threading.Thread(target=self.server.shutdown, daemon=True).start()

    def info(self) -> dict:
        return {"ok": True, "pid": os.getpid(), "version": __version__, "code": self.code,
                "started": time.strftime("%Y-%m-%dT%H:%M:%S", time.localtime(self.started)),
                "model_loaded": self._nli is not None, "jobs": self.jobs, "busy": self.busy,
                "idle_seconds": round(time.monotonic() - self.last)}

    def record(self, job: dict) -> None:
        with self.work:
            _record(job, self.nli)
            self.jobs += 1


class _Handler(socketserver.StreamRequestHandler):
    def handle(self) -> None:
        state: _State = self.server.state
        with state.active():
            try:
                msg = json.loads(self.rfile.readline())
            except ValueError:
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
            if op == "record":
                self._reply({"ok": True})
                return state.record(msg)
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


if SERVER:
    class _Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
        daemon_threads = True


def serve(job_file: str | None = None, nli_factory=None, idle: float | None = None) -> int:
    """Run the server until it is idle for `idle` seconds or asked to stop. If another
    server holds the store, hand it `job_file` and return."""
    if not SERVER:
        return _work_queue(nli_factory)
    job = None
    if job_file:
        with contextlib.suppress(OSError, ValueError):
            job = json.loads(Path(job_file).read_text(encoding="utf-8"))
        Path(job_file).unlink(missing_ok=True)
    deadline = time.monotonic() + START_TIMEOUT
    while True:
        with _try_lock() as held:
            if held is not None:
                return _run(held, job, nli_factory, idle_seconds() if idle is None else idle)
        # Another server owns the store. It may still be binding or just shutting down.
        reply = request({"op": "record", **job}, timeout=2.0) if job else ping()
        if reply and reply.get("ok"):
            return 0
        if time.monotonic() > deadline:
            return 1
        time.sleep(0.1)


def _run(lock_fd: int, job: dict | None, nli_factory, idle: float) -> int:
    path = socket_path()
    path.unlink(missing_ok=True)  # we hold the lock, so any socket left here is stale
    server = _Server(str(path), _Handler)
    os.chmod(path, 0o600)
    state = server.state = _State(server, nli_factory, idle)
    if nli_factory is None and _local_nli() is None:
        state.stop()  # no model to serve; hooks fall back to doing nothing
    if job:
        def first() -> None:
            with state.active():
                state.record(job)
        threading.Thread(target=first, daemon=True).start()

    def watchdog() -> None:
        while not state.stopping.wait(min(5.0, max(idle / 4, 0.05))):
            with state.count:
                idle_for = time.monotonic() - state.last if state.busy == 0 else 0
            if idle_for >= idle:
                state.stop()
    threading.Thread(target=watchdog, daemon=True).start()
    try:
        server.serve_forever(poll_interval=0.2)
    finally:
        server.server_close()
        deadline = time.monotonic() + 120
        while state.busy and time.monotonic() < deadline:
            time.sleep(0.05)  # finish accepted jobs before letting go of the lock
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

    pending, seen = store_dir() / "pending", set()
    # `seen` stops a job file that cannot be deleted (held open by a virus scanner) from
    # being run over and over.
    while jobs := [p for p in sorted(pending.glob("*.json")) if p not in seen]:
        for job_file in jobs:
            seen.add(job_file)
            try:
                job = json.loads(job_file.read_text(encoding="utf-8"))
            except (OSError, ValueError):
                job = None
            with contextlib.suppress(OSError):
                job_file.unlink()
            if isinstance(job, dict):
                _record(job, nli)
    return len(seen)
