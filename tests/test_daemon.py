import json
import os
import shutil
import socket
import stat
import subprocess
import sys
import tempfile
import threading
import time
from pathlib import Path

import pytest

from agentdetox import background, daemon, engine, events, storage
from agentdetox.cli import main
from agentdetox.context import claude_memory_dir
from agentdetox.integrity import private_dir

OLD_FACT = "Deploys go through `make deploy`, which runs the staging checks first.\n"
NEW_FACT = "Deploy with ./deploy.sh --skip-checks; the staging checks were retired.\n"


class FakeNLI:
    def contradiction(self, pairs):
        return [0.97 if "skip" in a + b else 0.01 for a, b in pairs]


def wait_for(check, timeout=5.0):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        result = check()
        if result:
            return result
        time.sleep(0.02)
    return None


@pytest.fixture
def store(monkeypatch):
    # pytest's tmp_path is too deep for a Unix socket path on macOS.
    path = Path(tempfile.mkdtemp(prefix="adx-", dir="/tmp" if os.name == "posix" else None))
    monkeypatch.setenv("AGENTDETOX_HOME", str(path))
    yield path
    shutil.rmtree(path, ignore_errors=True)


posix_only = pytest.mark.skipif(os.name == "nt", reason="Unix sockets and permission bits")


def start(factory=FakeNLI, idle=30.0):
    if not daemon.SERVER:
        pytest.skip("no model server on this platform yet")
    loads = []

    def counted():
        loads.append(1)
        return factory()

    t = threading.Thread(target=daemon.serve, kwargs={"nli_factory": counted, "idle": idle}, daemon=True)
    t.start()
    assert wait_for(daemon.ping), "server did not start"
    return t, loads


@pytest.fixture
def server(store):
    t, loads = start()
    yield t, loads
    daemon.stop()
    t.join(5)


@pytest.fixture
def memory(store, tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    monkeypatch.setenv("AGENTDETOX_USER_HOME", str(home))
    mem = claude_memory_dir(project, home)
    mem.mkdir(parents=True)
    (mem / "deploy.md").write_text(OLD_FACT, encoding="utf-8")
    (mem / "deploy-new.md").write_text(NEW_FACT, encoding="utf-8")
    return project, mem


def contradictions():
    return [r for r in events.read(None) if r["event"] == "contradiction"]


def test_model_loads_once_and_answers(server):
    _, loads = server
    assert daemon.contradiction([("skip the checks", "run the checks"), ("a", "b")]) == [0.97, 0.01]
    assert daemon.contradiction([("x", "y")]) == [0.01]
    assert loads == [1]
    info = daemon.ping()
    assert info["model_loaded"] and info["code"] == daemon.code_id()


def test_socket_is_private(server, store):
    assert stat.S_IMODE(daemon.socket_path().stat().st_mode) == 0o600
    assert stat.S_IMODE(store.stat().st_mode) == 0o700


def test_record_job_is_logged(server, memory):
    project, mem = memory
    daemon.submit({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""})
    [row] = wait_for(contradictions)
    assert "skip-checks" in row["new"] and row["id"]
    assert wait_for(lambda: daemon.ping()["jobs"] == 1)


def test_a_second_server_hands_its_job_to_the_first(server, memory, store):
    project, mem = memory
    job_file = store / "job.json"
    job_file.write_text(json.dumps({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""}), encoding="utf-8")
    started = time.monotonic()
    assert daemon.serve(str(job_file)) == 0
    assert time.monotonic() - started < 3 and not job_file.exists()
    assert wait_for(contradictions)


def test_a_server_with_old_code_steps_down(server, monkeypatch):
    t, _ = server
    monkeypatch.setattr(daemon, "code_id", lambda: "newer-build")
    assert daemon.request({"op": "contradiction", "pairs": [["a", "b"]]}) == {"ok": False, "error": "stale"}
    t.join(5)
    assert not t.is_alive() and not daemon.socket_path().exists()


def test_idle_server_exits_and_releases_the_store(store):
    t, _ = start(idle=0.3)
    t.join(5)
    assert not t.is_alive() and daemon.ping() is None
    t2, _ = start()                    # the lock was released, so a new one can take over
    daemon.stop()
    t2.join(5)


def test_no_server_is_a_fast_none(store):
    started = time.monotonic()
    assert daemon.ping() is None and time.monotonic() - started < 1


def test_missing_model_is_reported_not_retried(store, monkeypatch):
    spawned = []
    t, _ = start(factory=lambda: None)
    monkeypatch.setattr(daemon, "_spawn", spawned.append)
    assert daemon.contradiction([("a", "b")]) is None and spawned == []
    daemon.stop()
    t.join(5)


def test_submit_without_a_server_starts_one_with_a_private_job_file(store, monkeypatch):
    spawned = []
    monkeypatch.setattr(daemon, "_spawn", spawned.append)
    daemon.submit({"path": "/x", "project": "/p", "old": "secret memory"})
    [job_file] = spawned
    assert os.name == "nt" or stat.S_IMODE(Path(job_file).stat().st_mode) == 0o600
    assert json.loads(Path(job_file).read_text(encoding="utf-8"))["old"] == "secret memory"


def test_ask_mode_hooks_use_the_server(server):
    assert engine._ServerNLI().contradiction([("skip it", "do it")]) == [0.97]


@posix_only
def test_deep_store_falls_back_to_a_private_temp_socket(tmp_path, monkeypatch):
    deep = tmp_path / ("d" * 60) / "store"
    monkeypatch.setenv("AGENTDETOX_HOME", str(deep))
    path = daemon.socket_path()
    assert len(str(path)) <= 104
    assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700


@pytest.fixture
def no_server(monkeypatch):
    """Windows: no Unix sockets, so record jobs queue up for workers."""
    monkeypatch.setattr(daemon, "SERVER", False)
    spawned = []
    monkeypatch.setattr(daemon, "_spawn", spawned.append)
    return spawned


def pending_jobs():
    return sorted(background.queue_dir().glob("*"))


def test_without_a_server_one_worker_runs_every_queued_job(memory, no_server):
    project, mem = memory
    for _ in range(3):
        daemon.submit({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""})
    assert len(no_server) == 3 and [p.suffix for p in pending_jobs()] == [".json"] * 3
    loads = []

    def factory():
        loads.append(1)
        return FakeNLI()

    assert daemon.serve(no_server[0], nli_factory=factory) == 0
    assert len(contradictions()) == 3 and loads == [1] and pending_jobs() == []
    assert daemon.serve(no_server[1], nli_factory=factory) == 0      # later workers find nothing left
    assert loads == [1]


def test_a_job_queued_while_the_worker_runs_is_not_left_behind(memory, no_server):
    project, mem = memory
    job = {"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""}

    class WriteDuringCheck(FakeNLI):
        def contradiction(self, pairs):
            if len(no_server) == 1:
                daemon.submit(job)      # its worker would find the lock held and wait
            return super().contradiction(pairs)

    daemon.submit(job)
    assert daemon.serve(no_server[0], nli_factory=WriteDuringCheck) == 0
    assert len(no_server) == 2 and len(contradictions()) == 2 and pending_jobs() == []


def test_a_worker_that_cannot_get_the_lock_leaves_its_job_queued(memory, no_server):
    project, mem = memory
    daemon.submit({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""})
    with daemon._try_lock() as held:
        assert held is not None
        assert daemon._work_queue(FakeNLI, wait=0.3) == 1
    assert len(pending_jobs()) == 1 and not contradictions()
    assert daemon._work_queue(FakeNLI) == 0 and len(contradictions()) == 1


def test_without_a_server_checks_in_the_hook_load_the_model_there(store, no_server, monkeypatch):
    assert daemon.contradiction([("a", "b")]) is None and no_server == []

    class LocalNLI:
        def available(self):
            return True

    monkeypatch.setattr(engine, "NLI", LocalNLI)
    assert isinstance(engine._nli(), LocalNLI)


@posix_only
def test_stale_socket_file_is_replaced(store):
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(daemon.socket_path()))
    stale.close()                      # a crashed server leaves its socket file behind
    t, _ = start()
    assert daemon.ping()["pid"]
    daemon.stop()
    t.join(5)


# Durable queue ------------------------------------------------------------------------

class Killed(BaseException):
    """What a killed process looks like to the code: nothing gets to clean up."""


class Broken:
    """A model whose error text quotes the memory it was given."""

    def __init__(self):
        self.calls = 0

    def contradiction(self, pairs):
        self.calls += 1
        raise RuntimeError(f"cannot score {pairs}")


@pytest.fixture
def fast_retries(monkeypatch):
    monkeypatch.setattr(daemon, "RETRY_DELAYS", (0.01, 0.01))


def job_for(memory):
    project, mem = memory
    return {"path": str(mem / "deploy-new.md"), "project": str(project), "old": "",
            "content_hex": NEW_FACT.encode().hex()}


def named(event):
    return [r for r in events.read(None) if r["event"] == event]


def test_a_job_is_saved_before_the_server_hears_of_it(store, monkeypatch):
    heard = []

    def request(message, timeout=5.0):
        heard.append((message, [background.load(p) for p in background.queued()]))
        return {"ok": True}

    monkeypatch.setattr(daemon, "request", request)
    monkeypatch.setattr(daemon, "_spawn", lambda job_file: pytest.fail("the wake-up was acknowledged"))
    daemon.submit({"path": "/x", "project": "/p", "old": "earlier text", "content_hex": "6e6577"})
    [(message, saved)] = heard
    assert message == {"op": "wake"}                   # the job never travels in memory
    assert [(j["old"], j["content_hex"]) for j in saved] == [("earlier text", "6e6577")]
    [job_file] = pending_jobs()                        # acknowledged, not run: still there to be run
    assert job_file.suffix == ".json" and background.load(job_file)["queue"]["attempts"] == 0


@posix_only
def test_queued_and_failed_jobs_are_private(store, no_server, fast_retries):
    daemon.submit({"path": "/x", "project": "/p", "old": "secret memory", "content_hex": "zz"})
    [job_file] = background.queued()
    assert stat.S_IMODE(job_file.stat().st_mode) == 0o600
    assert stat.S_IMODE(background.queue_dir().stat().st_mode) == 0o700
    assert daemon._work_queue(FakeNLI) == 0            # "zz" is not hex: every attempt fails
    [kept] = background.failed()
    assert stat.S_IMODE(kept.stat().st_mode) == 0o600 and pending_jobs() == [kept]


def test_the_server_keeps_a_job_until_its_check_has_finished(store, memory):
    entered, release = threading.Event(), threading.Event()

    class Slow(FakeNLI):
        def contradiction(self, pairs):
            entered.set()
            release.wait(10)
            return super().contradiction(pairs)

    t, _ = start(factory=Slow)
    try:
        daemon.submit(job_for(memory))
        assert entered.wait(5)
        [job_file] = background.queued()
        job = background.load(job_file)
        assert job["queue"]["attempts"] == 1 and job["content_hex"] == NEW_FACT.encode().hex()
        assert not contradictions()
        release.set()
        assert wait_for(contradictions) and wait_for(lambda: not pending_jobs())
    finally:
        release.set()
        daemon.stop()
        t.join(5)


def test_a_failed_check_is_kept_and_reported_then_runs_after_a_restart(store, memory, fast_retries, monkeypatch,
                                                                       capsys):
    job, broken = job_for(memory), Broken()
    t, _ = start(factory=lambda: broken)
    daemon.submit(job)
    assert wait_for(lambda: background.status()["failed"] == 1)
    daemon.stop()
    t.join(5)
    assert broken.calls == background.MAX_ATTEMPTS and not contradictions()
    state = background.status()
    assert state["queued"] == 0 and state["waiting_model"] == 0
    assert (state["last_failure"]["error"], state["last_failure"]["attempts"]) == ("RuntimeError", 3)
    assert state["last_failure"]["path"] == job["path"]
    [kept] = background.failed()                       # still everything needed to run it again
    assert {k: background.load(kept)[k] for k in job} == job
    [event] = named("background_check_failed")
    assert (event["path"], event["error"], event["attempts"]) == (job["path"], "RuntimeError", 3)
    logged = capsys.readouterr().err
    assert "RuntimeError" in logged
    for private in ("skip-checks", "staging checks"):   # the error quoted memory; no record of it may
        assert private not in logged and private not in json.dumps(named("background_check_failed"))

    spawned = []
    monkeypatch.setattr(daemon, "_spawn", spawned.append)
    assert daemon.retry() == (1, 1) and spawned == [None]
    assert background.status()["failed"] == 0 and background.status()["queued"] == 1
    t, _ = start()                                     # a restart, with no new job to trigger it
    assert wait_for(contradictions) and wait_for(lambda: not pending_jobs())
    daemon.stop()
    t.join(5)
    assert len(contradictions()) == 1


def test_without_a_server_a_failing_check_stops_after_its_attempts(memory, no_server, fast_retries):
    broken = Broken()
    daemon.submit(job_for(memory))
    assert daemon.serve(no_server[0], nli_factory=lambda: broken) == 0
    assert broken.calls == background.MAX_ATTEMPTS
    assert background.status()["failed"] == 1 and background.queued() == [] and not contradictions()
    assert daemon._work_queue(lambda: broken) == 0     # set aside: later workers do not pick it up again
    assert broken.calls == background.MAX_ATTEMPTS and len(named("background_check_failed")) == 1


def test_a_check_that_fails_once_is_retried_and_recorded_once(memory, no_server, fast_retries):
    class Flaky(FakeNLI):
        calls = 0

        def contradiction(self, pairs):
            Flaky.calls += 1
            if Flaky.calls == 1:
                raise OSError("disk hiccup")
            return super().contradiction(pairs)

    daemon.submit(job_for(memory))
    assert daemon._work_queue(Flaky) == 0
    assert Flaky.calls == 2 and len(contradictions()) == 1
    assert pending_jobs() == [] and not named("background_check_failed")


def test_a_retry_whose_job_has_gone_does_not_keep_the_worker_spinning(memory, no_server, fast_retries, monkeypatch):
    note = background.retry_later

    def then_vanish(path, job, error):
        note(path, job, error)
        path.unlink()

    monkeypatch.setattr(background, "retry_later", then_vanish)
    daemon.submit(job_for(memory))
    worker = threading.Thread(target=daemon._work_queue, args=(Broken,), daemon=True)
    worker.start()
    worker.join(5)
    assert not worker.is_alive() and pending_jobs() == []


def test_a_store_error_keeps_its_own_text(memory, no_server, fast_retries, monkeypatch):
    from agentdetox.integrity import StoreLocked

    def locked(*args, **kwargs):
        raise StoreLocked("the store is locked by another process")

    monkeypatch.setattr(engine, "record_contradictions", locked)
    daemon.submit(job_for(memory))
    assert daemon._work_queue(FakeNLI) == 0
    assert background.status()["last_failure"]["error"] == "StoreLocked: the store is locked by another process"


def test_a_check_cut_short_by_a_crash_runs_again(memory, no_server):
    class Dies(FakeNLI):
        def contradiction(self, pairs):
            raise Killed

    daemon.submit(job_for(memory))
    with pytest.raises(Killed):
        daemon._work_queue(Dies)
    [job_file] = pending_jobs()
    job = background.load(job_file)
    assert job["queue"]["attempts"] == 1 and job["content_hex"] == NEW_FACT.encode().hex()
    assert background.status()["queued"] == 1 and background.status()["failed"] == 0
    assert daemon._work_queue(FakeNLI) == 0            # the next worker, with no new job
    assert len(contradictions()) == 1 and pending_jobs() == []


SERVER_THAT_HANGS_IN_A_CHECK = """
import sys, time
from pathlib import Path
from agentdetox import daemon

class Hangs:
    def contradiction(self, pairs):
        Path(sys.argv[1]).write_text("checking")
        time.sleep(120)

daemon.serve(nli_factory=Hangs, idle=120)
"""


@posix_only
def test_a_server_killed_during_a_check_leaves_the_job_for_the_next_server(store, memory):
    if not daemon.SERVER:
        pytest.skip("no model server on this platform yet")
    background.enqueue(job_for(memory))
    marker = store / "checking"
    server = subprocess.Popen([sys.executable, "-c", SERVER_THAT_HANGS_IN_A_CHECK, str(marker)])
    try:
        assert wait_for(marker.exists, timeout=20), "the server never reached the check"
        assert daemon.ping()["pid"] == server.pid
    finally:
        server.kill()                                  # SIGKILL: no handler, no cleanup
        server.wait(10)
    [job_file] = pending_jobs()
    job = background.load(job_file)
    assert job["queue"]["attempts"] == 1 and job["content_hex"] == NEW_FACT.encode().hex()
    assert not contradictions() and daemon.ping() is None
    t, _ = start()                                     # takes over the lock and the stale socket
    assert wait_for(contradictions) and wait_for(lambda: not pending_jobs())
    daemon.stop()
    t.join(5)
    assert len(contradictions()) == 1


def test_a_check_that_keeps_killing_the_worker_is_set_aside(memory, no_server):
    class Dies(FakeNLI):
        def contradiction(self, pairs):
            raise Killed

    daemon.submit(job_for(memory))
    for _ in range(background.MAX_ATTEMPTS):
        with pytest.raises(Killed):
            daemon._work_queue(Dies)
    assert daemon._work_queue(Dies) == 0               # not started a fourth time
    state = background.status()
    assert state["failed"] == 1 and state["queued"] == 0 and state["last_failure"]["error"] == "Interrupted"
    assert named("background_check_failed")[0]["attempts"] == background.MAX_ATTEMPTS


def contradiction_findings():
    with storage.connection() as db:
        return [(r["change_id"], r["flag_id"]) for r in db.execute("SELECT change_id, flag_id FROM findings")]


def test_a_check_delivered_twice_adds_its_finding_once_to_the_version_it_captured(memory, no_server, monkeypatch):
    from agentdetox import ledger

    project, mem = memory
    path = mem / "deploy-new.md"
    monkeypatch.setattr(engine, "_nli_installed", lambda: True)
    engine.after_write([path], project, True)          # the hook: ledger entry, then the durable job
    captured = ledger.entries(str(path))[-1]
    path.write_text("The user prefers short answers.\n", encoding="utf-8")
    engine.after_write([path], project, False)
    later = ledger.entries(str(path))[-1]
    assert len(background.queued()) == 1 and not contradiction_findings()

    finish = background.done

    def killed_before_removal(job_file):
        monkeypatch.setattr(background, "done", finish)
        raise Killed

    monkeypatch.setattr(background, "done", killed_before_removal)
    with pytest.raises(Killed):
        daemon._work_queue(FakeNLI)                    # recorded its result, died before removing the job
    [(change, flag)] = contradiction_findings()
    assert change == captured.id != later.id and len(background.queued()) == 1
    assert daemon._work_queue(FakeNLI) == 0            # so the job is delivered a second time
    assert contradiction_findings() == [(change, flag)] and pending_jobs() == []


def test_without_the_model_checks_wait_and_are_not_failures(memory, no_server, capsys):
    loads = []

    def missing():
        loads.append(1)
        return None

    daemon.submit(job_for(memory))
    daemon.submit(job_for(memory))
    assert daemon._work_queue(missing) == 0
    state = background.status()
    assert (state["waiting_model"], state["queued"], state["failed"]) == (2, 0, 0)
    assert [background.load(p)["queue"]["attempts"] for p in background.queued()] == [0, 0]
    assert not named("background_check_failed") and not contradictions() and loads == [1]
    assert "skip-checks" not in capsys.readouterr().err
    assert daemon._work_queue(missing) == 0            # asking again uses up nothing
    assert [background.load(p)["queue"]["attempts"] for p in background.queued()] == [0, 0]
    assert daemon._work_queue(FakeNLI) == 0            # the model has arrived
    assert len(contradictions()) == 2 and pending_jobs() == []


def test_a_check_with_nothing_to_compare_finishes_without_the_model(memory, no_server):
    project, mem = memory
    daemon.submit({"path": str(mem / "deploy.md"), "project": str(project), "old": OLD_FACT,
                   "content_hex": OLD_FACT.encode().hex()})
    assert daemon._work_queue(lambda: None) == 0
    assert pending_jobs() == [] and background.status()["waiting_model"] == 0


def test_a_server_without_the_model_marks_its_jobs_and_exits(store, memory, monkeypatch):
    if not daemon.SERVER:
        pytest.skip("no model server on this platform yet")
    monkeypatch.setattr(daemon, "_spawn", lambda job_file: None)
    monkeypatch.setattr(daemon, "_local_nli", lambda: None)
    daemon.submit(job_for(memory))
    started = time.monotonic()
    assert daemon.serve() == 0 and time.monotonic() - started < 5      # exits by itself, long before idle
    state = background.status()
    assert (state["waiting_model"], state["failed"]) == (1, 0) and not named("background_check_failed")
    t, _ = start()                                     # once there is a model, the next server runs it
    assert wait_for(contradictions) and wait_for(lambda: not pending_jobs())
    daemon.stop()
    t.join(5)


def test_a_job_left_by_an_earlier_version_is_run(memory, no_server):
    project, mem = memory
    legacy = private_dir(private_dir(daemon.store_dir()) / "pending") / "tmpk3x9wq_a.json"
    legacy.write_text(json.dumps({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""}),
                      encoding="utf-8")
    assert background.status()["queued"] == 1          # visible before any worker has touched it
    assert daemon._work_queue(FakeNLI) == 0
    assert len(contradictions()) == 1 and not legacy.exists() and pending_jobs() == []


def test_a_restarted_server_runs_what_was_left_without_a_new_job(store, memory):
    project, mem = memory
    legacy = private_dir(private_dir(store) / "pending") / "tmpk3x9wq_a.json"
    legacy.write_text(json.dumps({"path": str(mem / "deploy-new.md"), "project": str(project), "old": ""}),
                      encoding="utf-8")
    background.enqueue(job_for(memory))
    t, _ = start()
    assert wait_for(lambda: len(contradictions()) == 2) and wait_for(lambda: not pending_jobs())
    assert not legacy.exists() and daemon.ping()["jobs"] == 2
    daemon.stop()
    t.join(5)


def test_an_unreadable_job_is_set_aside_as_it_is(store, no_server):
    damaged = private_dir(private_dir(store) / "pending") / "tmpdamaged.json"
    damaged.write_bytes(b'{"path": "/x", "proj')
    assert daemon._work_queue(FakeNLI) == 0
    [kept] = pending_jobs()
    assert kept.suffix == ".failed" and kept.read_bytes() == b'{"path": "/x", "proj'
    assert background.status()["last_failure"]["error"] == "InvalidJob"
    assert named("background_check_failed")[0]["error"] == "InvalidJob"
    assert daemon.retry() == (0, 0) and no_server == []                # nothing in it to run again


def test_a_job_queued_while_the_server_shuts_down_runs_on_the_next_start(store, memory, monkeypatch):
    entered, release = threading.Event(), threading.Event()

    class Slow(FakeNLI):
        def contradiction(self, pairs):
            entered.set()
            release.wait(10)
            return super().contradiction(pairs)

    t, _ = start(factory=Slow)
    try:
        daemon.submit(job_for(memory))
        assert entered.wait(5)
        assert daemon.request({"op": "stop"}) == {"ok": True}
        assert wait_for(lambda: daemon.ping() is None)                 # stopping: it answers nobody now
        spawned = []
        monkeypatch.setattr(daemon, "_spawn", spawned.append)
        daemon.submit(job_for(memory))                                 # no acknowledgement, so a new server is started
        assert len(background.queued()) == 2 and spawned == [str(background.queued()[1])]
    finally:
        release.set()
        t.join(5)
    assert not t.is_alive() and len(contradictions()) == 1             # it finished the job it was on, only
    assert [str(p) for p in background.queued()] == spawned
    t, _ = start()
    assert wait_for(lambda: len(contradictions()) == 2) and wait_for(lambda: not pending_jobs())
    daemon.stop()
    t.join(5)


def test_a_stopping_server_does_not_acknowledge_a_wake_up():
    class Quiet:
        def shutdown(self):
            pass

    state = daemon._State(Quiet(), FakeNLI, 30.0)
    assert state.wake_up() is True
    state.stop()
    assert state.wake_up() is False


@posix_only
def test_a_wake_up_reaching_a_server_that_is_stopping_gets_no_acknowledgement(server):
    early = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    early.settimeout(5)
    try:
        early.connect(str(daemon.socket_path()))
        assert daemon.ping()                           # accepted in order, so `early` has its handler now
        assert daemon.request({"op": "stop"}) == {"ok": True}
        early.sendall((json.dumps({"code": daemon.code_id(), "op": "wake"}) + "\n").encode())
        assert json.loads(early.makefile().readline()) == {"ok": False}
    finally:
        early.close()


def test_a_job_saved_as_the_idle_server_exits_is_still_run(store, memory):
    t, _ = start(idle=0.4)
    background.enqueue(job_for(memory))                # saved, but its wake-up never arrives
    t.join(5)
    assert not t.is_alive() and len(contradictions()) == 1 and pending_jobs() == []


def test_a_full_queue_turns_new_jobs_away_visibly(store, no_server, monkeypatch):
    monkeypatch.setattr(background, "QUEUE_LIMIT", 2)
    for _ in range(3):
        daemon.submit({"path": "/x", "project": "/p", "old": "secret memory"})
    assert len(background.queued()) == 2 and len(no_server) == 2
    [error] = named("hook_error")
    assert error["stage"] == "background-queue" and error["error"].startswith("QueueFull")
    assert "secret memory" not in json.dumps(error)
    first, second = background.queued()
    background.fail(first, background.load(first), "RuntimeError")     # a failed job still holds its copy
    daemon.submit({"path": "/x", "project": "/p", "old": "secret memory"})
    assert background.queued() == [second] and len(named("hook_error")) == 2


def test_checks_that_waited_past_the_limit_expire_with_a_record(memory, no_server, fast_retries):
    daemon.submit(job_for(memory))
    [job_file] = background.queued()
    queued_long_ago = time.time_ns() - int((background.KEEP_SECONDS + 60) * 1e9)
    job_file.rename(job_file.with_name(f"{queued_long_ago:020d}-0a0b0c0d.json"))
    assert background.status()["stalled"] == 1
    daemon.submit({"path": "/x", "project": "/p", "old": "", "content_hex": "zz"})
    assert daemon._work_queue(FakeNLI) == 0
    assert not contradictions() and [e["count"] for e in named("background_check_expired")] == [1]
    [kept] = pending_jobs()                            # the failed one stays, for now
    long_ago = time.time() - background.KEEP_SECONDS - 60
    os.utime(kept, (long_ago, long_ago))
    assert daemon._work_queue(FakeNLI) == 0
    assert pending_jobs() == [] and len(named("background_check_expired")) == 1


def test_daemon_retry_command(memory, no_server, fast_retries, capsys):
    assert main(["daemon", "retry"]) == 0
    assert "no background checks" in capsys.readouterr().out and no_server == []
    broken = Broken()
    daemon.submit(job_for(memory))
    assert daemon._work_queue(lambda: broken) == 0 and background.status()["failed"] == 1
    no_server.clear()
    assert main(["daemon", "retry"]) == 0
    assert "1 failed check(s) queued again" in capsys.readouterr().out and no_server == [None]
    assert daemon.serve(nli_factory=FakeNLI) == 0
    assert len(contradictions()) == 1 and pending_jobs() == []
