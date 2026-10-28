import json
import os
import shutil
import socket
import stat
import tempfile
import threading
import time
from pathlib import Path

import pytest

from agentdetox import daemon, events, hooks
from agentdetox.context import claude_memory_dir

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
    assert hooks._ServerNLI().contradiction([("skip it", "do it")]) == [0.97]


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
    return sorted((daemon.store_dir() / "pending").glob("*"))


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

    monkeypatch.setattr(hooks, "NLI", LocalNLI)
    assert isinstance(hooks._nli(), LocalNLI)


@posix_only
def test_stale_socket_file_is_replaced(store):
    stale = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    stale.bind(str(daemon.socket_path()))
    stale.close()                      # a crashed server leaves its socket file behind
    t, _ = start()
    assert daemon.ping()["pid"]
    daemon.stop()
    t.join(5)
