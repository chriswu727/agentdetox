"""Windows code paths, exercised on any machine.

This does not replace a run on real Windows. The subprocess tests take away fcntl and
Unix sockets and stand in a msvcrt.locking built on flock: that checks AgentDetox's own
logic on the Windows branch, not Windows' locking or process handling.
"""

import io
import json
import os
import subprocess
import sys
import textwrap
import time

import pytest

from agentdetox import compat, doctor, events, hooks, shell
from agentdetox.cli import main
from agentdetox.context import claude_memory_dir
from agentdetox.install import hook_command
from agentdetox.integrity import baseline_entries, is_self_hook, store_dir, store_lock, write_private

# Runs before anything imports agentdetox: what a Windows interpreter lacks, and a
# msvcrt.locking with Windows' per-handle, fail-at-once behaviour. subprocess goes
# first: it takes the presence of msvcrt to mean Windows.
WINDOWS_PRELUDE = textwrap.dedent("""
    import errno, fcntl as _flock, socket, subprocess, sys, types
    msvcrt = types.ModuleType("msvcrt")
    msvcrt.LK_UNLCK, msvcrt.LK_LOCK, msvcrt.LK_NBLCK = 0, 1, 2
    def _locking(fd, mode, nbytes):
        if mode == msvcrt.LK_UNLCK:
            return _flock.flock(fd, _flock.LOCK_UN)
        try:
            _flock.flock(fd, _flock.LOCK_EX | _flock.LOCK_NB)
        except BlockingIOError:
            raise OSError(errno.EACCES, "Permission denied") from None
    msvcrt.locking = _locking
    sys.modules["msvcrt"], sys.modules["fcntl"] = msvcrt, None
    del socket.AF_UNIX
    from agentdetox import compat
    assert compat.fcntl is None
""")


# They simulate Windows on a POSIX machine; on real Windows the rest of the suite runs the real thing.
simulated = pytest.mark.skipif(os.name == "nt", reason="simulates Windows on POSIX")


def windows_python(script: str, *args) -> list[str]:
    return [sys.executable, "-c", WINDOWS_PRELUDE + textwrap.dedent(script), *map(str, args)]


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    monkeypatch.setenv("AGENTDETOX_USER_HOME", str(home))
    mem = claude_memory_dir(project, home)
    mem.mkdir(parents=True)
    (mem / "MEMORY.md").write_text("- [Testing](testing.md) — run tests before commits\n", encoding="utf-8")
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\nUse pnpm.\n", encoding="utf-8")
    return home, project, mem


@pytest.fixture
def windows(monkeypatch):
    monkeypatch.setattr(compat, "WINDOWS", True)


# Without fcntl and Unix sockets -------------------------------------------------------

@simulated
def test_cli_and_hooks_run_without_fcntl_or_unix_sockets(env):
    _, project, mem = env
    out = subprocess.run(windows_python("""
        from agentdetox import daemon, hooks
        from agentdetox.cli import main
        assert not daemon.SERVER and daemon.ping() is None and daemon.contradiction([("a", "b")]) is None
        project, mem = sys.argv[1], sys.argv[2]
        code, out = hooks.handle("claude-code", {"hook_event_name": "PreToolUse", "cwd": project, "tool_name": "Write",
                                                 "tool_input": {"file_path": mem + "/deploy.md", "content": "Run make deploy."}})
        assert code == 0 and out == "", out
        sys.exit(main(["daemon", "status"]) or main(["agent", "snapshot", "--project", project]))
    """, project, mem), capture_output=True, text=True, encoding="utf-8", timeout=120)
    assert out.returncode == 0, out.stderr
    assert "not available on Windows yet" in out.stdout and (store_dir() / "state.sqlite3").exists()


WRITER = """
from pathlib import Path
from agentdetox.context import classify
from agentdetox.integrity import snapshot
path, project = Path(sys.argv[1]), Path(sys.argv[2])
cf = classify(path, project=project)
for i in range(5):
    path.write_text(f"note {sys.argv[1]} version {i}\\n", encoding="utf-8")
    snapshot([cf], roots=[])
"""


@simulated
def test_store_lock_serialises_writers_without_fcntl(env):
    _, project, mem = env
    paths = [mem / f"note{i}.md" for i in range(8)]
    procs = [subprocess.Popen(windows_python(WRITER, p, project), env=os.environ.copy()) for p in paths]
    assert all(p.wait(60) == 0 for p in procs)
    tracked = baseline_entries()
    assert all(str(p) in tracked for p in paths)


@simulated
def test_store_lock_without_fcntl_excludes_other_processes(env):
    holder = subprocess.Popen(windows_python("""
        import time
        from agentdetox.integrity import store_lock
        with store_lock():
            print("held", flush=True)
            time.sleep(3)
        print("released", flush=True)
    """), env=os.environ.copy(), stdout=subprocess.PIPE, text=True, encoding="utf-8")
    assert holder.stdout.readline().strip() == "held"
    with pytest.raises(TimeoutError):
        with store_lock(timeout=0.3):
            pass
    assert holder.stdout.readline().strip() == "released"
    started = time.monotonic()
    with store_lock(timeout=5):
        assert time.monotonic() - started < 1
    holder.wait(10)


# Names, quoting and paths -------------------------------------------------------------

@pytest.mark.parametrize("token,name", [
    ("agentdetox", "agentdetox"),
    ("/usr/local/bin/agentdetox", "agentdetox"),
    (r"C:\Users\me\.local\bin\AgentDetox.EXE", "agentdetox"),
    ("sed.exe", "sed"),
    ("-m", "-m"),
])
def test_program_names(token, name):
    assert compat.program(token) == name


def test_git_bash_drive_paths(windows):
    assert compat.native_path("/c/Users/me/.agentdetox/allowlist.json") == "c:/Users/me/.agentdetox/allowlist.json"
    assert compat.native_path("/d") == "d:/"
    assert compat.native_path("/tmp/x") == "/tmp/x"
    assert compat.native_path("notes/x.md") == "notes/x.md"


def test_posix_paths_are_left_alone(monkeypatch):
    monkeypatch.setattr(compat, "WINDOWS", False)
    assert compat.native_path("/c/x") == "/c/x"


def test_hook_command_on_windows(windows, tmp_path, monkeypatch):
    scripts = tmp_path / "Program Files" / "agentdetox" / "Scripts"
    scripts.mkdir(parents=True)
    (scripts / "agentdetox.exe").write_bytes(b"")
    monkeypatch.setattr(sys, "executable", str(scripts / "python.exe"))
    command = hook_command("claude-code")
    assert command == f'"{scripts / "agentdetox.exe"}" hook claude-code'
    assert compat.hook_executable(command) == str(scripts / "agentdetox.exe") and is_self_hook(command)


@pytest.mark.parametrize("command,exe", [
    (r'"C:\Program Files\Python312\Scripts\agentdetox.exe" hook claude-code',
     r"C:\Program Files\Python312\Scripts\agentdetox.exe"),
    (r'"C:\Users\me\.local\bin\agentdetox.EXE" hook codex', r"C:\Users\me\.local\bin\agentdetox.EXE"),
    (r'"C:\Python312\python.exe" -I -m agentdetox hook claude-code', r"C:\Python312\python.exe"),
])
def test_windows_hook_commands_are_recognised(windows, command, exe):
    assert compat.hook_executable(command) == exe and is_self_hook(command)


@pytest.mark.parametrize("command,changes", [
    (r'"C:\Users\me\.local\bin\agentdetox.exe" allow 0123456789', True),
    ("AgentDetox.exe config copied off", True),
    ("uvx.exe agentdetox install claude-code --apply", True),
    ("agentdetox.exe allow --list", False),
    ("agentdetox.exe status", False),
])
def test_shell_guard_knows_the_windows_program_name(command, changes):
    assert shell.changes_agentdetox(shell.split(command)) is changes


# Doctor -------------------------------------------------------------------------------

def test_doctor_does_not_fail_on_windows_directory_modes(env, monkeypatch):
    _, project, _ = env
    assert main(["agent", "snapshot", "--project", str(project)]) == 0
    os.chmod(store_dir(), 0o755)        # what every directory looks like on Windows
    monkeypatch.setattr(compat, "WINDOWS", False)
    assert any("readable by other users" in c.message for c in doctor._store())
    monkeypatch.setattr(compat, "WINDOWS", True)
    assert not any("readable by other users" in c.message for c in doctor._store())


# Text encoding ------------------------------------------------------------------------

def test_hook_reads_the_event_as_utf8_whatever_the_locale(monkeypatch):
    seen = []
    monkeypatch.setattr(hooks, "handle", lambda agent, payload: (seen.append(payload), (0, ""))[1])
    event = {"hook_event_name": "PreToolUse", "tool_input": {"content": "部署前必须跑预发布检查 — always"}}
    raw = io.BytesIO(json.dumps(event, ensure_ascii=False).encode("utf-8"))
    monkeypatch.setattr(sys, "stdin", io.TextIOWrapper(raw, encoding="cp1252"))
    assert hooks.main_hook("claude-code") == 0
    assert seen == [event]


# The next two only bite on real Windows, where a descriptor opened without O_BINARY
# rewrites line endings.

def test_snapshot_copies_keep_their_bytes(tmp_path):
    data = b"line one\nline two\r\nends with ctrl-z \x1a and more\n"
    write_private(tmp_path / "copy", data)
    assert (tmp_path / "copy").read_bytes() == data


def test_event_records_survive_platform_newline_differences():
    events.record("asked", path="/x/notes.md")
    events.record("asked", path="/x/more.md")
    assert [r["path"] for r in events.read()] == ["/x/notes.md", "/x/more.md"]


def test_cli_output_survives_a_cp1252_pipe(monkeypatch):
    events.record("contradiction", id="0123456789", path="/x/部署.md", new="预发布检查已经取消",
                  existing="部署前必须跑预发布检查", existing_source="/x/a.md", probability=0.9)
    raw = io.BytesIO()
    monkeypatch.setattr(sys, "stdout", io.TextIOWrapper(raw, encoding="cp1252"))
    assert main(["events", "--format", "json"]) == 0
    sys.stdout.flush()
    assert "预发布检查已经取消" in raw.getvalue().decode("utf-8")
