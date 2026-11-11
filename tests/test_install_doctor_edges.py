"""Installing, checking health and recovering at the edges: a linked settings file, a hook
command written another way, a recovery stopped half-way, a daemon handed the wrong thing."""

import json
import os
import shutil
import stat
import sys
import tempfile
import time
from pathlib import Path

import pytest

from agentdetox import __version__, background, cli, daemon, engine, install, ledger, review, safefs
from agentdetox.cli import main
from agentdetox.integrity import StoreError, store_dir

posix = pytest.mark.skipif(os.name != "posix", reason="links and permission bits")


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    (home / ".claude").mkdir(parents=True)
    project.mkdir()
    monkeypatch.setenv("AGENTDETOX_USER_HOME", str(home))
    monkeypatch.setenv("AGENTDETOX_HOME", str(tmp_path / "store"))
    return home, project


def run(capsys, *args):
    code = main(list(args))
    out = capsys.readouterr()
    return code, out.out + out.err


def doctor(capsys, project):
    return run(capsys, "doctor", "--project", str(project))


def own_hooks(command=None):
    return install.claude_code_settings({}, command or install.hook_command("claude-code"))["hooks"]


# Install -------------------------------------------------------------------------------

@posix
def test_linked_settings_file_is_written_where_the_link_points(env, capsys):
    home, project = env
    dotfiles = home / "dotfiles"
    dotfiles.mkdir()
    real = dotfiles / "claude-settings.json"
    real.write_text(json.dumps({"model": "opus"}, indent=2) + "\n", encoding="utf-8")
    link = home / ".claude" / "settings.json"
    link.symlink_to(real)
    assert run(capsys, "install", "claude-code", "--project", str(project), "--apply")[0] == 0
    assert link.is_symlink() and os.path.samefile(link, real)
    written = json.loads(real.read_text(encoding="utf-8"))
    assert written["model"] == "opus" and "PreToolUse" in written["hooks"]
    assert run(capsys, "uninstall", "claude-code", "--project", str(project))[0] == 0
    assert link.is_symlink() and "hooks" not in json.loads(real.read_text(encoding="utf-8"))


@pytest.mark.parametrize("layout, first_level", [
    (lambda data: json.dumps(data, indent=4).replace("\n", "\r\n") + "\r\n", '\r\n    "hooks"'),
    (lambda data: json.dumps(data, indent="\t") + "\n", '\n\t"hooks"'),
    (lambda data: json.dumps(data, indent=2), '\n  "hooks"'),
    (lambda data: json.dumps(data) + "\n", '\n  "hooks"'),
])
def test_install_and_uninstall_keep_the_files_layout(layout, first_level, env, capsys):
    home, project = env
    settings = home / ".claude" / "settings.json"
    original = layout({"model": "opus", "permissions": {"allow": ["Bash(npm test)"]}})
    settings.write_bytes(original.encode())
    assert run(capsys, "install", "claude-code", "--project", str(project), "--apply")[0] == 0
    installed = settings.read_bytes().decode()
    assert ("\r\n" in installed) == ("\r\n" in original) and installed.endswith("\n") == original.endswith("\n")
    assert first_level in installed
    assert run(capsys, "uninstall", "claude-code", "--project", str(project))[0] == 0
    if "\n" in original.strip():
        assert settings.read_bytes().decode() == original      # back to the very bytes


def test_installing_what_is_already_there_writes_and_backs_up_nothing(env, capsys):
    home, project = env
    settings = home / ".claude" / "settings.json"
    assert run(capsys, "install", "claude-code", "--project", str(project), "--apply")[0] == 0
    before = settings.read_bytes()
    code, out = run(capsys, "install", "claude-code", "--project", str(project), "--apply")
    assert code == 0 and "already in" in out and "nothing was changed" in out
    assert settings.read_bytes() == before
    assert not list(settings.parent.glob("*.agentdetox-backup-*"))


def test_settings_changed_meanwhile_are_not_overwritten(env):
    home, _ = env
    settings = home / ".claude" / "settings.json"
    settings.write_text('{"model": "opus"}\n', encoding="utf-8")
    seen = settings.read_bytes()
    settings.write_text('{"model": "sonnet"}\n', encoding="utf-8")       # Claude Code saved its settings meanwhile
    with pytest.raises(ValueError, match="changed while"):
        install._write_with_backup(settings, '{"model": "opus", "hooks": {}}\n', unchanged_since=seen)
    assert settings.read_text(encoding="utf-8") == '{"model": "sonnet"}\n'
    assert [p.name for p in settings.parent.iterdir()] == ["settings.json"]


def test_store_failure_after_writing_says_the_hooks_were_added(env, capsys, monkeypatch):
    home, project = env

    def fail(*args, **kwargs):
        raise StoreError("database is locked")

    monkeypatch.setattr(cli.session, "check", fail)
    code, out = run(capsys, "install", "claude-code", "--project", str(project), "--apply")
    assert code == 2 and "hooks were added to" in out and "database is locked" in out
    assert "PreToolUse" in json.loads((home / ".claude" / "settings.json").read_text(encoding="utf-8"))["hooks"]


# Doctor --------------------------------------------------------------------------------

def register(path, hooks):
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps({"hooks": hooks}), encoding="utf-8")


def test_hooks_without_the_write_check_fail(env, capsys):
    home, project = env
    hooks = own_hooks()
    del hooks["PreToolUse"], hooks["PostToolUseFailure"]
    register(home / ".claude" / "settings.json", hooks)
    code, out = doctor(capsys, project)
    assert code == 1 and "missing PreToolUse" in out and "writes are not checked before they happen" in out


def test_hooks_without_a_later_addition_only_warn(env, capsys):
    home, project = env
    hooks = own_hooks()
    del hooks["PostToolUseFailure"]
    register(home / ".claude" / "settings.json", hooks)
    code, out = doctor(capsys, project)
    assert code == 0 and "older version (missing PostToolUseFailure)" in out


def test_hook_run_through_the_interpreter_is_asked_for_its_own_version(env, capsys):
    home, project = env
    command = f'"{sys.executable}" -I -m agentdetox hook claude-code'
    register(home / ".claude" / "settings.json", own_hooks(command))
    code, out = doctor(capsys, project)
    assert code == 0 and "hooks installed and current" in out, out


@posix
def test_bare_command_is_looked_up_on_the_path(env, capsys, monkeypatch, tmp_path):
    home, project = env
    bin_dir = tmp_path / "bin"
    bin_dir.mkdir()
    exe = bin_dir / "agentdetox"
    exe.write_text(f"#!/bin/sh\necho agentdetox {__version__}\n", encoding="utf-8")
    exe.chmod(0o755)
    monkeypatch.setenv("PATH", f"{bin_dir}{os.pathsep}{os.environ['PATH']}")
    register(home / ".claude" / "settings.json", own_hooks("agentdetox hook claude-code"))
    code, out = doctor(capsys, project)
    assert code == 0 and "hooks installed and current" in out, out


def test_hook_command_that_cannot_be_split_is_a_failure_not_a_traceback(env, capsys):
    home, project = env
    register(home / ".claude" / "settings.json", own_hooks('/x/agentdetox hook claude-code # "do not remove'))
    code, out = doctor(capsys, project)
    assert code == 1 and "cannot be read" in out
    assert run(capsys, "status", "--project", str(project))[0] == 0


def test_hooks_in_local_settings_are_found_and_counted(env, capsys):
    home, project = env
    command = f'"{sys.executable}" -I -m agentdetox hook claude-code'
    register(project / ".claude" / "settings.local.json", own_hooks(command))
    code, out = doctor(capsys, project)
    assert code == 0 and "settings.local.json" in out and "hooks not installed" not in out
    register(home / ".claude" / "settings.json", own_hooks(command))
    code, out = doctor(capsys, project)
    assert "registered in 2 settings files" in out and "more than once" in out


def test_a_broken_claude_hook_is_not_passed_off_as_not_set_up(env, capsys):
    home, project = env
    shutil.rmtree(home / ".claude")
    command = f'"{sys.executable}" -I -m agentdetox hook codex'
    (home / ".codex").mkdir()
    (home / ".codex" / "hooks.json").write_text(json.dumps({"hooks": {"SessionStart": [{"hooks": [
        {"type": "command", "command": command}]}]}}), encoding="utf-8")
    code, out = doctor(capsys, project)
    assert "not set up on this machine" in out
    register(project / ".claude" / "settings.json", own_hooks("/nonexistent/agentdetox hook claude-code"))
    code, out = doctor(capsys, project)
    assert code == 1 and "does not exist" in out and "not set up on this machine" not in out


# Recovery ------------------------------------------------------------------------------

@pytest.fixture
def changed(env):
    home, project = env
    script = project / ".claude" / "hooks" / "guard.sh"
    script.parent.mkdir(parents=True)
    script.write_text("#!/bin/sh\necho ok\n", encoding="utf-8")
    script.chmod(0o755)
    return project, script


@posix
def test_restore_keeps_the_files_permissions_when_none_were_recorded(changed):
    project, script = changed
    ledger.record(script, "inspected", None, script.read_bytes())          # found, never checkpointed
    script.write_text("#!/bin/sh\necho changed\n", encoding="utf-8")
    engine.after_write([script], project, False)
    entry = ledger.entries(str(script))[-1]
    assert "before_mode" not in json.dumps(entry.__dict__) or entry.__dict__.get("before_mode") is None
    review.restore(f"C{entry.id}", True)
    assert script.read_text(encoding="utf-8") == "#!/bin/sh\necho ok\n"
    assert stat.S_IMODE(script.stat().st_mode) == 0o755


@posix
def test_what_a_stopped_recovery_left_beside_the_file_is_swept(changed):
    _, script = changed
    stale = script.with_name(safefs.TEMP_PREFIX + "aaaa")
    fresh = script.with_name(safefs.TEMP_PREFIX + "bbbb")
    other = script.with_name("notes.txt")
    for path in (stale, fresh, other):
        path.write_text("x", encoding="utf-8")
    old = time.time() - safefs.STALE_TEMP - 60
    os.utime(stale, (old, old))
    os.utime(other, (old, old))
    with safefs.pinned(script) as pin:
        assert pin.sweep() == 1
    assert not stale.exists() and fresh.exists() and other.exists()


def test_unfinished_recovery_names_a_backup_only_if_there_is_one(env):
    operation = {"id": "abc", "backup": None}
    assert "no backup was written" in review.operation_backup(operation)
    written = store_dir() / "quarantine" / "abc" / "content"
    written.parent.mkdir(parents=True)
    written.write_bytes(b"kept")
    assert review.operation_backup(operation) == f"backup: {written}"
    assert "no backup was written" in review.operation_backup({"id": "abc", "backup": str(written) + ".gone"})


# Daemon --------------------------------------------------------------------------------

@posix
def test_socket_path_counts_bytes_and_distrusts_a_linked_temp_folder(tmp_path, monkeypatch):
    if not daemon.SERVER:
        pytest.skip("no model server on this platform")
    short = Path(tempfile.mkdtemp(prefix="adx-", dir="/tmp"))
    try:
        store = short / ("\u5b58" * 30)             # 30 characters, 90 bytes
        monkeypatch.setenv("AGENTDETOX_HOME", str(store))
        temp = short / "t"
        temp.mkdir()
        monkeypatch.setattr(tempfile, "tempdir", str(temp))
        assert len(str(store / "nli.sock")) <= 100 < len(os.fsencode(store / "nli.sock"))
        path = daemon.socket_path()
        assert path.parent == temp / f"agentdetox-{os.getuid()}" and len(os.fsencode(path)) <= 100
        assert stat.S_IMODE(path.parent.stat().st_mode) == 0o700
        shutil.rmtree(path.parent)
        elsewhere = short / "elsewhere"
        elsewhere.mkdir(mode=0o755)
        path.parent.symlink_to(elsewhere, target_is_directory=True)
        with pytest.raises(PermissionError):
            daemon.socket_path()
        assert stat.S_IMODE(elsewhere.stat().st_mode) == 0o755
    finally:
        shutil.rmtree(short, ignore_errors=True)


def test_only_a_job_file_inside_the_store_is_taken_into_the_queue(env, tmp_path):
    outside = tmp_path / "id_rsa"
    outside.write_text("secret", encoding="utf-8")
    background.adopt(outside)
    assert outside.read_text(encoding="utf-8") == "secret"
    store_dir().mkdir(parents=True, exist_ok=True)
    own = store_dir() / "allowlist.json"
    own.write_text(json.dumps({"version": 1, "allowed": {}}), encoding="utf-8")
    background.adopt(own)
    assert own.exists() and not background.queued()
    job = store_dir() / "job.json"
    job.write_text(json.dumps({"path": str(tmp_path / "a.md"), "project": str(tmp_path), "old": ""}), encoding="utf-8")
    background.adopt(job)
    assert not job.exists() and len(background.queued()) == 1


def test_the_internal_daemon_command_needs_approval(env):
    _, project = env
    assert {s.check for s in engine.check_command("agentdetox _daemon --job ~/.ssh/id_rsa", project)} == {engine.OWN_STATE}
    assert engine.check_command("agentdetox daemon status", project) == []


def test_a_client_that_sends_nothing_times_out():
    assert daemon._Handler.timeout == daemon.REQUEST_TIMEOUT and 0 < daemon.REQUEST_TIMEOUT <= 60
