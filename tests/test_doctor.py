import json
import os
import time

import pytest

from agentdetox import __version__, background, compat
from agentdetox.cli import main


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    (home / ".claude").mkdir(parents=True)
    project.mkdir()
    monkeypatch.setenv("AGENTDETOX_USER_HOME", str(home))
    monkeypatch.setenv("AGENTDETOX_HOME", str(tmp_path / "store"))
    return home, project


def doctor(capsys, project):
    code = main(["doctor", "--project", str(project)])
    return code, capsys.readouterr().out


def test_not_installed_fails(env, capsys):
    _, project = env
    code, out = doctor(capsys, project)
    assert code == 1 and "hooks not installed" in out


def test_installed_and_current(env, capsys, monkeypatch):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    capsys.readouterr()
    code, out = doctor(capsys, project)
    assert code == 0, out
    assert "hooks installed and current" in out and "file(s) tracked" in out
    from agentdetox import storage
    assert f"store format {storage.VERSION}" in out


def test_run_from_the_home_folder_reports_the_settings_once(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    capsys.readouterr()
    code, out = doctor(capsys, home)
    assert code == 0, out
    assert out.count("hooks installed and current") == 1


def test_user_hooks_around_ours_do_not_look_outdated(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    settings = home / ".claude/settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["hooks"]["PreToolUse"].append({"matcher": "Bash", "hooks": [{"type": "command", "command": "~/bin/audit.sh"}]})
    settings.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    assert "hooks installed and current" in doctor(capsys, project)[1]


def test_outdated_matcher_warns(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    settings = home / ".claude/settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    data["hooks"]["PreToolUse"][0]["matcher"] = "Write|Edit"        # what an older release installed
    settings.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    code, out = doctor(capsys, project)
    assert code == 0 and "older version" in out


def test_missing_hook_executable_fails(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    settings = home / ".claude/settings.json"
    data = json.loads(settings.read_text(encoding="utf-8"))
    for groups in data["hooks"].values():
        for group in groups:
            for hook in group["hooks"]:
                exe = compat.hook_executable(hook["command"])
                hook["command"] = hook["command"].replace(exe, "/nonexistent/agentdetox")
    settings.write_text(json.dumps(data), encoding="utf-8")
    capsys.readouterr()
    code, out = doctor(capsys, project)
    assert code == 1 and "does not exist" in out


def test_doctor_is_read_only(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    before = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    doctor(capsys, project)
    assert before == {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}


@pytest.mark.skipif(os.name != "posix", reason="stub executable is a shell script")
def test_the_plugin_counts_as_installed_and_is_not_doubled(env, capsys):
    home, project = env
    exe = home / ".local/bin/agentdetox"
    exe.parent.mkdir(parents=True)
    exe.write_text(f"#!/bin/sh\necho agentdetox {__version__}\n", encoding="utf-8")
    exe.chmod(0o755)
    settings = home / ".claude/settings.json"
    settings.write_text(json.dumps({"enabledPlugins": {"agentdetox@agentdetox": True}}), encoding="utf-8")
    code, out = doctor(capsys, project)
    assert code == 0 and "hooks run by the agentdetox@agentdetox plugin" in out, out
    assert main(["install", "claude-code", "--project", str(project), "--apply"]) == 0
    assert "already runs AgentDetox's hooks" in capsys.readouterr().out
    assert "hooks" not in json.loads(settings.read_text(encoding="utf-8"))
    settings.write_text(json.dumps({"enabledPlugins": {"agentdetox@agentdetox": True},
                                    "hooks": {"SessionStart": [{"hooks": [{"type": "command",
                                                                          "command": f"{exe} hook claude-code"}]}]}}),
                        encoding="utf-8")
    assert "every check runs twice" in doctor(capsys, project)[1]
    (project / ".claude").mkdir()
    (project / ".claude/settings.local.json").write_text(
        json.dumps({"enabledPlugins": {"agentdetox@agentdetox": False}}), encoding="utf-8")
    assert "agentdetox@agentdetox" not in doctor(capsys, project)[1]   # disabled for this project


def test_a_store_not_yet_upgraded_shows_its_own_format(env, capsys):
    import sqlite3

    from agentdetox import storage
    _, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    with sqlite3.connect(storage.path()) as db:
        db.execute("PRAGMA user_version=2")
    capsys.readouterr()
    _, out = doctor(capsys, project)
    assert "store format 2)" in out and f"upgrades to {storage.VERSION}" in out


# Background contradiction checks ------------------------------------------------------

def queue_job(home, project):
    return background.enqueue({"path": str(home / ".claude/projects/p/memory/deploy.md"), "project": str(project),
                               "old": "the undisclosed old text", "content_hex": b"the undisclosed new text".hex()})


def installed_doctor(capsys, project):
    main(["install", "claude-code", "--project", str(project), "--apply"])
    capsys.readouterr()
    code, out = doctor(capsys, project)
    return code, out, [line for line in out.splitlines() if "background contradiction check" in line]


def test_nothing_queued_says_nothing_and_creates_nothing(env, capsys):
    _, project = env
    code, _, lines = installed_doctor(capsys, project)
    assert code == 0 and lines == [] and not background.queue_dir().exists()


def test_a_failed_background_check_fails_doctor_and_says_what_to_do(env, capsys):
    home, project = env
    path = queue_job(home, project)
    job = background.load(path)
    for _ in range(background.MAX_ATTEMPTS):
        background.claim(path, job)
    background.fail(path, job, "RuntimeError")
    code, out, [line] = installed_doctor(capsys, project)
    assert code == 1 and line.startswith("FAIL 1 background contradiction check(s) failed")
    assert "RuntimeError" in line and "after 3 attempt(s)" in line
    assert f"~{os.sep}.claude{os.sep}projects{os.sep}p{os.sep}memory{os.sep}deploy.md" in line
    assert "daemon.log" in line and "`agentdetox daemon retry`" in line
    assert "undisclosed" not in out and b"the undisclosed new text".hex() not in out


def test_checks_waiting_for_the_model_warn_without_failing(env, capsys):
    home, project = env
    path = queue_job(home, project)
    job = background.load(path)
    background.claim(path, job)
    background.wait_for_model(path, job)
    code, _, [line] = installed_doctor(capsys, project)
    assert code == 0 and line.startswith("WARN 1 background contradiction check(s) are waiting for the contradiction model")
    assert "`agentdetox fetch-models`" in line and "failed" not in line


def test_a_queue_nobody_is_working_on_warns(env, capsys):
    home, project = env
    fresh = queue_job(home, project)
    code, _, [line] = installed_doctor(capsys, project)
    assert code == 0 and line == "OK   1 background contradiction check(s) queued"
    queued_long_ago = time.time_ns() - int((background.STALLED_AFTER + 60) * 1e9)
    fresh.rename(fresh.with_name(f"{queued_long_ago:020d}-0a0b0c0d.json"))
    queue_job(home, project)
    code, _, lines = installed_doctor(capsys, project)
    assert code == 0 and len(lines) == 2
    assert lines[0].startswith("WARN 1 background contradiction check(s) have waited more than 10 min")
    assert "`agentdetox daemon retry`" in lines[0] and "daemon.log" in lines[0]
    assert lines[1] == "OK   1 background contradiction check(s) queued"
