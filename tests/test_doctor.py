import json
import os

import pytest

from agentdetox import __version__, compat
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
