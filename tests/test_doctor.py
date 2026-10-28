import json

import pytest

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
    text = settings.read_text(encoding="utf-8")
    exe = json.loads(text)["hooks"]["SessionStart"][0]["hooks"][0]["command"].split(" hook ")[0].strip("'")
    settings.write_text(text.replace(exe, "/nonexistent/agentdetox"), encoding="utf-8")
    capsys.readouterr()
    code, out = doctor(capsys, project)
    assert code == 1 and "does not exist" in out


def test_doctor_is_read_only(env, capsys):
    home, project = env
    main(["install", "claude-code", "--project", str(project), "--apply"])
    before = {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
    doctor(capsys, project)
    assert before == {p: p.read_bytes() for p in home.rglob("*") if p.is_file()}
