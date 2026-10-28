"""The Claude Code plugin: kept in step with the package, and its hook script finds
AgentDetox the way the README says."""

import json
import os
import re
import subprocess
from pathlib import Path

import pytest

from agentdetox import __version__
from agentdetox.install import claude_code_settings

ROOT = Path(__file__).resolve().parent.parent
PLUGIN = ROOT / "plugins" / "agentdetox"
SCRIPT = PLUGIN / "scripts" / "hook"
posix_only = pytest.mark.skipif(os.name != "posix", reason="the hook script is POSIX sh")


def _matchers(hooks: dict) -> dict:
    return {event: [g.get("matcher") for g in groups] for event, groups in hooks.items()}


def test_plugin_matches_the_package():
    manifest = json.loads((PLUGIN / ".claude-plugin/plugin.json").read_text(encoding="utf-8"))
    pinned = re.search(r"^VERSION=(\S+)$", SCRIPT.read_text(encoding="utf-8"), re.M).group(1)
    assert manifest["version"] == pinned == __version__
    hooks = json.loads((PLUGIN / "hooks/hooks.json").read_text(encoding="utf-8"))["hooks"]
    assert _matchers(hooks) == _matchers(claude_code_settings({}, "x")["hooks"])
    market = json.loads((ROOT / ".claude-plugin/marketplace.json").read_text(encoding="utf-8"))
    [entry] = market["plugins"]
    assert entry["name"] == manifest["name"] and (ROOT / entry["source"]).resolve() == PLUGIN


def run(tmp_path, event, path_dirs=()):
    env = {"HOME": str(tmp_path / "home"), "PATH": os.pathsep.join([*map(str, path_dirs), "/usr/bin", "/bin"])}
    payload = json.dumps({"hook_event_name": event, "cwd": str(tmp_path)})
    return subprocess.run(["sh", str(SCRIPT)], input=payload, capture_output=True, text=True, env=env, timeout=20)


def stub(path: Path, name: str) -> None:
    path.mkdir(parents=True, exist_ok=True)
    (path / name).write_text('#!/bin/sh\necho "$0 $*"; cat\n', encoding="utf-8")
    (path / name).chmod(0o755)


@posix_only
def test_script_prefers_the_installed_command(tmp_path):
    stub(tmp_path / "home/.local/bin", "agentdetox")
    stub(tmp_path / "elsewhere", "uvx")
    out = run(tmp_path, "PreToolUse", [tmp_path / "elsewhere"]).stdout
    assert out.startswith(f"{tmp_path}/home/.local/bin/agentdetox hook claude-code") and '"PreToolUse"' in out


@posix_only
def test_script_falls_back_to_the_pinned_release_through_uvx(tmp_path):
    stub(tmp_path / "bin", "uvx")
    out = run(tmp_path, "PreToolUse", [tmp_path / "bin"]).stdout
    assert f"--from agentdetox=={__version__} agentdetox hook claude-code" in out


@posix_only
def test_without_agentdetox_the_user_is_told_once_and_the_agent_works(tmp_path):
    started = run(tmp_path, "SessionStart")
    out = json.loads(started.stdout)
    assert started.returncode == 0 and "not installed" in out["systemMessage"]
    assert "Mention this to the user once" in out["hookSpecificOutput"]["additionalContext"]
    write = run(tmp_path, "PreToolUse")
    assert (write.returncode, write.stdout) == (0, "")
