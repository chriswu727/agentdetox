"""Read-only health check of an AgentDetox installation. It never changes anything:
a tool that rewrites its own hook config is the behaviour AgentDetox flags in others."""

from __future__ import annotations

import json
import shlex
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__
from .consistency import NLI, NLI_MODEL
from .context import home_dir
from .install import claude_code_settings, default_settings_path
from .integrity import baseline_paths, is_self_hook, store_dir


@dataclass
class Check:
    status: str  # "ok", "warn", "fail"
    message: str


def run(project: Path) -> list[Check]:
    checks = [Check("ok", f"agentdetox {__version__} (Python {sys.version.split()[0]})")]
    checks += _claude_code_hooks(project)
    checks += _nli()
    checks += _store()
    checks += _other_agents(project)
    return checks


def _claude_code_hooks(project: Path) -> list[Check]:
    found = []
    for scope in ("user", "project"):
        path = default_settings_path("claude-code", scope, project)
        if not path.exists():
            continue
        try:
            settings = json.loads(path.read_text())
        except ValueError:
            found.append(Check("fail", f"Claude Code: {path} is not valid JSON"))
            continue
        commands = [h.get("command", "") for groups in settings.get("hooks", {}).values()
                    for g in groups for h in g.get("hooks", []) if is_self_hook(h.get("command", ""))]
        if commands:
            found.append(_check_claude_settings(path, settings, commands[0]))
    if not found:
        return [Check("fail", "Claude Code: hooks not installed (run `agentdetox install claude-code --apply`)")]
    return found


def _ours(hooks: dict) -> dict:
    return {event: [g for g in groups if any(is_self_hook(h.get("command", "")) for h in g.get("hooks", []))]
            for event, groups in hooks.items()}


def _check_claude_settings(path: Path, settings: dict, command: str) -> Check:
    # Compare only AgentDetox's own groups: the user's hooks and their order are theirs.
    expected = {k: v for k, v in _ours(claude_code_settings(settings, command)["hooks"]).items() if v}
    actual = {k: v for k, v in _ours(settings.get("hooks", {})).items() if v}
    if expected != actual:
        return Check("warn", f"Claude Code: hooks in {path} are from an older version; "
                             "re-run `agentdetox install claude-code --apply`")
    exe = shlex.split(command)[0]
    if not Path(exe).exists():
        return Check("fail", f"Claude Code: hook command {exe} does not exist; every tool call will report a hook error")
    try:
        out = subprocess.run([exe, "--version"], capture_output=True, text=True, timeout=20).stdout.strip()
    except (OSError, subprocess.SubprocessError) as e:
        return Check("fail", f"Claude Code: hook command {exe} failed to run: {e}")
    hooked = out.split()[-1] if out else "?"
    if hooked != __version__:
        return Check("warn", f"Claude Code: hooks run agentdetox {hooked}, this is {__version__} ({exe})")
    return Check("ok", f"Claude Code: hooks installed and current in {path}")


def _nli() -> list[Check]:
    # Reports on this interpreter; the hooks' own install is checked via its --version only.
    nli = NLI()
    if not NLI.installed():
        return [Check("warn", "contradiction detection off: install 'agentdetox[nli]', then `agentdetox fetch-models`")]
    if not nli.available():
        return [Check("warn", "contradiction detection off: model not downloaded; run `agentdetox fetch-models`")]
    return [Check("ok", f"contradiction detection on ({NLI_MODEL})")]


def _store() -> list[Check]:
    store = store_dir()
    if not (store / "baseline.json").exists():
        return [Check("warn", f"snapshot store {store} is empty; it is created on install or first session")]
    checks = [Check("ok", f"snapshot store {store}: {len(baseline_paths())} file(s) tracked")]
    for p in (store, store / "objects"):
        if p.exists() and stat.S_IMODE(p.stat().st_mode) & 0o077:
            checks.append(Check("fail", f"{p} is readable by other users; run `chmod 700 {p}`"))
    return checks


def _other_agents(project: Path) -> list[Check]:
    checks = []
    for agent in ("codex", "cursor"):
        hooked = [p for scope in ("user", "project")
                  if (p := default_settings_path(agent, scope, project)).exists() and is_self_hook(p.read_text())]
        if hooked:
            checks.append(Check("ok", f"{agent}: AgentDetox hook registered in {hooked[0]} (experimental)"))
    return checks


def render(checks: list[Check]) -> str:
    tag = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    home = str(home_dir())
    return "\n".join(f"{tag[c.status]} {c.message.replace(home, '~')}" for c in checks)
