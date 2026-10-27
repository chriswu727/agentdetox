"""Register AgentDetox hooks with an agent."""

from __future__ import annotations

import json
import os
import shlex
import shutil
import sys
import time
from pathlib import Path

from .context import home_dir
from .integrity import is_self_hook


def hook_command(agent: str) -> str:
    # Prefer the executable from the environment AgentDetox is running in, so the hook
    # keeps working when that environment is not on the agent's PATH.
    sibling = Path(sys.executable).with_name("agentdetox")
    exe = str(sibling) if sibling.exists() else shutil.which("agentdetox")
    if exe:
        return f"{shlex.quote(exe)} hook {agent}"
    return f"{shlex.quote(sys.executable)} -m agentdetox hook {agent}"


def claude_code_settings(existing: dict, command: str) -> dict:
    """Merge AgentDetox's hooks into a Claude Code settings dict, replacing any earlier copy."""
    settings = json.loads(json.dumps(existing))
    hooks = settings.setdefault("hooks", {})
    wanted = {
        "SessionStart": {"hooks": [{"type": "command", "command": command}]},
        "PreToolUse": {"matcher": "Write|Edit|MultiEdit|Bash", "hooks": [{"type": "command", "command": command}]},
        "PostToolUse": {"matcher": "Write|Edit|MultiEdit", "hooks": [{"type": "command", "command": command}]},
    }
    for event, group in wanted.items():
        groups = [g for g in hooks.get(event, []) if not any(is_self_hook(h.get("command", "")) for h in g.get("hooks", []))]
        hooks[event] = groups + [group]
    return settings


def cursor_hooks(command: str) -> dict:
    return {"version": 1, "hooks": {
        "sessionStart": [{"command": command}],
        "preToolUse": [{"command": command}],
        "afterFileEdit": [{"command": command}],
    }}


def remove_claude_code_hooks(existing: dict) -> dict:
    settings = json.loads(json.dumps(existing))
    hooks = settings.get("hooks", {})
    for event in list(hooks):
        groups = [g for g in hooks[event] if not any(is_self_hook(h.get("command", "")) for h in g.get("hooks", []))]
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if "hooks" in settings and not hooks:
        del settings["hooks"]
    return settings


def install_claude_code(settings_path: Path, apply: bool) -> tuple[str, Path | None]:
    existing = json.loads(settings_path.read_text()) if settings_path.exists() else {}
    merged = claude_code_settings(existing, hook_command("claude-code"))
    text = json.dumps(merged, indent=2, ensure_ascii=False) + "\n"
    return text, (_write_with_backup(settings_path, text) if apply else None)


def uninstall_claude_code(settings_path: Path) -> tuple[bool, Path | None]:
    """Remove only AgentDetox's hook groups, leaving every other setting as it is now."""
    if not settings_path.exists():
        return False, None
    existing = json.loads(settings_path.read_text())
    cleaned = remove_claude_code_hooks(existing)
    if cleaned == existing:
        return False, None
    return True, _write_with_backup(settings_path, json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n")


def _write_with_backup(path: Path, text: str) -> Path | None:
    backup = None
    if path.exists():
        backup = path.with_name(f"{path.name}.agentdetox-backup-{time.strftime('%Y%m%d-%H%M%S')}")
        shutil.copy2(path, backup)  # copy2 keeps the original's permissions
    path.parent.mkdir(parents=True, exist_ok=True)
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    tmp = path.with_name(path.name + ".agentdetox-tmp")
    tmp.write_text(text)
    os.chmod(tmp, mode)
    tmp.replace(path)
    return backup


def default_settings_path(agent: str, scope: str, project: Path) -> Path:
    base = home_dir() if scope == "user" else project
    return {
        "claude-code": base / ".claude" / "settings.json",
        "cursor": base / ".cursor" / "hooks.json",
        "codex": base / ".codex" / "hooks.json",
    }[agent]
