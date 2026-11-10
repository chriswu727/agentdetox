"""Register AgentDetox hooks with an agent."""

from __future__ import annotations

import json
import os
import shutil
import sys
import tempfile
import time
from pathlib import Path

from . import compat
from .context import claude_dir, codex_dir, home_dir
from .integrity import is_self_hook


def hook_command(agent: str) -> str:
    # Prefer the executable from the environment AgentDetox is running in, so the hook
    # keeps working when that environment is not on the agent's PATH.
    sibling = Path(sys.executable).with_name("agentdetox.exe" if compat.WINDOWS else "agentdetox")
    exe = str(sibling) if sibling.exists() else shutil.which("agentdetox")
    if exe:
        return f"{compat.quote_executable(exe)} hook {agent}"
    # -I: hooks run in the project directory, and plain -m would import an `agentdetox`
    # package planted at the top of a cloned repository.
    return f"{compat.quote_executable(sys.executable)} -I -m agentdetox hook {agent}"


def claude_code_settings(existing: dict, command: str) -> dict:
    """Merge AgentDetox's hooks into a Claude Code settings dict, replacing any earlier copy."""
    settings = remove_claude_code_hooks(existing)
    hooks = settings.setdefault("hooks", {})
    wanted = {
        "SessionStart": {"hooks": [{"type": "command", "command": command}]},
        "PreToolUse": {"matcher": "Write|Edit|MultiEdit|Bash", "hooks": [{"type": "command", "command": command}]},
        "PostToolUse": {"matcher": "Write|Edit|MultiEdit|Bash", "hooks": [{"type": "command", "command": command}]},
        "PostToolUseFailure": {"matcher": "Bash", "hooks": [{"type": "command", "command": command}]},
    }
    for event, group in wanted.items():
        hooks[event] = hooks.get(event, []) + [group]
    return settings


def cursor_hooks(command: str) -> dict:
    """Cursor's hooks.json entries. The matchers are Cursor's documented tool names: without
    one, preToolUse would also run for every read and search. postToolUse fires only when a
    command succeeds, so a failed one is compared through postToolUseFailure."""
    return {"version": 1, "hooks": {
        "sessionStart": [{"command": command}],
        "preToolUse": [{"command": command, "matcher": "Shell|Write|Delete"}],
        "postToolUse": [{"command": command, "matcher": "Shell|Delete"}],
        "postToolUseFailure": [{"command": command, "matcher": "Shell"}],
        "afterFileEdit": [{"command": command}],
    }}


def codex_hooks(command: str) -> dict:
    """Codex's hooks.json entries. `Bash` and `apply_patch` are the tool names Codex reports
    for shell commands and file edits; its PostToolUse also follows a command that failed."""
    def handler() -> list[dict]:
        return [{"type": "command", "command": command}]

    return {"hooks": {
        "SessionStart": [{"hooks": handler()}],
        "PreToolUse": [{"matcher": "^(Bash|apply_patch)$", "hooks": handler()}],
        "PostToolUse": [{"matcher": "^(Bash|apply_patch)$", "hooks": handler()}],
    }}


def remove_claude_code_hooks(existing: dict) -> dict:
    _validate_claude_settings(existing)
    settings = json.loads(json.dumps(existing))
    hooks = settings.get("hooks", {})
    changed = False
    for event in list(hooks):
        groups = []
        for group in hooks[event]:
            handlers = group.get("hooks", [])
            kept = [h for h in handlers if not is_self_hook(h.get("command", ""))]
            if len(kept) == len(handlers):
                groups.append(group)
            elif kept:
                groups.append({**group, "hooks": kept})
        if groups == hooks[event]:
            continue
        changed = True
        if groups:
            hooks[event] = groups
        else:
            del hooks[event]
    if changed and not hooks:
        del settings["hooks"]
    return settings


def _validate_claude_settings(data) -> None:
    if not isinstance(data, dict):
        raise ValueError("settings must be a JSON object")
    hooks = data.get("hooks", {})
    if not isinstance(hooks, dict):
        raise ValueError("hooks must be a JSON object")
    for event, groups in hooks.items():
        if not isinstance(groups, list):
            raise ValueError(f"hooks.{event} must be an array")
        for group in groups:
            if not isinstance(group, dict) or not isinstance(group.get("hooks", []), list):
                raise ValueError(f"hooks.{event} entries must be objects with a hooks array")
            for handler in group.get("hooks", []):
                if not isinstance(handler, dict) or not isinstance(handler.get("command", ""), str):
                    raise ValueError(f"hooks.{event} handlers must be objects with string commands when present")


def read_claude_settings(path: Path) -> dict:
    try:
        data = json.loads(path.read_text(encoding="utf-8")) if path.exists() else {}
        _validate_claude_settings(data)
    except ValueError as e:
        raise ValueError(f"{path}: {e}. Fix the settings file and retry; no settings were changed.") from None
    return data


def install_claude_code(settings_path: Path, apply: bool) -> tuple[str, Path | None]:
    existing = read_claude_settings(settings_path)
    merged = claude_code_settings(existing, hook_command("claude-code"))
    text = json.dumps(merged, indent=2, ensure_ascii=False) + "\n"
    return text, (_write_with_backup(settings_path, text) if apply else None)


def uninstall_claude_code(settings_path: Path) -> tuple[bool, Path | None]:
    """Remove only AgentDetox's handlers, leaving every other setting as it is now."""
    if not settings_path.exists():
        return False, None
    existing = read_claude_settings(settings_path)
    cleaned = remove_claude_code_hooks(existing)
    if cleaned == existing:
        return False, None
    return True, _write_with_backup(settings_path, json.dumps(cleaned, indent=2, ensure_ascii=False) + "\n")


def _write_with_backup(path: Path, text: str) -> Path | None:
    backup = None
    path.parent.mkdir(parents=True, exist_ok=True)
    if path.exists():
        fd, name = tempfile.mkstemp(prefix=f"{path.name}.agentdetox-backup-{time.strftime('%Y%m%d-%H%M%S')}-",
                                    dir=path.parent)
        os.close(fd)
        backup = Path(name)
        try:
            shutil.copy2(path, backup)  # copy2 keeps the original's permissions
        except OSError:
            backup.unlink(missing_ok=True)
            raise
    mode = path.stat().st_mode & 0o777 if path.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix=f".{path.name}.agentdetox-", suffix=".tmp", dir=path.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="\n") as stream:
            stream.write(text)
        os.chmod(tmp, mode)
        tmp.replace(path)
    finally:
        tmp.unlink(missing_ok=True)
    return backup


def default_settings_path(agent: str, scope: str, project: Path) -> Path:
    base = home_dir() if scope == "user" else project
    return {
        "claude-code": (claude_dir() if scope == "user" else project / ".claude") / "settings.json",
        "cursor": base / ".cursor" / "hooks.json",
        "codex": (codex_dir() if scope == "user" else project / ".codex") / "hooks.json",
    }[agent]


PLUGIN = "agentdetox"


def claude_code_plugin(project: Path) -> str | None:
    """The id of the AgentDetox plugin if Claude Code has it enabled for this project.
    Its hooks run in addition to any in settings: Claude Code does not merge the two."""
    enabled: dict = {}
    for path in (claude_dir() / "settings.json", project / ".claude" / "settings.json",
                 project / ".claude" / "settings.local.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("enabledPlugins"), dict):
            enabled.update(data["enabledPlugins"])
    return next((k for k, v in enabled.items() if v is True and k.split("@")[0] == PLUGIN), None)


def plugin_command() -> list[str] | None:
    """What the plugin's hook script runs, looked up in the same order as the script."""
    local = home_dir() / ".local" / "bin" / "agentdetox"
    if os.access(local, os.X_OK):
        return [str(local)]
    if exe := shutil.which("agentdetox"):
        return [exe]
    if uvx := shutil.which("uvx"):
        return [uvx, "--quiet", "--from", "agentdetox", "agentdetox"]
    return None
