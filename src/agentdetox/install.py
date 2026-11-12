"""Register AgentDetox hooks with an agent."""

from __future__ import annotations

import json
import os
import re
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
    return _read_settings(path)[0]


def _read_settings(path: Path) -> tuple[dict, bytes | None]:
    """The settings and the bytes they were read from (None when there is no file)."""
    try:
        raw = path.read_bytes() if path.exists() else None
        data = json.loads(raw.decode("utf-8")) if raw is not None else {}
        _validate_claude_settings(data)
    except ValueError as e:
        raise ValueError(f"{path}: {e}. Fix the settings file and retry; no settings were changed.") from None
    return data, raw


def _as_written(data: dict, raw: bytes | None) -> str:
    """`data` as JSON in the file's own layout: its indentation, its line ends and whether
    it ends with one. Number and escape spellings are JSON's, not the file's."""
    before = raw.decode("utf-8", "replace") if raw else ""
    indent: int | str = 2
    first = re.search(r"\n([ \t]+)\S", before)
    if first:
        indent = "\t" if first.group(1).startswith("\t") else len(first.group(1))
    text = json.dumps(data, indent=indent, ensure_ascii=False)
    if "\r\n" in before:
        text = text.replace("\n", "\r\n")
    if before.endswith("\r\n"):
        return text + "\r\n"
    # A file of one line, or none, gets the line end a new file is given.
    return text + ("\n" if before.endswith("\n") or "\n" not in before.strip() else "")


def install_claude_code(settings_path: Path, apply: bool) -> tuple[str, Path | None]:
    existing, raw = _read_settings(settings_path)
    merged = claude_code_settings(existing, hook_command("claude-code"))
    if merged == existing and raw is not None:
        return raw.decode("utf-8"), None        # already there: nothing to write or back up
    text = _as_written(merged, raw)
    return text, (_write_with_backup(settings_path, text, unchanged_since=raw) if apply else None)


def uninstall_claude_code(settings_path: Path) -> tuple[bool, Path | None]:
    """Remove only AgentDetox's handlers, leaving every other setting as it is now."""
    if not settings_path.exists():
        return False, None
    existing, raw = _read_settings(settings_path)
    cleaned = remove_claude_code_hooks(existing)
    if cleaned == existing:
        return False, None
    return True, _write_with_backup(settings_path, _as_written(cleaned, raw), unchanged_since=raw)


_UNCHECKED = object()


def _write_with_backup(path: Path, text: str, unchanged_since: object = _UNCHECKED) -> Path | None:
    """Replace `path` with `text`, keeping a copy of what was there beside it. A settings
    file that is a link (kept in a dotfiles folder) is written where the link points, so
    the link stays one. With `unchanged_since` (the bytes the new text was made from, None
    for no file), nothing is written when the file has changed since: Claude Code rewrites
    its settings too, and its change must not be lost."""
    backup = None
    path.parent.mkdir(parents=True, exist_ok=True)
    target = Path(os.path.realpath(path)) if path.is_symlink() else path
    target.parent.mkdir(parents=True, exist_ok=True)
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
    mode = target.stat().st_mode & 0o777 if target.exists() else 0o600
    fd, name = tempfile.mkstemp(prefix=f".{target.name}.agentdetox-", suffix=".tmp", dir=target.parent)
    tmp = Path(name)
    try:
        with os.fdopen(fd, "w", encoding="utf-8", newline="") as stream:
            stream.write(text)
        os.chmod(tmp, mode)
        if unchanged_since is not _UNCHECKED:
            now = target.read_bytes() if target.exists() else None
            if now != unchanged_since:
                if backup is not None:
                    backup.unlink(missing_ok=True)
                raise ValueError(f"{path} changed while AgentDetox was updating it, so nothing was written. "
                                 "Run the command again.")
        tmp.replace(target)
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
# The plugin from this repository's marketplace. One of the same name from another marketplace
# is someone else's code, and says nothing about whether AgentDetox's hooks run.
OWN_PLUGIN = "agentdetox@agentdetox"


def plugin_state(project: Path) -> tuple[str | None, str]:
    """(the plugin's id when its hooks can be counted on, what is wrong otherwise or besides).

    A key in `enabledPlugins` is only a wish: a project's own settings can carry one, so it
    cannot stand for hooks being there. The plugin counts when Claude Code's record of
    installed plugins has it and the folder it names holds a hooks file."""
    enabled: dict = {}
    for path in (claude_dir() / "settings.json", project / ".claude" / "settings.json",
                 project / ".claude" / "settings.local.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        if isinstance(data, dict) and isinstance(data.get("enabledPlugins"), dict):
            enabled.update(data["enabledPlugins"])
    named = [k for k, v in enabled.items() if v is True and isinstance(k, str) and k.split("@")[0] == PLUGIN]
    if not named:
        return None, ""
    others = [k for k in named if k != OWN_PLUGIN]
    foreign = (f"a plugin named {others[0]} is enabled, which is not AgentDetox's own ({OWN_PLUGIN}) and is not "
               "counted as running its hooks") if others else ""
    if OWN_PLUGIN not in named:
        return None, foreign
    record = claude_dir() / "plugins" / "installed_plugins.json"
    try:
        plugins = json.loads(record.read_text(encoding="utf-8")).get("plugins")
        entries = plugins.get(OWN_PLUGIN) or []
        folders = [Path(entry["installPath"]) for entry in entries if isinstance(entry, dict) and entry.get("installPath")]
    except FileNotFoundError:
        folders = []
    except (OSError, ValueError, AttributeError, TypeError):
        return None, (f"the {OWN_PLUGIN} plugin is enabled, but Claude Code's record of installed plugins "
                      f"({record}) could not be read, so whether its hooks run is unknown")
    for folder in folders:
        try:
            registered = json.loads((folder / "hooks" / "hooks.json").read_text(encoding="utf-8"))["hooks"]
        except (OSError, ValueError, KeyError, TypeError):
            continue
        missing = missing_hooks(registered)
        outdated = (f"the {OWN_PLUGIN} plugin is an older version that does not register "
                    + ", ".join(missing) + "; update it with `claude plugin update " + OWN_PLUGIN + "`") if missing else ""
        return OWN_PLUGIN, "; ".join(filter(None, (outdated, foreign)))
    return None, (f"the {OWN_PLUGIN} plugin is enabled in settings but is not installed, so it runs no hooks"
                  + (f"; {foreign}" if foreign else ""))


def missing_hooks(registered: object, own=None) -> list[str]:
    """What this version registers that `registered` (the `hooks` of a settings file or of a
    plugin) lacks: an event, or a tool in an event's matcher. With `own`, a test of a
    handler's command, only the groups holding such a handler count: the user's other hooks
    are theirs."""
    expected = claude_code_settings({}, "agentdetox")["hooks"]
    missing = []
    for event, groups in expected.items():
        have = registered.get(event) if isinstance(registered, dict) else None
        have = [group for group in have or [] if isinstance(group, dict) and (own is None or any(
            isinstance(h, dict) and own(str(h.get("command", ""))) for h in group.get("hooks") or []))]
        tools = {tool for group in have for tool in str(group.get("matcher") or "").split("|")}
        if not have:
            missing.append(event)
            continue
        for group in groups:
            lacking = sorted(set(str(group.get("matcher") or "").split("|")) - tools - {""})
            if lacking:
                missing.append(f"{event} for {'|'.join(lacking)}")
    return missing


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
