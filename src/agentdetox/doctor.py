"""Read-only health check of an AgentDetox installation. It never changes anything:
a tool that rewrites its own hook config is the behaviour AgentDetox flags in others."""

from __future__ import annotations

import json
import re
import stat
import subprocess
import sys
import tomllib
from dataclasses import dataclass
from pathlib import Path

from . import __version__, allowlist, background, compat, daemon, events, settings, storage
from .consistency import NLI, NLI_MODEL
from .context import claude_dir, home_dir
from .install import (
    claude_code_plugin,
    claude_code_settings,
    default_settings_path,
    plugin_command,
    read_claude_settings,
)
from .integrity import StoreError, is_self_hook, store_dir, usage


@dataclass
class Check:
    status: str  # "ok", "warn", "fail"
    message: str


def run(project: Path) -> list[Check]:
    checks = [Check("ok", f"agentdetox {__version__} (Python {sys.version.split()[0]})")]
    others = _other_agents(project)
    claude = _claude_code_hooks(project)
    if others and not claude_dir().exists() and [c.status for c in claude] == ["fail"]:
        # Someone who uses only Codex or Cursor has no Claude Code hooks to be missing.
        claude = [Check("ok", f"Claude Code: not set up on this machine (no {claude_dir()}); its hooks are not checked")]
    checks += claude
    checks += _settings()
    checks += _nli()
    checks += _background()
    checks += _store()
    checks += others
    try:
        with storage.connection() as db:
            interrupted = db.execute("SELECT * FROM operations WHERE stage NOT IN ('completed', 'acknowledged')").fetchall() if db else []
        for operation in interrupted:
            checks.append(Check("fail", f"Recovery {operation['id']} for {operation['path']} is incomplete; "
                                       f"backup: {operation['backup']}; error: {operation['error'] or 'process interrupted'}. "
                                       "Inspect both, then retry or run `agentdetox health acknowledge-recovery "
                                       f"{operation['id']}`"))
    except StoreError:
        pass
    try:
        errors = [r for r in events.read(None) if r.get("event") == "hook_error" and not r.get("resolved")]
    except StoreError:
        errors = []
    if errors:
        last = errors[-1]
        checks.append(Check("fail", f"Protection degraded: {len(errors)} hook check(s) failed; last at "
                                   f"{last.get('ts', 'unknown')} ({last.get('stage')}: {last.get('error')}). "
                                   "Inspect `agentdetox events` and fix the failing check."))
    return checks


def _claude_code_hooks(project: Path) -> list[Check]:
    found = []
    in_settings = False
    seen = set()
    for scope in ("user", "project"):
        path = default_settings_path("claude-code", scope, project)
        # In the home folder the project's settings are the user's settings.
        if not path.exists() or path.resolve() in seen:
            continue
        seen.add(path.resolve())
        try:
            settings = read_claude_settings(path)
        except (OSError, ValueError) as e:
            found.append(Check("fail", f"Claude Code: {e}"))
            continue
        commands = [h.get("command", "") for groups in settings.get("hooks", {}).values()
                    for g in groups for h in g.get("hooks", []) if is_self_hook(h.get("command", ""))]
        if commands:
            in_settings = True
            found.append(_check_claude_settings(path, settings, commands[0]))
    disabled = False
    for path in (default_settings_path("claude-code", "user", project),
                 project / ".claude/settings.json", project / ".claude/settings.local.json"):
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
            if "disableAllHooks" in data:
                disabled = data["disableAllHooks"] is True
        except (OSError, ValueError, TypeError):
            continue
    if disabled:
        found.append(Check("fail", "Claude Code: disableAllHooks is true; AgentDetox hooks are disabled"))
    plugin = claude_code_plugin(project)
    if plugin:
        found.append(_check_plugin(plugin))
        if in_settings:
            found.append(Check("warn", f"Claude Code: the {plugin} plugin and settings both register AgentDetox's "
                                       "hooks, so every check runs twice; remove the settings copy with "
                                       "`agentdetox uninstall claude-code`"))
    if not found:
        return [Check("fail", "Claude Code: hooks not installed (install the plugin, or run "
                              "`agentdetox install claude-code --apply`)")]
    return found


def _check_plugin(plugin: str) -> Check:
    command = plugin_command()
    if command is None:
        return Check("fail", f"Claude Code: the {plugin} plugin is enabled but finds neither an agentdetox command "
                             "nor uvx, so nothing is checked")
    if len(command) > 1:  # uvx, which a read-only check must not make download anything
        return Check("ok", f"Claude Code: hooks run by the {plugin} plugin, through uvx")
    try:
        hooked = _version(command[0])
    except (OSError, subprocess.SubprocessError) as e:
        return Check("fail", f"Claude Code: the {plugin} plugin runs {command[0]}, which failed: {e}")
    if hooked != __version__:
        return Check("warn", f"Claude Code: the {plugin} plugin runs agentdetox {hooked} ({command[0]}), "
                             f"this is {__version__}")
    return Check("ok", f"Claude Code: hooks run by the {plugin} plugin ({command[0]})")


def _version(exe: str) -> str:
    out = subprocess.run([exe, "--version"], capture_output=True, text=True, encoding="utf-8", errors="replace",
                         timeout=20).stdout.strip()
    return out.split()[-1] if out else "?"


def _ours(hooks: dict) -> dict:
    return {event: [g for g in groups if any(is_self_hook(h.get("command", "")) for h in g.get("hooks", []))]
            for event, groups in hooks.items()}


def _registered_by_older(settings: dict, command: str) -> bool:
    # Compare only AgentDetox's own groups: the user's hooks and their order are theirs.
    expected = {k: v for k, v in _ours(claude_code_settings(settings, command)["hooks"]).items() if v}
    actual = {k: v for k, v in _ours(settings.get("hooks", {})).items() if v}
    return expected != actual


def outdated_settings(project: Path) -> list[Path]:
    """Claude Code settings whose AgentDetox hooks an older version registered. Runs no
    subprocess, so session start can afford it."""
    out = []
    for path in dict.fromkeys(default_settings_path("claude-code", scope, project) for scope in ("user", "project")):
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
            commands = [h.get("command", "") for groups in settings.get("hooks", {}).values()
                        for g in groups for h in g.get("hooks", []) if is_self_hook(h.get("command", ""))]
        except (OSError, ValueError, AttributeError, TypeError):
            continue
        if commands and _registered_by_older(settings, commands[0]):
            out.append(path)
    return out


def _check_claude_settings(path: Path, settings: dict, command: str) -> Check:
    if _registered_by_older(settings, command):
        return Check("warn", f"Claude Code: hooks in {path} are from an older version; "
                             "re-run `agentdetox install claude-code --apply`")
    exe = compat.hook_executable(command)
    if not Path(exe).exists():
        return Check("fail", f"Claude Code: hook command {exe} does not exist; every tool call will report a hook error")
    try:
        hooked = _version(exe)
    except (OSError, subprocess.SubprocessError) as e:
        return Check("fail", f"Claude Code: hook command {exe} failed to run: {e}")
    if hooked != __version__:
        return Check("warn", f"Claude Code: hooks run agentdetox {hooked}, this is {__version__} ({exe})")
    return Check("ok", f"Claude Code: hooks installed and current in {path}")


def _settings() -> list[Check]:
    current, problems = settings.load()
    summary = ", ".join(f"{s.key}={s.value}" + (f" ({s.source})" if s.source == "env" or s.value != settings.DEFAULTS[s.key]
                                                 else "") for s in current)
    checks = [Check("ok", f"checks: {summary}")] + [Check("warn", p) for p in problems]
    path = allowlist.path()
    if path.exists():
        try:
            json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            checks.append(Check("warn", f"{path} is not valid JSON, so nothing is allowed until it is fixed"))
    return checks


def _nli() -> list[Check]:
    # Reports on this interpreter; the hooks' own install is checked via its --version only.
    nli = NLI()
    if not NLI.installed():
        return [Check("ok", "optional contradiction detection inactive: install 'agentdetox[nli]', then `agentdetox fetch-models`")]
    if not nli.available():
        return [Check("ok", "optional contradiction detection inactive: model not downloaded; run `agentdetox fetch-models`")]
    how = {"ask": "asks on conflicts", "off": "turned off"}.get(settings.mode("contradiction"),
                                                               "records conflicts in the background")
    checks = [Check("ok", f"contradiction detection {how} ({NLI_MODEL})")]
    if not daemon.SERVER:
        checks.append(Check("warn", "no model server on Windows yet: each contradiction check loads the model "
                                    "(about 6 s and 1 GB; record jobs run in one background worker at a time)"))
    info = daemon.ping()
    if info and info["code"] != daemon.code_id():
        checks.append(Check("warn", f"model server (pid {info['pid']}) runs an older build; it is replaced on its "
                                    "next job, or run `agentdetox daemon stop`"))
    elif info:
        checks.append(Check("ok", f"model server running (pid {info['pid']}, model "
                                  f"{'loaded' if info['model_loaded'] else 'not loaded yet'})"))
    return checks


def _background() -> list[Check]:
    """Contradiction checks handed to the background worker that have not finished. A
    failed one is a version nobody compared; one that only waits is not a failure."""
    state = background.status()
    log = store_dir() / "daemon.log"
    days = int(background.KEEP_SECONDS // 86400)
    checks = []
    if state["failed"]:
        last = state["last_failure"]
        about = f" for {last['path']}" if last["path"] else ""
        checks.append(Check("fail", f"{state['failed']} background contradiction check(s) failed, so those versions "
                                    f"were not compared with what the agent already knows; last at {last['ts']}: "
                                    f"{last['error']}{about} after {last['attempts']} attempt(s). Each is kept in "
                                    f"{state['directory']} for {days} days. See {log}, fix the cause, then run "
                                    "`agentdetox daemon retry`"))
    if state["waiting_model"]:
        checks.append(Check("warn", f"{state['waiting_model']} background contradiction check(s) are waiting for the "
                                    "contradiction model, which the background worker did not find; run "
                                    "`agentdetox fetch-models`, then `agentdetox daemon retry`, or turn the check off "
                                    f"with `agentdetox config contradiction off`. Waiting checks expire after {days} days"))
    if state["stalled"]:
        checks.append(Check("warn", f"{state['stalled']} background contradiction check(s) have waited more than "
                                    f"{int(background.STALLED_AFTER // 60)} min (oldest queued {state['oldest']}); run "
                                    f"`agentdetox daemon retry` to start them, and see {log} if they stay queued"))
    if state["queued"] - state["stalled"]:
        checks.append(Check("ok", f"{state['queued'] - state['stalled']} background contradiction check(s) queued"))
    return checks


def _store() -> list[Check]:
    store = store_dir()
    if not (store / "baseline.json").exists() and not storage.path().exists() and not (store / "sqlite-migrated").exists():
        return [Check("warn", f"snapshot store {store} is empty; it is created on install or first session")]
    try:
        tracked = usage()["tracked"]
    except StoreError as e:
        return [Check("fail", str(e))]
    found = storage.format_version()
    checks = [Check("ok", f"snapshot store {store}: {tracked} file(s) tracked (store format {found or 'not created'})")]
    if found and found < storage.VERSION:
        checks.append(Check("ok", f"store format {found} upgrades to {storage.VERSION} at the next write; "
                                  f"a copy is kept as {storage.path().with_name(f'state.v{found}.sqlite3')}"))
    # Windows reports 0o777 for every directory; access there comes from the profile's ACLs.
    for p in (store, store / "objects") if not compat.WINDOWS else ():
        if p.exists() and stat.S_IMODE(p.stat().st_mode) & 0o077:
            checks.append(Check("fail", f"{p} is readable by other users; run `chmod 700 {p}`"))
    return checks


def _other_agents(project: Path) -> list[Check]:
    """What can be read of the Codex and Cursor hooks from their files. Whether the client
    runs them cannot: Codex skips a hook until the user has trusted it, and neither client
    tells a hook's owner that it ran."""
    checks = []
    for agent in ("codex", "cursor"):
        for path in dict.fromkeys(default_settings_path(agent, scope, project) for scope in ("user", "project")):
            try:
                text = path.read_text(encoding="utf-8")
            except OSError:
                continue
            if not is_self_hook(text):
                continue
            try:
                problems = _codex_gaps(json.loads(text), path) if agent == "codex" else _cursor_gaps(json.loads(text))
            except (ValueError, TypeError, AttributeError):
                checks.append(Check("warn", f"{agent}: {path} names AgentDetox's hook but is not a hooks file "
                                            f"{agent} would load"))
                continue
            unseen = ("Codex runs it only once you have trusted it in /hooks, which AgentDetox cannot see"
                      if agent == "codex" else "whether Cursor runs it cannot be seen from here")
            if problems:
                checks.append(Check("warn", f"{agent}: AgentDetox's hook is in {path}, but " + "; ".join(problems)))
            else:
                checks.append(Check("ok", f"{agent}: AgentDetox's hook is in {path} (experimental; {unseen})"))
    return checks


def _matches(matcher, names: tuple[str, ...]) -> bool:
    if matcher in (None, "", "*"):
        return True
    try:
        return any(re.search(str(matcher), name) for name in names)
    except re.error:
        return False


def _codex_gaps(data: dict, path: Path) -> list[str]:
    """What a Codex hooks.json that names AgentDetox leaves unchecked."""
    events: dict[str, list] = {}
    for event, groups in data.get("hooks", {}).items():
        events[event] = [g.get("matcher") for g in groups
                         if any(is_self_hook(str(h.get("command", ""))) for h in g.get("hooks", []))]
    gaps = []
    if not events.get("SessionStart"):
        gaps.append("not for SessionStart, so changes made outside Codex are not reported")
    # Codex reports shell commands as Bash, and file edits as apply_patch (also matched as Edit or Write).
    for tool, names, what in (("Bash", ("Bash",), "shell commands"),
                              ("apply_patch", ("apply_patch", "Edit", "Write"), "file edits")):
        for event in ("PreToolUse", "PostToolUse"):
            if not any(_matches(m, names) for m in events.get(event, [])):
                gaps.append(f"no {event} matcher covers Codex's {tool} tool, so {what} are not "
                            + ("checked" if event == "PreToolUse" else "recorded"))
    try:
        features = tomllib.loads(path.with_name("config.toml").read_text(encoding="utf-8")).get("features", {})
    except (OSError, ValueError):
        features = {}
    if isinstance(features, dict) and (features.get("hooks") is False or features.get("codex_hooks") is False):
        gaps.append(f"hooks are turned off in {path.with_name('config.toml')} ([features]), so it does not run")
    return gaps


def _cursor_gaps(data: dict) -> list[str]:
    """What a Cursor hooks.json that names AgentDetox leaves unchecked."""
    events = {event: [h.get("matcher") for h in handlers if is_self_hook(str(h.get("command", "")))]
              for event, handlers in data.get("hooks", {}).items()}
    gaps = []
    if not events.get("sessionStart"):
        gaps.append("not for sessionStart, so changes made outside Cursor are not reported")
    if not any(_matches(m, ("Write",)) for m in events.get("preToolUse", [])):
        gaps.append("no preToolUse matcher covers Write, so file edits are not checked")
    if not events.get("afterFileEdit") and not any(_matches(m, ("Write",)) for m in events.get("postToolUse", [])):
        gaps.append("not for afterFileEdit, so file edits are not recorded")
    for event in ("preToolUse", "postToolUse", "postToolUseFailure"):
        if not any(_matches(m, ("Shell",)) for m in events.get(event, [])):
            gaps.append(f"no {event} matcher covers Shell, so context is not compared across "
                        + ("failed " if event == "postToolUseFailure" else "") + "shell commands")
    if any(m in (None, "", "*") for m in events.get("preToolUse", [])):
        gaps.append("its preToolUse entry has no matcher, so it also runs for every read and search")
    return gaps


def render(checks: list[Check]) -> str:
    tag = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    home = str(home_dir())
    return "\n".join(f"{tag[c.status]} {c.message.replace(home, '~')}" for c in checks)
