"""Read-only health check of an AgentDetox installation. It never changes anything:
a tool that rewrites its own hook config is the behaviour AgentDetox flags in others."""

from __future__ import annotations

import json
import stat
import subprocess
import sys
from dataclasses import dataclass
from pathlib import Path

from . import __version__, allowlist, compat, daemon, settings
from .consistency import NLI, NLI_MODEL
from .context import home_dir
from .install import claude_code_plugin, claude_code_settings, default_settings_path, plugin_command
from .integrity import SCHEMA_VERSION, StoreError, is_self_hook, store_dir, usage


@dataclass
class Check:
    status: str  # "ok", "warn", "fail"
    message: str


def run(project: Path) -> list[Check]:
    checks = [Check("ok", f"agentdetox {__version__} (Python {sys.version.split()[0]})")]
    checks += _claude_code_hooks(project)
    checks += _settings()
    checks += _nli()
    checks += _store()
    checks += _other_agents(project)
    return checks


def _claude_code_hooks(project: Path) -> list[Check]:
    found = []
    in_settings = False
    for scope in ("user", "project"):
        path = default_settings_path("claude-code", scope, project)
        if not path.exists():
            continue
        try:
            settings = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            found.append(Check("fail", f"Claude Code: {path} is not valid JSON"))
            continue
        commands = [h.get("command", "") for groups in settings.get("hooks", {}).values()
                    for g in groups for h in g.get("hooks", []) if is_self_hook(h.get("command", ""))]
        if commands:
            in_settings = True
            found.append(_check_claude_settings(path, settings, commands[0]))
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


def _check_claude_settings(path: Path, settings: dict, command: str) -> Check:
    # Compare only AgentDetox's own groups: the user's hooks and their order are theirs.
    expected = {k: v for k, v in _ours(claude_code_settings(settings, command)["hooks"]).items() if v}
    actual = {k: v for k, v in _ours(settings.get("hooks", {})).items() if v}
    if expected != actual:
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
        return [Check("warn", "contradiction detection off: install 'agentdetox[nli]', then `agentdetox fetch-models`")]
    if not nli.available():
        return [Check("warn", "contradiction detection off: model not downloaded; run `agentdetox fetch-models`")]
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


def _store() -> list[Check]:
    store = store_dir()
    if not (store / "baseline.json").exists():
        return [Check("warn", f"snapshot store {store} is empty; it is created on install or first session")]
    try:
        tracked = usage()["tracked"]
    except StoreError as e:
        return [Check("fail", str(e))]
    checks = [Check("ok", f"snapshot store {store}: {tracked} file(s) tracked (store version {SCHEMA_VERSION})")]
    # Windows reports 0o777 for every directory; access there comes from the profile's ACLs.
    for p in (store, store / "objects") if not compat.WINDOWS else ():
        if p.exists() and stat.S_IMODE(p.stat().st_mode) & 0o077:
            checks.append(Check("fail", f"{p} is readable by other users; run `chmod 700 {p}`"))
    return checks


def _other_agents(project: Path) -> list[Check]:
    checks = []
    for agent in ("codex", "cursor"):
        hooked = [p for scope in ("user", "project")
                  if (p := default_settings_path(agent, scope, project)).exists() and is_self_hook(p.read_text(encoding="utf-8"))]
        if hooked:
            checks.append(Check("ok", f"{agent}: AgentDetox hook registered in {hooked[0]} (experimental)"))
    return checks


def render(checks: list[Check]) -> str:
    tag = {"ok": "OK  ", "warn": "WARN", "fail": "FAIL"}
    home = str(home_dir())
    return "\n".join(f"{tag[c.status]} {c.message.replace(home, '~')}" for c in checks)
