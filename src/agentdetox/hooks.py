"""Agent hook entry point: an agent's event in, its reply out.

PreToolUse   checks a planned write to persistent context and denies, asks or records.
PostToolUse records edit-tool writes or compares context across a shell tool.
PostToolUseFailure compares shell context even when the tool failed.
SessionStart reports context changed out-of-band since the last check.

Claude Code, Codex and Cursor name these events differently (adapters.py). Codex sends
PostToolUse after a failed command too; Cursor sends postToolUseFailure.

adapters.py reads each agent's protocol, engine.py checks, policy.py decides, and
session.py runs the session-start check. Handlers fail open: an error inside AgentDetox
must never break the agent. The one exception is a write to agent context, or to
AgentDetox's own state, that could not be checked: that asks (or is refused where the
agent cannot ask), because what the check reads is chosen by whoever steers the agent,
and an input that makes the check fail must not be a way past it.
"""

from __future__ import annotations

import json
import os
import sys
from dataclasses import asdict
from pathlib import Path

from . import adapters, engine, events, observation, policy, session, settings, shell
from . import patch as patches
from .context import classify, short_path
from .integrity import StoreError, store_dir


def handle(agent: str, payload: dict) -> tuple[int, str]:
    payload = _clean(payload)
    # The command names the agent the hook was registered for; the event says which agent
    # is running it (Cursor runs the hooks in Claude Code's settings on its own events).
    adapter = adapters.resolve(agent, payload)
    event = ""
    try:
        event = adapter.event(payload)
        if event == "pre":
            return 0, adapter.render_pre(_pre(agent, adapter, payload))
        project, cwd = adapter.project(payload), adapter.cwd(payload)
        if event in ('post', 'post-failed') and adapter.command(payload) is not None:
            text = ''
            if adapter.observes_shell and payload.get('tool_use_id'):
                text = observation.finish(adapter.name, adapter.session(payload), str(payload['tool_use_id']),
                                          project, failed=event == 'post-failed',
                                          command=adapter.command(payload) or '',
                                          tool=str(payload.get('tool_name') or 'shell'))
            return 0, adapter.render_observation(text, str(payload.get('hook_event_name')))
        if event == "post":
            groups: dict[Path, list[Path]] = {}
            for path in adapter.written(payload, cwd):
                groups.setdefault(adapter.root_for(payload, path), []).append(path)
            for root, paths in groups.items():
                engine.after_write(paths, root,
                                   record_contradictions=settings.mode("contradiction") == "record",
                                   transcript=adapter.transcript(payload), agent=adapter.name,
                                   session=adapter.session(payload), tool=str(payload.get("tool_name") or ""))
            return 0, adapter.render_allow(event)
        if event == "session":
            notice = session.notice(project, settings.mode("contradiction"), cwd=cwd)
            if adapter.name == "claude-code":
                notice = "\n".join(filter(None, (notice, session.upgrade_notice(project))))
            if notice:
                events.record("session_notice", agent=adapter.name, project=str(project), notice=notice[:1500])
            return 0, adapter.render_session(notice)
        return 0, adapter.render_allow(event)
    except Exception as e:  # noqa: BLE001
        _report_error(adapter.name, str(payload.get("hook_event_name", "unknown")), e)
        return 0, adapter.render_allow(event)


def _clean(payload: object) -> dict:
    """The event with every string fit to hash, store and print. JSON can spell half of a
    surrogate pair (`"\\ud83d"`); Python reads it as a character UTF-8 cannot encode."""
    if not isinstance(payload, dict):
        return {}
    try:
        text = json.dumps(payload, ensure_ascii=False)
        text.encode("utf-8")
        return payload
    except UnicodeEncodeError:
        cleaned = json.loads(text.encode("utf-8", "replace").decode("utf-8"))
        return cleaned if isinstance(cleaned, dict) else {}
    except (ValueError, TypeError, RecursionError):
        return payload


def _pre(agent: str, adapter: adapters.Adapter, payload: dict) -> policy.Decision:
    """The answer to a tool call about to run. An error while checking a write to agent
    context or to AgentDetox's own state asks; any other error lets the call through."""
    project = cwd = Path(os.getcwd())
    try:
        project, cwd = adapter.project(payload), adapter.cwd(payload)
        decision = _pre_tool_use(adapter, payload, project, cwd)
    except Exception as error:  # noqa: BLE001
        target = _unchecked_target(adapter, payload, project, cwd)
        _report_error(adapter.name, str(payload.get("hook_event_name", "unknown")), error, asking=target is not None)
        if target is None:
            return policy.Decision("allow")
        decision = policy.Decision(
            "ask" if adapter.can_ask else "deny",
            f"AgentDetox could not check {target} ({type(error).__name__}), so it is not let through unseen. "
            "Approve only if you expected this change; `agentdetox doctor` shows the error.")
    try:
        if decision.action != "allow" or decision.flags or decision.reason:
            events.record("write_checked", agent=adapter.name,
                          decision=decision.action if decision.action != "allow" else "record",
                          tool=payload.get("tool_name"), target=_target(adapter, payload, cwd),
                          reason=decision.reason[:500], flags=[asdict(f) for f in decision.flags],
                          **({"registered_for": agent} if agent != adapter.name else {}))
    except Exception as error:  # noqa: BLE001 - logging must not change the answer
        _report_error(adapter.name, 'pre-log', error, asking=decision.action != "allow")
    try:
        if (adapter.observes_shell and adapter.command(payload) is not None
                and payload.get('tool_use_id') and decision.action != 'deny'):
            observation.start(adapter.name, adapter.session(payload), str(payload['tool_use_id']), project)
    except Exception as error:  # noqa: BLE001
        _report_error(adapter.name, 'shell-start', error, asking=decision.action != "allow")
    return decision


def _unchecked_target(adapter: adapters.Adapter, payload: dict, project: Path, cwd: Path) -> str | None:
    """What a tool call that could not be checked is about, when that is agent context or
    AgentDetox's own state; None for anything else. Read as plainly as possible: this runs
    after something already failed."""
    try:
        command = adapter.command(payload)
    except Exception:  # noqa: BLE001
        command = None
    if command is not None:
        text = str(command)
        if shell.names_context(text) or "agentdetox" in text.lower() or str(store_dir()) in text:
            return "a shell command that names the agent's memory, rules or config, or AgentDetox"
        return None
    try:
        paths = [write.path for write in adapter.writes(payload, cwd)]
    except Exception:  # noqa: BLE001
        raw = json.dumps(payload.get("tool_input"), ensure_ascii=True, default=str)[:65536]
        return "a write whose target could not be read" if shell.names_context(raw) else None
    for path in paths:
        try:
            protected = engine.is_own_state(path) or classify(path, project=adapter.root_for(payload, path)) is not None
        except Exception:  # noqa: BLE001
            protected = shell.names_context(str(path))
        if protected:
            return f"this write to {short_path(str(path))}"
    return None


def _report_error(agent: str, stage: str, error: Exception, asking: bool = False) -> None:
    events.record('hook_error', agent=agent, stage=stage, error=type(error).__name__)
    outcome = 'asking instead of checking' if asking else 'ignored (failing open)'
    print(f'agentdetox: hook error {outcome}: {type(error).__name__}: {error}', file=sys.stderr)


def _target(adapter: adapters.Adapter, payload: dict, cwd: Path) -> str:
    """The command, or the files, a logged tool call was about."""
    command = adapter.command(payload)
    if command is not None:
        return command[:300]
    paths = adapter.written(payload, cwd) or [w.path for w in adapter.writes(payload, cwd)]
    return ", ".join(short_path(str(p)) for p in paths)[:300]


def _pre_tool_use(adapter: adapters.Adapter, payload: dict, project: Path, cwd: Path) -> policy.Decision:
    # Relative paths in the tool input are relative to cwd; which files count as the
    # project's context depends on the project root.
    modes = {s.key: s.value for s in settings.load()[0]}
    command = adapter.command(payload)
    transcript = adapter.transcript(payload)
    if command is not None:
        decision = policy.decide(engine.check_command(command, project, cwd), adapter.can_ask, modes)
        # A patch fed to the shell (`apply_patch <<EOF`, or as an argument) is checked as the
        # patch it is, in every folder the command may have entered before applying it.
        fed_patches = shell.patches_in(command, patches.BEGIN)
        folders = [shell.resolve(folder, cwd) if folder else cwd
                   for folder in (shell.patch_folders(shell.split(command)) if fed_patches else [])] or [cwd]
        fed = [write for body in fed_patches for folder in dict.fromkeys(folders)
               for write in adapter.writes({"tool_input": {"command": body}}, folder)]
        if not fed:
            return decision
        return policy.combine([decision] + _check_writes(adapter, payload, fed, modes, transcript))
    writes = adapter.writes(payload, cwd)
    try:
        engine.before_write([w.path for w in writes if w.new is not None], project)
        for w in writes:
            if w.new is None:
                root = adapter.root_for(payload, w.path)
                engine.before_removal(engine.removal_targets(w.path, root), root, adapter.name)
    except StoreError as error:
        # Bookkeeping only: the content check below must still run, or holding the store
        # lock would let any write through.
        _report_error(adapter.name, 'before-write', error)
    return policy.combine(_check_writes(adapter, payload, writes, modes, transcript))


def _check_writes(adapter: adapters.Adapter, payload: dict, writes: list[engine.Write], modes: dict[str, str],
                  transcript: str | None) -> list[policy.Decision]:
    run = policy.checks_to_run(modes)
    return [policy.decide(engine.check_write(w, adapter.root_for(payload, w.path), run, transcript),
                          adapter.can_ask, modes) for w in writes]


def main_hook(agent: str) -> int:
    # Bytes, so the event is read as UTF-8 whatever the locale (cp1252 on many Windows setups).
    raw = sys.stdin.buffer.read()
    try:
        payload = json.loads(raw or b"{}")
        unread = "" if isinstance(payload, dict) else type(payload).__name__
    except (ValueError, RecursionError) as error:
        payload, unread = {}, type(error).__name__
    if unread:
        # Nothing can be checked without the event; doctor and status show that one was lost.
        events.record('hook_error', agent=agent, stage='stdin', error=unread)
        payload = {}
    code, out = handle(agent, payload)
    if out:
        print(out)
    return code
