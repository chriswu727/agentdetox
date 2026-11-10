"""Agent hook entry point: an agent's event in, its reply out.

PreToolUse   checks a planned write to persistent context and denies, asks or records.
PostToolUse records edit-tool writes or compares context across a shell tool.
PostToolUseFailure compares shell context even when the tool failed.
SessionStart reports context changed out-of-band since the last check.

Claude Code, Codex and Cursor name these events differently (adapters.py). Codex sends
PostToolUse after a failed command too; Cursor sends postToolUseFailure.

adapters.py reads each agent's protocol, engine.py checks, policy.py decides, and
session.py runs the session-start check. Handlers fail open: an error inside AgentDetox
must never break the agent.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import adapters, engine, events, observation, policy, session, settings, shell
from . import patch as patches
from .context import short_path
from .integrity import StoreError


def handle(agent: str, payload: dict) -> tuple[int, str]:
    # The command names the agent the hook was registered for; the event says which agent
    # is running it (Cursor runs the hooks in Claude Code's settings on its own events).
    adapter = adapters.resolve(agent, payload)
    event = ""
    try:
        event, project, cwd = adapter.event(payload), adapter.project(payload), adapter.cwd(payload)
        if event == "pre":
            decision = _pre_tool_use(adapter, payload, project, cwd)
            if decision.action != "allow" or decision.flags or decision.reason:
                events.record("write_checked", agent=adapter.name,
                              decision=decision.action if decision.action != "allow" else "record",
                              tool=payload.get("tool_name"), target=_target(adapter, payload, cwd),
                              reason=decision.reason[:500], flags=[asdict(f) for f in decision.flags],
                              **({"registered_for": agent} if agent != adapter.name else {}))
            if (adapter.observes_shell and adapter.command(payload) is not None
                    and payload.get('tool_use_id') and decision.action != 'deny'):
                try:
                    observation.start(adapter.name, adapter.session(payload), str(payload['tool_use_id']), project)
                except Exception as error:
                    _report_error(adapter.name, 'shell-start', error)
            return 0, adapter.render_pre(decision)
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


def _report_error(agent: str, stage: str, error: Exception) -> None:
    events.record('hook_error', agent=agent, stage=stage, error=type(error).__name__)
    print(f'agentdetox: hook error ignored (failing open): {type(error).__name__}: {error}', file=sys.stderr)


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
        # A patch fed to the shell (`apply_patch <<EOF`) is checked as the patch it is.
        fed = [write for _, body in shell.heredocs(command)[1] if body.lstrip().startswith(patches.BEGIN)
               for write in adapter.writes({"tool_input": {"command": body}}, cwd)]
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
    try:
        # Bytes, so the event is read as UTF-8 whatever the locale (cp1252 on many Windows setups).
        payload = json.loads(sys.stdin.buffer.read() or b"{}")
    except ValueError:
        payload = {}
    code, out = handle(agent, payload)
    if out:
        print(out)
    return code
