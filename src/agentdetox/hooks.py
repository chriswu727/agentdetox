"""Agent hook entry point: an agent's event in, its reply out.

PreToolUse   checks a planned write to persistent context and denies or asks.
PostToolUse records edit-tool writes or compares context across a shell tool.
PostToolUseFailure compares shell context even when the tool failed.
SessionStart reports context changed out-of-band since the last check.

adapters.py reads each agent's protocol, engine.py checks, policy.py decides, and
session.py runs the session-start check. Handlers fail open: an error inside AgentDetox
must never break the agent.
"""

from __future__ import annotations

import json
import sys
from dataclasses import asdict
from pathlib import Path

from . import adapters, engine, events, observation, policy, session, settings
from .context import short_path


def handle(agent: str, payload: dict) -> tuple[int, str]:
    adapter = adapters.get(agent)
    try:
        event, project = adapter.event(payload), adapter.project(payload)
        if event == "pre":
            decision = _pre_tool_use(adapter, payload, project)
            if decision.action != "allow" or decision.flags:
                events.record("write_checked", agent=agent,
                              decision=decision.action if decision.action != "allow" else "record",
                              tool=payload.get("tool_name"), target=_target(adapter, payload, project),
                              reason=decision.reason[:500], flags=[asdict(f) for f in decision.flags])
            if (adapter.observes_shell and adapter.command(payload) is not None
                    and payload.get('tool_use_id') and decision.action != 'deny'):
                try:
                    observation.start(adapter.name, adapter.session(payload), str(payload['tool_use_id']), project)
                except Exception as error:
                    _report_error(agent, 'shell-start', error)
            return 0, adapter.render_pre(decision)
        if event in ('post', 'post-failed') and adapter.command(payload) is not None:
            text = ''
            if adapter.observes_shell and payload.get('tool_use_id'):
                text = observation.finish(adapter.name, adapter.session(payload), str(payload['tool_use_id']),
                                          project, failed=event == 'post-failed')
            return 0, adapter.render_observation(text, str(payload.get('hook_event_name')))
        if event == "post":
            engine.after_write(adapter.written(payload, project), project,
                               record_contradictions=settings.mode("contradiction") == "record",
                               transcript=adapter.transcript(payload), agent=adapter.name,
                               session=adapter.session(payload), tool=str(payload.get("tool_name") or ""))
            return 0, adapter.render_allow()
        if event == "session":
            notice = session.notice(project, settings.mode("contradiction"))
            if notice:
                events.record("session_notice", agent=agent, project=str(project), notice=notice[:1500])
            return 0, adapter.render_session(notice)
        return 0, adapter.render_allow()
    except Exception as e:  # noqa: BLE001
        _report_error(agent, str(payload.get("hook_event_name", "unknown")), e)
        return 0, adapter.render_allow()


def _report_error(agent: str, stage: str, error: Exception) -> None:
    events.record('hook_error', agent=agent, stage=stage, error=type(error).__name__)
    print(f'agentdetox: hook error ignored (failing open): {type(error).__name__}: {error}', file=sys.stderr)


def _target(adapter: adapters.Adapter, payload: dict, project: Path) -> str:
    """The command, or the files, a logged tool call was about."""
    command = adapter.command(payload)
    if command is not None:
        return command[:300]
    paths = adapter.written(payload, project) or [w.path for w in adapter.writes(payload, project)]
    return ", ".join(short_path(str(p)) for p in paths)[:300]


def _pre_tool_use(adapter: adapters.Adapter, payload: dict, project: Path) -> policy.Decision:
    modes = {s.key: s.value for s in settings.load()[0]}
    command = adapter.command(payload)
    if command is not None:
        return policy.decide(engine.check_command(command, project), adapter.can_ask, modes)
    run, transcript = policy.checks_to_run(modes), adapter.transcript(payload)
    writes = adapter.writes(payload, project)
    engine.before_write([w.path for w in writes], project)
    return policy.combine([policy.decide(engine.check_write(w, project, run, transcript), adapter.can_ask, modes)
                           for w in writes])


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
