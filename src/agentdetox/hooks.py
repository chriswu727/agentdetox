"""Agent hook entry point: an agent's event in, its reply out.

PreToolUse   checks a planned write to persistent context and denies or asks.
PostToolUse  re-trusts a context file the agent just wrote, so the snapshot only ever
             lags behind writes that bypassed the agent's tools.
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

from . import adapters, engine, events, policy, session, settings


def handle(agent: str, payload: dict) -> tuple[int, str]:
    adapter = adapters.get(agent)
    try:
        event, project = adapter.event(payload), adapter.project(payload)
        if event == "pre":
            decision = _pre_tool_use(adapter, payload, project)
            if decision.action != "allow" or decision.flags:
                events.record("write_checked", agent=agent,
                              decision=decision.action if decision.action != "allow" else "record",
                              tool=payload.get("tool_name"), reason=decision.reason[:500],
                              flags=[asdict(f) for f in decision.flags])
            return 0, adapter.render_pre(decision)
        if event == "post":
            engine.after_write(adapter.written(payload, project), project,
                               record_contradictions=settings.mode("contradiction") == "record")
            return 0, adapter.render_allow()
        if event == "session":
            notice = session.notice(project, settings.mode("contradiction"))
            if notice:
                events.record("session_notice", agent=agent, project=str(project), notice=notice[:1500])
            return 0, adapter.render_session(notice)
        return 0, adapter.render_allow()
    except Exception as e:  # noqa: BLE001
        print(f"agentdetox: hook error ignored (failing open): {type(e).__name__}: {e}", file=sys.stderr)
        return 0, adapter.render_allow()


def _pre_tool_use(adapter: adapters.Adapter, payload: dict, project: Path) -> policy.Decision:
    modes = {s.key: s.value for s in settings.load()[0]}
    command = adapter.command(payload)
    if command is not None:
        return policy.decide(engine.check_command(command, project), adapter.can_ask, modes)
    run, transcript = policy.checks_to_run(modes), adapter.transcript(payload)
    return policy.combine([policy.decide(engine.check_write(w, project, run, transcript), adapter.can_ask, modes)
                           for w in adapter.writes(payload, project)])


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
