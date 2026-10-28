"""What to do about what the engine found: block it, ask the user, or let it through and
log it. The user's settings and what each agent can do come in here, not in the checks.

- A clear-cut planted instruction is always blocked, unless the user typed or pasted it
  themselves: then it asks, and is blocked where the agent cannot ask.
- A change to AgentDetox's own state, or to the agent's own hooks, MCP servers or
  permissions, asks where the agent can ask and is blocked where it cannot.
- Suspicious, copied and contradicting writes follow the user's settings. "ask" falls
  back to recording on agents that cannot ask.
"""

from __future__ import annotations

import os
from dataclasses import dataclass, field

from .allowlist import Flag
from .engine import CONTRADICTION, COPIED, GUARDRAILS, OWN_STATE, PLANTED, SHELL_WRITE, SUSPICIOUS, USER_WRITTEN, Signal

_DENY_HINT = {OWN_STATE: "Make this change yourself.",
              GUARDRAILS: "Make this change yourself, or set AGENTDETOX_ALLOW_CONFIG_WRITES=1."}


@dataclass
class Decision:
    action: str  # "allow", "ask", "deny"
    reason: str = ""
    # Everything flagged, including checks set to "record": an "allow" with flags is
    # logged, not silently dropped.
    flags: list[Flag] = field(default_factory=list)


def checks_to_run(modes: dict[str, str]) -> set[str]:
    """The configurable checks a write check does. Contradictions in record mode are
    checked after the write, in the background, so the hook does not wait for the model."""
    run = {check for check in (SUSPICIOUS, COPIED) if modes[check] != "off"}
    return run | {CONTRADICTION} if modes[CONTRADICTION] == "ask" else run


def decide(signals: list[Signal], can_ask: bool, modes: dict[str, str]) -> Decision:
    signals = [s for s in signals if modes.get(s.check) != "off"]
    flags = [f for s in signals for f in s.flags]
    planted = [s for s in signals if s.check == PLANTED]
    if planted:
        return Decision("deny", with_ids(" ".join(s.reason for s in planted), flags), flags)
    typed = [s for s in signals if s.check == USER_WRITTEN]
    if typed:
        return Decision("ask" if can_ask else "deny", with_ids(" ".join(s.reason for s in typed), flags), flags)
    guards = [s for s in signals if s.check in _DENY_HINT
              and not (s.check == GUARDRAILS and os.environ.get("AGENTDETOX_ALLOW_CONFIG_WRITES"))]
    if guards:
        if can_ask:
            return Decision("ask", " ".join(f"{s.reason} Approve only if you asked for this change." for s in guards))
        return Decision("deny", " ".join(f"{s.reason} {_DENY_HINT[s.check]}" for s in guards))
    asked: list[str] = []
    recorded: list[str] = []
    for s in signals:
        if s.check == SHELL_WRITE:
            if can_ask:
                asked.append(s.reason)
        elif s.check in modes:
            (asked if modes[s.check] == "ask" and can_ask else recorded).append(s.reason)
    if asked:
        return Decision("ask", with_ids(" ".join(asked), flags), flags)
    return Decision("allow", " ".join(recorded), flags)


def combine(decisions: list[Decision]) -> Decision:
    """One answer for a tool call that writes several files (a Codex patch)."""
    flags = [f for d in decisions for f in d.flags]
    for action in ("deny", "ask"):
        hits = [d for d in decisions if d.action == action]
        if hits:
            return Decision(action, " ".join(d.reason for d in hits), flags)
    return Decision("allow", " ".join(d.reason for d in decisions if d.reason), flags)


def with_ids(reason: str, flags: list[Flag]) -> str:
    ids = " ".join(dict.fromkeys(f.id for f in flags))
    if not ids:
        return reason
    return f"{reason} [AgentDetox id {ids}. False positive? `agentdetox allow {ids}` stops it being flagged again.]"
