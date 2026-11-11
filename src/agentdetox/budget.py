"""How long one piece of text may be checked.

A rule is a pattern, and a pattern runs to its end once started. So the time is looked at
between rules: a rule that turns out slow on some text costs its own time once, and the
rules after it are not run. The answer is then OverBudget, never a partial result: text
that was only half checked must not read as checked.
"""

from __future__ import annotations

import contextlib
import contextvars
import time

# Ordinary context files take milliseconds. This is for text built to be slow.
SECONDS = 15.0

_deadline: contextvars.ContextVar[float | None] = contextvars.ContextVar("agentdetox_scan_deadline", default=None)


class OverBudget(Exception):
    """Checking took longer than it may; what the rest of the rules would have found is unknown."""


@contextlib.contextmanager
def limit(seconds: float | None = None):
    """Checks inside share one deadline. An inner limit never extends an outer one."""
    current = _deadline.get()
    wanted = time.monotonic() + (SECONDS if seconds is None else seconds)
    token = _deadline.set(wanted if current is None else min(current, wanted))
    try:
        yield
    finally:
        _deadline.reset(token)


def check() -> None:
    deadline = _deadline.get()
    if deadline is not None and time.monotonic() >= deadline:
        raise OverBudget("checking this text took too long")
