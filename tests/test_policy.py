"""The policy table: what each kind of signal leads to, per setting and per agent."""

import pytest

from agentdetox import policy
from agentdetox.allowlist import Flag
from agentdetox.engine import CONTRADICTION, COPIED, GUARDRAILS, OWN_STATE, PLANTED, SHELL_WRITE, SUSPICIOUS, Signal

ASK = {SUSPICIOUS: "ask", COPIED: "ask", CONTRADICTION: "ask"}
RECORD = {k: "record" for k in ASK}
OFF = {k: "off" for k in ASK}


def signal(check, flag_id=None):
    return Signal(check, f"{check} found.", [Flag(flag_id, check)] if flag_id else [])


@pytest.mark.parametrize("can_ask", [True, False])
def test_planted_instructions_are_always_denied(can_ask):
    d = policy.decide([signal(PLANTED, "a" * 10)], can_ask, OFF)
    assert d.action == "deny" and "agentdetox allow aaaaaaaaaa" in d.reason and [f.id for f in d.flags] == ["a" * 10]


@pytest.mark.parametrize("check", [OWN_STATE, GUARDRAILS])
def test_guardrail_changes_ask_where_the_agent_can_and_are_denied_elsewhere(check):
    assert policy.decide([signal(check)], True, RECORD).action == "ask"
    denied = policy.decide([signal(check)], False, RECORD)
    assert denied.action == "deny" and "Make this change yourself" in denied.reason


def test_the_environment_can_allow_config_writes_but_not_changes_to_agentdetox(monkeypatch):
    monkeypatch.setenv("AGENTDETOX_ALLOW_CONFIG_WRITES", "1")
    assert policy.decide([signal(GUARDRAILS)], False, RECORD) == policy.Decision("allow")
    assert policy.decide([signal(OWN_STATE)], False, RECORD).action == "deny"


@pytest.mark.parametrize("check", [SUSPICIOUS, COPIED, CONTRADICTION])
@pytest.mark.parametrize("mode,can_ask,action,logged", [
    ("ask", True, "ask", True),
    ("ask", False, "allow", True),       # no ask prompt: recorded instead
    ("record", True, "allow", True),
    ("off", True, "allow", False),
])
def test_configurable_checks_follow_the_settings(check, mode, can_ask, action, logged):
    d = policy.decide([signal(check, "b" * 10)], can_ask, {**OFF, check: mode})
    assert d.action == action and bool(d.flags) is logged and bool(d.reason) is logged


def test_a_shell_write_to_context_asks_only_where_the_agent_can():
    assert policy.decide([signal(SHELL_WRITE)], True, RECORD).action == "ask"
    assert policy.decide([signal(SHELL_WRITE)], False, RECORD) == policy.Decision("allow")


def test_an_ask_names_every_flagged_id_so_each_can_be_allowed():
    d = policy.decide([signal(SUSPICIOUS, "c" * 10), signal(COPIED, "d" * 10)], True, {**RECORD, COPIED: "ask"})
    assert d.action == "ask" and d.reason.startswith(f"{COPIED} found.") and "cccccccccc dddddddddd" in d.reason


def test_record_mode_contradictions_are_left_to_the_background():
    assert policy.checks_to_run(ASK) == {SUSPICIOUS, COPIED, CONTRADICTION}
    assert policy.checks_to_run(RECORD) == {SUSPICIOUS, COPIED}
    assert policy.checks_to_run(OFF) == set()


def test_a_call_writing_several_files_gets_the_strictest_answer():
    noted = policy.Decision("allow", "noted.", [Flag("e" * 10, "x")])
    asked, denied = policy.Decision("ask", "asked."), policy.Decision("deny", "denied.")
    assert policy.combine([noted, asked, denied]) == policy.Decision("deny", "denied.", noted.flags)
    assert policy.combine([noted, asked]).reason == "asked."
    assert policy.combine([noted]) == noted and policy.combine([]) == policy.Decision("allow")
