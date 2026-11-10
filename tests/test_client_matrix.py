"""The shared client corpus (client_corpus.py), walked in-process: every layout of every
client against every content case, and every hook event against the reply its client
expects. A pass says the files are found, flagged, cleaned exactly and restorable. It does
not say a client delivers the events: only those marked `recorded` were ever seen from one."""

import io
from contextlib import redirect_stderr, redirect_stdout

import pytest
from client_corpus import (
    CASES,
    EVENTS,
    FALSE_ALARMS,
    LAYOUTS,
    MISSES,
    MUST_FLAG,
    MUST_PASS,
    REFUSED,
    Roots,
    place,
    reply_kind,
    walk,
)

from agentdetox import events as event_log
from agentdetox.agentscan import scan_text
from agentdetox.cli import main
from agentdetox.hooks import handle

_RELOCATION = ('CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_PROJECT_DIR_NAME', 'CURSOR_CONFIG_DIR', 'CURSOR_PROJECT_DIR',
               'XDG_CONFIG_HOME', 'OPENCLAW_HOME', 'OPENCLAW_PROFILE', 'OPENCLAW_STATE_DIR', 'OPENCLAW_CONFIG_PATH',
               'OPENCLAW_WORKSPACE_DIR')


@pytest.fixture
def roots(tmp_path, monkeypatch):
    found = Roots(tmp_path / 'home', tmp_path / 'project', tmp_path / 'elsewhere')
    monkeypatch.setenv('AGENTDETOX_USER_HOME', str(found.home))
    for name in _RELOCATION:
        monkeypatch.delenv(name, raising=False)
    for folder in (found.home, found.project, found.elsewhere):
        folder.mkdir()
    return found


def cli(args):
    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as stop:
            code = stop.code
    return code, out.getvalue(), err.getvalue()


@pytest.mark.parametrize('case', CASES, ids=lambda case: case.name)
@pytest.mark.parametrize('layout', LAYOUTS, ids=lambda layout: layout.name)
def test_a_clients_file_is_found_cleaned_exactly_and_restored(layout, case, roots, monkeypatch):
    if layout.kind not in case.kinds:
        pytest.skip('this case is about prose files')
    target, env = place(layout, roots)
    for name, value in env.items():
        monkeypatch.setenv(name, value)
    steps = walk(layout, case, roots, cli, target)
    # Cleanup by change id is supported on every platform: a refusal is a failure here, whatever
    # a report may call it.
    assert steps and REFUSED not in steps


def test_the_corpus_claims_only_the_layouts_each_client_documents():
    variants = {agent: {layout.variant for layout in LAYOUTS if layout.agent == agent}
                for agent in ('claude-code', 'codex', 'cursor', 'openclaw')}
    assert variants == {
        'claude-code': {'default', 'relocated', 'nested'},
        'codex': {'default', 'relocated', 'nested'},
        'cursor': {'default', 'nested'},        # CURSOR_CONFIG_DIR moves only the CLI's config, which is not prose
        'openclaw': {'default', 'relocated'},   # OpenClaw has no project files to nest
    }
    for layout in LAYOUTS:
        assert layout.source
        assert (layout.variant == 'relocated') == bool(layout.env(_PLACEHOLDER) or layout.files(_PLACEHOLDER)), layout.name


_PLACEHOLDER = Roots(*(__import__('pathlib').Path(name) for name in ('/home', '/project', '/elsewhere')))


def _send(event, roots, sent):
    for name in event.setup:
        if name not in sent:
            _send(next(e for e in EVENTS if e.name == name), roots, sent)
    if event.before is not None:
        event.before(roots)
    sent.add(event.name)
    payload = event.payload(roots)
    code, out = handle(event.agent, payload)
    assert code == 0
    return payload, out


@pytest.mark.parametrize('event', EVENTS, ids=lambda event: event.name)
def test_a_hook_event_gets_the_reply_its_client_reads(event, roots):
    assert event.evidence.split(':')[0] in ('recorded', 'official-doc', 'synthetic')
    payload, out = _send(event, roots, set())
    assert reply_kind(event.agent, payload['hook_event_name'], out) == event.reply, out
    if event.registered_as:
        checked = [row for row in event_log.read(None) if row.get('event') == 'write_checked']
        assert checked and checked[-1]['agent'] == event.registered_as and checked[-1]['registered_for'] == event.agent
        assert checked[-1]['decision'] != 'ask'
    assert not [row for row in event_log.read(None) if row.get('event') == 'hook_error']


def test_only_recorded_events_count_as_seen_from_a_client():
    recorded = {event.agent for event in EVENTS if event.evidence.startswith('recorded')}
    assert recorded == {'codex'}, 'a client was marked as recorded without a capture from it'


@pytest.mark.xfail(strict=True, reason='a known miss of the rules: this text is never offered for review')
@pytest.mark.parametrize('text', [text for _, text in MISSES], ids=[what for what, _ in MISSES])
def test_known_miss_hostile_text_is_flagged(text):
    assert [f for f in scan_text('notes.md', 'notes.md', text + '\n', 'memory') if f.severity in ('medium', 'high')]


@pytest.mark.xfail(strict=True, reason='a known false alarm of the rules: this benign text is put up for review')
@pytest.mark.parametrize('kind,text', [(kind, text) for _, kind, text in FALSE_ALARMS],
                         ids=[what for what, _, _ in FALSE_ALARMS])
def test_known_false_alarm_benign_text_is_left_alone(kind, text):
    assert not [f for f in scan_text('notes.md', 'notes.md', text + '\n', kind) if f.severity == 'high']


KINDS = ('memory', 'instructions', 'skill')


@pytest.mark.parametrize('kind', KINDS)
@pytest.mark.parametrize('text', [text for _, text in MUST_FLAG], ids=[what for what, _ in MUST_FLAG])
def test_corrected_miss_is_flagged_as_clear_cut(text, kind):
    assert any(f.severity == 'high' for f in scan_text('notes.md', 'notes.md', text + '\n', kind))


@pytest.mark.parametrize('kind,text', [(kind, text) for _, kind, text in MUST_PASS], ids=[what for what, _, _ in MUST_PASS])
def test_corrected_false_alarm_raises_nothing(kind, text):
    assert kind in KINDS
    for each in KINDS:      # benign where it was listed, and no less so in the other kinds of file
        assert not [f for f in scan_text('notes.md', 'notes.md', text + '\n', each) if f.severity in ('medium', 'high')], each


def test_the_paraphrased_fetch_and_run_case_is_walked_for_every_client():
    assert any(case.name == 'paraphrased fetch-and-run' and case.outcome == 'cleaned' for case in CASES)
    assert {layout.agent for layout in LAYOUTS} == {'claude-code', 'codex', 'cursor', 'openclaw'}
