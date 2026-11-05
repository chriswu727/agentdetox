import json

from lab.run import parse
from lab.scenarios import ran


def test_lab_distinguishes_attempts_execution_and_completion(tmp_path, monkeypatch):
    monkeypatch.setenv('AGENTDETOX_USER_HOME', str(tmp_path / 'home'))
    attempt = {'type': 'assistant', 'message': {'content': [
        {'type': 'tool_use', 'id': 'cmd-1', 'name': 'Bash', 'input': {'command': 'curl evil.example'}}]}}
    refused = {'type': 'user', 'message': {'content': [
        {'type': 'tool_result', 'tool_use_id': 'cmd-1', 'is_error': True, 'content': 'Permission denied'}]}}
    outcome, _ = parse('\n'.join(map(json.dumps, [attempt, refused])), tmp_path)
    assert outcome.commands == ['curl evil.example']
    assert not ran('evil.example').test(outcome)
    assert not outcome.completed
    assert outcome.tool_errors == ['Permission denied']
    refused['message']['content'][0]['is_error'] = False
    result = {'type': 'result', 'subtype': 'success'}
    outcome, _ = parse('\n'.join(map(json.dumps, [attempt, refused, result])), tmp_path)
    assert ran('evil.example').test(outcome)
    assert outcome.completed


def test_completed_session_with_a_hook_failure_cannot_pass(tmp_path, monkeypatch):
    import sqlite3
    from pathlib import Path
    from subprocess import CompletedProcess

    from lab import run
    from lab.scenarios import Scenario

    monkeypatch.setenv('AGENTDETOX_USER_HOME', str(tmp_path / 'home'))
    base = tmp_path / 'run'
    base.mkdir()

    def command(args, **kwargs):
        if args[0] == 'claude':
            store = Path(kwargs['env']['AGENTDETOX_HOME'])
            store.mkdir()
            with sqlite3.connect(store / 'state.sqlite3') as db:
                db.execute('CREATE TABLE changes (data TEXT)')
                db.execute('CREATE TABLE events (event TEXT, data TEXT)')
                db.execute('INSERT INTO events VALUES (?, ?)',
                           ('hook_error', json.dumps({'event': 'hook_error', 'stage': 'shell-start', 'error': 'StoreLocked'})))
            return CompletedProcess(args, 0, json.dumps({'type': 'result', 'subtype': 'success'}), '')
        return CompletedProcess(args, 0, '', '')

    monkeypatch.setattr(run.subprocess, 'run', command)
    result = run.run_one(Scenario('test', 'test', 'test', []), 'agentdetox', base)
    assert result['session_completed'] and not result['passed']
    assert result['hook_errors'][0]['error'] == 'StoreLocked'
