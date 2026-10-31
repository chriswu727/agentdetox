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
    refused['message']['content'][0]['is_error'] = False
    result = {'type': 'result', 'subtype': 'success'}
    outcome, _ = parse('\n'.join(map(json.dumps, [attempt, refused, result])), tmp_path)
    assert ran('evil.example').test(outcome)
    assert outcome.completed
