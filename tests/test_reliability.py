import json
import os
import stat

import pytest

from agentdetox import doctor, events, hooks, session
from agentdetox.context import discover
from agentdetox.install import claude_code_settings, hook_command
from agentdetox.integrity import StoreError, baseline_entries, restore, snapshot, store_dir


@pytest.fixture
def context(tmp_path, monkeypatch):
    home, project = tmp_path / 'home', tmp_path / 'project'
    monkeypatch.setenv('AGENTDETOX_USER_HOME', str(home))
    project.mkdir()
    path = home / '.claude/settings.json'
    path.parent.mkdir(parents=True)
    path.write_text(json.dumps(claude_code_settings({}, hook_command('claude-code'))))
    path.chmod(0o600)
    (project / 'CLAUDE.md').write_text('Use pnpm.\n')
    snapshot(discover(project=project), [home, project])
    return home, project, path


def test_disabling_hooks_is_guarded_and_visible(context):
    home, project, path = context
    data = json.loads(path.read_text())
    data['disableAllHooks'] = True
    _, reply = hooks.handle('claude-code', {'hook_event_name': 'PreToolUse', 'cwd': str(project),
        'tool_name': 'Write', 'tool_input': {'file_path': str(path), 'content': json.dumps(data)}})
    assert json.loads(reply)['hookSpecificOutput']['permissionDecision'] == 'ask'
    path.write_text(json.dumps(data))
    assert 'disabled' in session.notice(project, 'off')
    assert any(c.status == 'fail' and 'disableAllHooks' in c.message for c in doctor.run(project))


def test_deleted_config_remains_restorable_and_reported(context):
    _, project, path = context
    path.unlink()
    assert 'deleted' in session.notice(project, 'off')
    assert 'deleted' in session.notice(project, 'off')
    assert str(path) in baseline_entries()
    assert restore(path) is None
    assert 'hooks' in json.loads(path.read_text())


def test_no_current_files_does_not_reinitialize_baseline(context):
    _, project, path = context
    path.unlink()
    (project / 'CLAUDE.md').unlink()
    assert 'deleted' in session.notice(project, 'off')
    restore(path)
    assert path.exists()


@pytest.mark.skipif(os.name == 'nt', reason='POSIX file permissions')
def test_restored_permissions_and_unique_quarantine(context):
    _, _, path = context
    path.write_text('first')
    first = restore(path)
    assert stat.S_IMODE(path.stat().st_mode) == 0o600
    path.write_text('second')
    second = restore(path)
    assert first != second
    assert first.read_text() == 'first'
    assert second.read_text() == 'second'


@pytest.mark.parametrize('damage', ['missing', 'corrupt'])
def test_invalid_recovery_copy_never_moves_current_file(context, damage):
    _, _, path = context
    obj = store_dir() / 'objects' / baseline_entries()[str(path)]['sha256']
    obj.unlink() if damage == 'missing' else obj.write_text('corrupt')
    path.write_text('current')
    with pytest.raises(StoreError):
        restore(path)
    assert path.read_text() == 'current'


def test_backup_and_replace_failures_leave_original(context, monkeypatch):
    from pathlib import Path

    from agentdetox import integrity

    _, _, path = context
    path.write_text('current')
    original = integrity.write_private

    def fail_backup(target, data):
        if target.name == 'content':
            raise OSError('disk full')
        return original(target, data)

    with monkeypatch.context() as m:
        m.setattr(integrity, 'write_private', fail_backup)
        with pytest.raises(OSError):
            restore(path)
    assert path.read_text() == 'current'
    original_replace = Path.replace

    def fail_replace(self, target):
        if self.name.startswith('.agentdetox-restore-'):
            raise OSError('replace failed')
        return original_replace(self, target)

    monkeypatch.setattr(Path, 'replace', fail_replace)
    with pytest.raises(OSError):
        restore(path)
    assert path.read_text() == 'current'
    assert any(p.read_text() == 'current' for p in (store_dir() / 'quarantine').glob('*/content'))
    assert not list(path.parent.glob('.agentdetox-restore-*'))


def test_failed_hook_is_visible_after_process_returns(context, monkeypatch):
    from agentdetox import engine

    _, project, path = context
    monkeypatch.setattr(engine, 'check_command', lambda *a: 1 / 0)
    assert hooks.handle('claude-code', {'hook_event_name': 'PreToolUse', 'cwd': str(project),
                                      'tool_name': 'Bash', 'tool_input': {'command': 'pwd'}}) == (0, '')
    assert any(r['event'] == 'hook_error' for r in events.read(None))
    assert any(c.status == 'fail' and 'degraded' in c.message for c in doctor.run(project))
