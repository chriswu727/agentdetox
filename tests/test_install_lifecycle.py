import json
import os
import stat
from pathlib import Path

import pytest

from agentdetox import install
from agentdetox.cli import main
from agentdetox.integrity import StoreError


@pytest.fixture
def context(tmp_path, monkeypatch):
    home, project = tmp_path / 'home', tmp_path / 'project'
    project.mkdir()
    path = home / '.claude/settings.json'
    path.parent.mkdir(parents=True)
    monkeypatch.setenv('AGENTDETOX_USER_HOME', str(home))
    return project, path


@pytest.mark.parametrize('action', ['install', 'uninstall'])
def test_mixed_groups_keep_other_handlers_and_group_settings(context, action):
    project, path = context
    theirs = [{'type': 'command', 'command': 'node audit.js', 'timeout': 10},
              {'type': 'prompt', 'prompt': 'Review the action'}]
    group = {'matcher': 'Bash', 'metadata': {'purpose': 'user checks'}, 'hooks': [
        theirs[0], {'type': 'command', 'command': install.hook_command('claude-code')}, theirs[1]]}
    data = {'hooks': {'PreToolUse': [group]}, 'model': 'test'}
    path.write_text(json.dumps(data), encoding='utf-8')
    args = [action, 'claude-code', '--project', str(project)] + (['--apply'] if action == 'install' else [])
    assert main(args) == 0
    after = json.loads(path.read_text())
    assert after['model'] == 'test'
    assert after['hooks']['PreToolUse'][0] == {**group, 'hooks': theirs}
    if action == 'install':
        assert main(args) == 0
        assert json.loads(path.read_text()) == after


@pytest.mark.parametrize('data', [{'hooks': {}}, {'hooks': {'SessionStart': []}}, {'hooks': {'SessionStart': [{'hooks': []}]}}])
def test_uninstall_without_our_handlers_is_a_noop(context, data):
    _, path = context
    original = json.dumps(data)
    path.write_text(original)
    assert install.uninstall_claude_code(path) == (False, None)
    assert path.read_text() == original
    assert not list(path.parent.glob('*.agentdetox-backup-*'))


@pytest.mark.parametrize('text', ['{', '[]', 'null', '{"hooks":null}', '{"hooks":{"SessionStart":{}}}',
                                '{"hooks":{"SessionStart":[null]}}',
                                '{"hooks":{"SessionStart":[{"hooks":null}]}}',
                                '{"hooks":{"SessionStart":[{"hooks":[{"command":1}]}]}}'])
@pytest.mark.parametrize('action', ['install', 'uninstall', 'doctor'])
def test_invalid_settings_give_actionable_errors_without_mutation(context, capsys, text, action):
    project, path = context
    path.write_text(text)
    args = [action] + ([] if action == 'doctor' else ['claude-code']) + ['--project', str(project)]
    if action == 'install':
        args.append('--apply')
    assert main(args) == (1 if action == 'doctor' else 2)
    output = capsys.readouterr()
    assert 'Fix the settings file and retry' in output.out + output.err
    assert 'Traceback' not in output.out + output.err
    assert path.read_text() == text
    assert not list(path.parent.glob('*.agentdetox-backup-*'))


def test_rapid_updates_keep_every_backup(context, monkeypatch):
    _, path = context
    monkeypatch.setattr(install.time, 'strftime', lambda _: 'fixed-second')
    path.write_text('original')
    path.chmod(0o600)
    first = install._write_with_backup(path, 'updated')
    second = install._write_with_backup(path, 'final')
    assert first != second
    assert first.read_text() == 'original'
    assert second.read_text() == 'updated'
    assert path.read_text() == 'final'
    if os.name != 'nt':
        assert all(stat.S_IMODE(p.stat().st_mode) == 0o600 for p in (path, first, second))


@pytest.mark.parametrize('stage', ['backup', 'replace'])
def test_failed_install_write_keeps_original_and_removes_partial_files(context, monkeypatch, stage):
    _, path = context
    path.write_text('original')
    if stage == 'backup':
        def fail_copy(source, target):
            Path(target).write_text('partial')
            raise OSError('disk full')
        monkeypatch.setattr(install.shutil, 'copy2', fail_copy)
    else:
        def fail_replace(self, target):
            raise OSError('replace failed')
        monkeypatch.setattr(Path, 'replace', fail_replace)
    with pytest.raises(OSError):
        install._write_with_backup(path, 'updated')
    assert path.read_text() == 'original'
    assert not list(path.parent.glob('.*.tmp'))
    backups = list(path.parent.glob('*.agentdetox-backup-*'))
    assert [p.read_text() for p in backups] == ([] if stage == 'backup' else ['original'])


def test_uninstall_reports_completed_removal_when_metadata_update_fails(context, monkeypatch, capsys):
    from agentdetox import cli

    project, path = context
    path.write_text(json.dumps(install.claude_code_settings({'model': 'test'}, install.hook_command('claude-code'))))

    def fail_update(*args):
        raise StoreError('damaged store')

    monkeypatch.setattr(cli, '_trust_own_removal', fail_update)
    assert main(['uninstall', 'claude-code', '--project', str(project)]) == 2
    assert json.loads(path.read_text()) == {'model': 'test'}
    error = capsys.readouterr().err
    assert 'hooks were removed' in error and 'agentdetox doctor' in error and 'Traceback' not in error
