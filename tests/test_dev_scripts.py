"""Development checks must stop before an update can install unchecked code."""

import subprocess
import sys
from subprocess import CompletedProcess

import pytest

from scripts import check


def test_check_uses_invoking_python_and_stops_on_failure(monkeypatch):
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        assert kwargs['cwd'] == check.ROOT
        assert kwargs['env']['PYTHONUTF8'] == '1'
        return CompletedProcess(command, 7 if command[2] == 'mypy' else 0)

    monkeypatch.setattr(check.subprocess, 'run', run)
    assert check.main() == 7
    assert [c[2] for c in calls] == ['ruff', 'mypy']
    assert all(c[:2] == [check.sys.executable, '-m'] for c in calls)


@pytest.mark.parametrize('platform', ['win32', 'linux', 'darwin'])
def test_platform_specific_code_type_checks_for_every_platform(platform, tmp_path):
    pytest.importorskip('mypy')
    result = subprocess.run(
        [sys.executable, '-m', 'mypy', '--platform', platform, '--cache-dir', str(tmp_path),
         'src/agentdetox/daemon.py'],
        cwd=check.ROOT, capture_output=True, text=True)
    assert result.returncode == 0, result.stdout + result.stderr
