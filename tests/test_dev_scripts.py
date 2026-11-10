"""Development checks must stop before an update can install unchecked code."""

from subprocess import CompletedProcess

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
