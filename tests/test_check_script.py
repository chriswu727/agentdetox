import importlib.util
from importlib import metadata
from pathlib import Path

SCRIPT = Path(__file__).resolve().parent.parent / "scripts" / "check.py"


def _load():
    spec = importlib.util.spec_from_file_location("check_script", SCRIPT)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    return module


def test_environment_in_sync_reports_nothing_missing():
    assert _load().missing_requirements() == []


def test_missing_dependency_stops_the_checks_with_a_plain_message(monkeypatch, capsys):
    check = _load()
    monkeypatch.setattr(metadata, "requires", lambda name: [
        "numpy>=1.24", "not-installed-anywhere>=1", 'also-missing; extra == "dev"', 'ignored-extra; extra == "nli"'])
    assert check.missing_requirements() == ["not-installed-anywhere", "also-missing"]
    assert check.main() == 2
    out = capsys.readouterr().out
    assert "out of sync with pyproject.toml" in out and "also-missing, not-installed-anywhere" in out
    assert "Running" not in out
