"""Run the required checks with the invoking Python environment, on every platform."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def missing_requirements() -> list[str]:
    """Declared dependencies (and the dev extra's) this environment does not have. Without
    this, a stale environment fails somewhere inside a check with an unrelated-looking error."""
    from importlib import metadata

    from packaging.requirements import Requirement

    missing = []
    for line in metadata.requires('agentdetox') or []:
        requirement = Requirement(line)
        if requirement.marker and not requirement.marker.evaluate({'extra': 'dev'}):
            continue
        try:
            metadata.version(requirement.name)
        except metadata.PackageNotFoundError:
            missing.append(requirement.name)
    return missing


def main() -> int:
    try:
        missing = missing_requirements()
    except Exception as error:  # noqa: BLE001 - the checks below report a broken install better
        print(f"Could not compare the environment with pyproject.toml: {error}", flush=True)
        missing = []
    if missing:
        print("This environment is out of sync with pyproject.toml: missing " + ", ".join(sorted(missing))
              + ".\nRun `uv sync --extra dev` or `python -m pip install -e '.[dev]'`, then try again.", flush=True)
        return 2
    env = {**os.environ, 'PYTHONUTF8': '1'}
    for args in (
        ['ruff', 'check', 'src', 'tests', 'bench', 'scripts', 'lab'],
        ['mypy'],
        ['pytest', '-q', '-p', 'no:warnings'],
    ):
        print(f"Running {args[0]}", flush=True)
        result = subprocess.run([sys.executable, '-m', *args], cwd=ROOT, env=env)
        if result.returncode:
            return result.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
