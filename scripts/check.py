"""Run the required checks with the invoking Python environment, on every platform."""

import os
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
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
