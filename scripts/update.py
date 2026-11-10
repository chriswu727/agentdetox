"""Check this checkout, reinstall the uv tool, then run doctor. NLI is opt-in."""

import argparse
import os
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--nli', action='store_true', help='install optional NLI dependencies (no model download)')
    args = parser.parse_args()
    env = {**os.environ, 'PYTHONUTF8': '1'}

    def run(command, **kwargs):
        return subprocess.run(command, cwd=ROOT, env=env, check=True, **kwargs)

    python = ROOT / '.venv' / ('Scripts/python.exe' if os.name == 'nt' else 'bin/python')
    try:
        if not python.is_file():
            run(['uv', 'venv', '--python', '3.12', str(ROOT / '.venv')])
        run(['uv', 'pip', 'install', '--python', str(python), '-e', '.[dev,nli]' if args.nli else '.[dev]'])
        run([str(python), 'scripts/check.py'])
        run(['uv', 'tool', 'install', '--reinstall', '--python', '3.12', '.[nli]' if args.nli else '.'])
        binaries = run(['uv', 'tool', 'dir', '--bin'], capture_output=True, text=True, encoding='utf-8').stdout.strip()
        executable = str(Path(binaries) / ('agentdetox.exe' if os.name == 'nt' else 'agentdetox'))
        subprocess.run([executable, 'daemon', 'stop'], cwd=ROOT, env=env, stdout=subprocess.DEVNULL)
        run([executable, 'doctor'])
    except subprocess.CalledProcessError as error:
        return error.returncode
    return 0


if __name__ == '__main__':
    raise SystemExit(main())
