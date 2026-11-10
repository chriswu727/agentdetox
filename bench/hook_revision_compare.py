"""Alternate hook subprocesses from a Git revision and the checkout; no model calls."""

from __future__ import annotations

import argparse
import hashlib
import json
import math
import os
import platform
import statistics
import subprocess
import sys
import tempfile
import time
from pathlib import Path


def source_hash(source: Path) -> str:
    digest = hashlib.sha256()
    for path in sorted(source.rglob('*.py')):
        digest.update(path.relative_to(source).as_posix().encode() + b'\0' + path.read_bytes() + b'\0')
    return digest.hexdigest()


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--baseline', required=True, help='Git revision to compare against the working tree')
    parser.add_argument('--samples', type=int, default=100)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error('--samples must be positive')
    repo = Path(__file__).resolve().parents[1]

    def git(*arguments):
        return subprocess.check_output(['git', *arguments], cwd=repo)

    revision = git('rev-parse', '--verify', args.baseline + '^{commit}').decode().strip()
    head = git('rev-parse', 'HEAD').decode().strip()
    results = []
    with tempfile.TemporaryDirectory(prefix='agentdetox-hook-compare-') as directory:
        base = Path(directory)
        for name in git('ls-tree', '-r', '--name-only', revision, 'src').decode().splitlines():
            path = base / 'baseline' / name
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_bytes(git('show', revision + ':' + name))
        sources = {'baseline': base / 'baseline/src', 'candidate': repo / 'src'}
        hashes = {name: source_hash(source) for name, source in sources.items()}
        home, project = base / 'home', base / 'project'
        home.mkdir()
        project.mkdir()
        (project / 'CLAUDE.md').write_bytes(b'Use pnpm.\n')
        env = {k: v for k, v in os.environ.items() if not k.startswith(('AGENTDETOX_', 'CLAUDE_', 'PYTHON'))}
        env.update(AGENTDETOX_USER_HOME=str(home), AGENTDETOX_NLI='0', AGENTDETOX_CONTRADICTION='off',
                   PYTHONUTF8='1')
        environments = {name: {**env, 'PYTHONPATH': str(source), 'AGENTDETOX_HOME': str(base / (name + '-store'))}
                        for name, source in sources.items()}
        for name, source in sources.items():
            imported = subprocess.check_output([sys.executable, '-c', 'import agentdetox; print(agentdetox.__file__)'],
                                               cwd=project, env=environments[name], text=True).strip()
            if not Path(imported).is_relative_to(source):
                raise RuntimeError(f'{name} imported the wrong source: {imported}')

        def hook(name, event, tool_id):
            payload = dict(hook_event_name=event, cwd=str(project), session_id='paired', tool_use_id=tool_id,
                           tool_name='Bash', tool_input={'command': 'git status --short'})
            done = subprocess.run([sys.executable, '-m', 'agentdetox', 'hook', 'claude-code'],
                                  input=json.dumps(payload), text=True, encoding='utf-8', capture_output=True,
                                  env=environments[name], cwd=project, check=True)
            if done.stderr or done.stdout:
                raise RuntimeError(done.stderr or done.stdout)

        for label, budget, pair in [('Bash pre, no context write', 100, False),
                                    ('Bash pre + post, 1000 active memory files plus 1000 unrelated files', 350, True)]:
            if pair:
                code = 'from pathlib import Path; from agentdetox.context import claude_memory_dir; '
                code += 'import sys; print(claude_memory_dir(Path(sys.argv[1])))'
                active = Path(subprocess.check_output([sys.executable, '-c', code, str(project)], cwd=project,
                                                      env=environments['candidate'], text=True).strip())
                for folder in (active, home / '.claude/projects/unrelated/memory'):
                    folder.mkdir(parents=True)
                    for n in range(1000):
                        (folder / f'note-{n}.md').write_bytes(
                            (f'# Module {n}\n' + 'Normal project notes.\n' * 40).encode())
            timings: dict[str, list[float]] = {name: [] for name in sources}
            for n in range(-1, args.samples):
                for name in ('baseline', 'candidate') if n % 2 else ('candidate', 'baseline'):
                    tool_id = f'{pair}-{n}'
                    start = time.perf_counter()
                    hook(name, 'PreToolUse', tool_id)
                    if pair:
                        hook(name, 'PostToolUse', tool_id)
                    if n >= 0:
                        timings[name].append((time.perf_counter() - start) * 1000)
            row = dict(case=label, budget_ms=budget, versions={})
            for name, values in timings.items():
                p95 = sorted(values)[math.ceil(.95 * len(values)) - 1]
                row['versions'][name] = dict(p50_ms=round(statistics.median(values), 1), p95_ms=round(p95, 1),
                                             within_budget=p95 <= budget, samples_ms=[round(v, 3) for v in values])
            results.append(row)
            print(json.dumps({**row, 'versions': {name: {k: v for k, v in value.items() if k != 'samples_ms'}
                                                  for name, value in row['versions'].items()}}), flush=True)
        if hashes != {name: source_hash(source) for name, source in sources.items()}:
            raise RuntimeError('Source changed during the comparison')
    report = dict(baseline=revision, candidate_head=head, source_sha256=hashes,
                  candidate_worktree_diff_sha256=hashlib.sha256(git('diff', 'HEAD', '--', 'src')).hexdigest(),
                  platform=platform.platform(), python=platform.python_version(), samples_per_version=args.samples,
                  method='alternating order, one untimed warmup per version/case, separate isolated stores, shared files',
                  model_calls=0, results=results)
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0 if all(v['within_budget'] for r in results for v in r['versions'].values()) else 1


if __name__ == '__main__':
    raise SystemExit(main())
