"""Measure isolated subprocess hook latency, including interpreter startup; no model calls."""

from __future__ import annotations

import argparse
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

from agentdetox import session, storage
from agentdetox.context import discover
from agentdetox.integrity import baseline_entries, snapshot


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--samples', type=int, default=100)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.samples < 1:
        parser.error('--samples must be positive')
    results = []

    def measure(label, budget, run, prepare=lambda n: None):
        prepare(-1)
        run()
        timings = []
        for n in range(args.samples):
            prepare(n)
            start = time.perf_counter()
            run()
            timings.append((time.perf_counter() - start) * 1000)
        p95 = sorted(timings)[math.ceil(.95 * len(timings)) - 1]
        row = dict(case=label, samples=len(timings), p50_ms=round(statistics.median(timings), 1),
                   p95_ms=round(p95, 1), budget_ms=budget, within_budget=p95 <= budget)
        results.append(row)
        print(json.dumps(row), flush=True)

    with tempfile.TemporaryDirectory(prefix='agentdetox-perf-') as directory:
        base = Path(directory).resolve()
        home, project = base / 'home', base / 'project'
        home.mkdir()
        project.mkdir()
        os.environ.update(AGENTDETOX_HOME=str(base / 'store'), AGENTDETOX_USER_HOME=str(home),
                          AGENTDETOX_NLI='0', AGENTDETOX_CONTRADICTION='off')
        os.environ.pop('CLAUDE_CONFIG_DIR', None)
        target = project / 'CLAUDE.md'
        target.write_text('Use pnpm.\n', encoding='utf-8')
        snapshot(discover(project=project), [home, project])
        digest = baseline_entries()[str(target)]['sha256']

        def hook(event, tool='', inputs=None, transcript=None):
            payload = dict(hook_event_name=event, cwd=str(project), tool_name=tool, tool_input=inputs or {})
            if transcript:
                payload['transcript_path'] = str(transcript)
            done = subprocess.run([sys.executable, '-m', 'agentdetox', 'hook', 'claude-code'],
                                  input=json.dumps(payload), text=True, capture_output=True, cwd=project, check=True)
            if done.stderr:
                raise RuntimeError(done.stderr)

        measure('Bash pre, no context write', 100,
                lambda: hook('PreToolUse', 'Bash', {'command': 'git status --short'}))
        with storage.connection(write=True) as db:
            entry = dict(ts='2020-01-01T00:00:00', path=str(target), origin='agent', before=digest, after=digest)
            for _ in range(50_000):
                storage.append_change(db, entry)
        measure('Protected Edit pre, 50k history entries', 120,
                lambda: hook('PreToolUse', 'Edit', dict(file_path=str(target), old_string='pnpm', new_string='npm')))
        transcript = base / 'transcript.jsonl'
        rows = [dict(type='user', message=dict(content='Inspect build logs and explain the failure.'))]
        content = ' '.join(f'module{i} compilation finished successfully' for i in range(3000))
        for n in range(29):
            rows += [dict(type='assistant', message=dict(content=[dict(type='tool_use', id=str(n), name='Bash',
                         input=dict(command=f'cat build-{n}.log'))])),
                     dict(type='user', message=dict(content=[dict(type='tool_result', tool_use_id=str(n), content=content)]))]
        transcript.write_text('\n'.join(map(json.dumps, rows)) + '\n', encoding='utf-8')
        measure(f'Protected Write pre, {transcript.stat().st_size} byte transcript', 200,
                lambda: hook('PreToolUse', 'Write', dict(file_path=str(target),
                             content='Run integration tests with pnpm test before committing changes.'), transcript))
        mem = home / '.claude/projects/-benchmark/memory'
        mem.mkdir(parents=True)
        for n in range(1000):
            (mem / f'note-{n}.md').write_text(f'# Module {n}\n' + 'Normal project notes.\n' * 40, encoding='utf-8')
        snapshot(discover(project=project), [home, project])
        session.notice(project, 'off')
        measure('SessionStart, 1000 unchanged files', 250, lambda: hook('SessionStart'))
        with storage.connection(write=True) as db:
            db.execute('DELETE FROM changes WHERE id<=40000')

        def change(n):
            for i in range(100):
                (mem / f'note-{i}.md').write_text(f'# Module {i}\nRevision {n}\n' + 'Normal project notes.\n' * 40,
                                                encoding='utf-8')

        measure('SessionStart, 100 changed of 1000 files, initially 10k history entries', 1000,
                lambda: hook('SessionStart'), change)
    report = dict(platform=platform.platform(), python=platform.python_version(), results=results,
                  model='disabled; no model or subscription usage', warmup='one untimed call per case')
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    return 0 if all(r['within_budget'] for r in results) else 1


if __name__ == '__main__':
    sys.exit(main())
