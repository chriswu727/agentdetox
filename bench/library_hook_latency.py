"""Run the unchanged hook budgets while a full library scan uses the same store."""

from __future__ import annotations

import argparse
import contextlib
import json
import os
import signal
import sqlite3
import subprocess
import sys
import time
from pathlib import Path

from bench import hook_latency
from bench.large_memory_eval import fixture, location


class Load:
    def __init__(self, files: int, minimum_bytes: int) -> None:
        self.files = files
        self.minimum_bytes = minimum_bytes
        self.process: subprocess.Popen | None = None
        self.database: Path | None = None
        self.report: dict = {}

    def state(self) -> dict:
        assert self.database is not None
        with sqlite3.connect(self.database.as_uri() + '?mode=ro', uri=True, timeout=5) as db:
            row = db.execute('SELECT id, state, phase FROM runs ORDER BY id DESC LIMIT 1').fetchone()
            count = db.execute('SELECT count(*) FROM files WHERE verified_run=?', (row[0],)).fetchone()[0]
        return {'run': row[0], 'state': row[1], 'phase': row[2], 'verified_files': count}

    def start(self) -> None:
        store = Path(os.environ['AGENTDETOX_HOME'])
        root = store.parent / 'scan-load'
        root.mkdir()
        total_bytes = 0
        for index in range(self.files):
            path = location(root, index, 10)
            path.parent.mkdir(parents=True, exist_ok=True)
            data = fixture(index, self.minimum_bytes)[0]
            path.write_bytes(data)
            total_bytes += len(data)
        log = store.parent / 'library-load.log'
        self.database = store / 'library.sqlite3'
        with log.open('xb') as output:
            self.process = subprocess.Popen(
                [sys.executable, '-I', '-m', 'agentdetox', 'library', 'scan', str(root), '--full', '--format', 'json'],
                cwd=store.parent, stdin=subprocess.DEVNULL, stdout=output, stderr=output,
            )
        self.report = {'files': self.files, 'corpus_bytes': total_bytes, 'minimum_file_bytes': self.minimum_bytes,
                       'same_store_as_hooks': True, 'valid_load': False}
        deadline = time.monotonic() + 60
        while time.monotonic() < deadline:
            if self.process.poll() is not None:
                raise RuntimeError('Library load exited before measurement: ' + log.read_text()[-1500:])
            with contextlib.suppress(sqlite3.Error, TypeError):
                state = self.state()
                if state['state'] == 'active' and state['phase'] == 'inspect':
                    self.report['at_start'] = state
                    return
            time.sleep(0.05)
        raise RuntimeError('Library load did not reach inspection within 60 seconds')

    def finish(self) -> None:
        if self.process is None:
            return
        try:
            state = self.state()
            self.report['at_end'] = state
            self.report['valid_load'] = (
                self.process.poll() is None and state['state'] == 'active' and state['phase'] == 'inspect'
                and state['run'] == self.report.get('at_start', {}).get('run')
                and state['verified_files'] > self.report['at_start']['verified_files']
            )
        except (sqlite3.Error, TypeError, KeyError) as error:
            self.report['error'] = str(error)
        finally:
            if self.process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    self.process.send_signal(signal.SIGTERM)
            try:
                self.report['worker_exit'] = self.process.wait(timeout=30)
            except subprocess.TimeoutExpired:
                self.process.kill()
                self.process.wait(timeout=5)
                self.report.update(valid_load=False, forced_termination=True)
            if self.report.get('worker_exit') not in (0, 3):
                self.report['valid_load'] = False


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, default=100000)
    parser.add_argument('--minimum-bytes', type=int, default=4096)
    parser.add_argument('--samples', type=int, default=100)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if os.name != 'posix':
        parser.error('This load harness uses POSIX termination signals')
    if min(args.files, args.minimum_bytes, args.samples) < 1:
        parser.error('files, minimum-bytes and samples must be positive')
    load = Load(args.files, args.minimum_bytes)
    snapshot = hook_latency.snapshot
    temporary = hook_latency.tempfile.TemporaryDirectory
    argv = sys.argv

    def with_load(*positional, **named):
        result = snapshot(*positional, **named)
        if load.process is None:
            load.start()
        return result

    @contextlib.contextmanager
    def protected_temporary(*positional, **named):
        with temporary(*positional, **named) as folder:
            try:
                yield folder
            finally:
                # Stop the owned worker before the hook harness removes its shared store.
                load.finish()

    try:
        hook_latency.snapshot = with_load
        hook_latency.tempfile.TemporaryDirectory = protected_temporary
        sys.argv = ['hook-latency', '--samples', str(args.samples), '--output', str(args.output)]
        code = hook_latency.main()
    finally:
        hook_latency.snapshot = snapshot
        hook_latency.tempfile.TemporaryDirectory = temporary
        sys.argv = argv
    report = json.loads(args.output.read_text())
    report['library_load'] = load.report
    report['scope'] = 'Original hook cases and budgets, during one continuously active same-store library scan'
    report['exclusions'] = ['completion of the load scan', 'NLI inference', 'production scale support']
    report['passed'] = code == 0 and load.report.get('valid_load', False)
    args.output.write_text(json.dumps(report, indent=2) + '\n', encoding='utf-8')
    print(json.dumps({'library_load': load.report, 'passed': report['passed']}), flush=True)
    return 0 if report['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
