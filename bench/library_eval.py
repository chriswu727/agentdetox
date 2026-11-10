"""End-to-end library inspection on a synthetic folder: full, unchanged, changed, failed,
cancelled and resumed runs, with time, memory and disk. Local only; no hooks, no model."""

from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import platform
import sys
import tempfile
import time
from collections import Counter
from pathlib import Path

from bench.large_memory_eval import fixture, location

EXTRA = 5  # of each kind of file that must not be inspected, per run


def peak_rss() -> int | None:
    try:
        import resource
    except ImportError:
        return None
    peak = resource.getrusage(resource.RUSAGE_SELF).ru_maxrss
    return peak if sys.platform == 'darwin' else peak * 1024


def build(root: Path, count: int, minimum_bytes: int, projects: int) -> dict:
    """Write the corpus. Its hash covers every file as first written, by relative path and
    content, in a fixed order; it does not depend on where the corpus is or when it was made."""
    digest = hashlib.sha256()
    total = 0

    def write(path: Path, data: bytes) -> None:
        nonlocal total
        path.parent.mkdir(parents=True, exist_ok=True)
        path.write_bytes(data)
        digest.update(path.relative_to(root).as_posix().encode() + b'\0' + hashlib.sha256(data).digest())
        total += len(data)

    for index in range(count):
        write(location(root, index, projects), fixture(index, minimum_bytes)[0])
    notes = total
    other = root / 'other'
    for n in range(EXTRA):
        write(other / f'too-large-{n}.md', b'x' * 1_000_001)
        write(other / f'not-utf8-{n}.md', b'caf\xe9 notes\n')
        write(other / f'export-{n}.json', b'{}')
        with contextlib.suppress(OSError):
            (other / f'link-{n}.md').symlink_to(location(root, n, projects))
    return {'bytes': notes, 'all_bytes': total, 'sha256': digest.hexdigest(),
            'links': sum(1 for p in other.iterdir() if p.is_symlink())}


def run(root: Path, count: int, minimum_bytes: int, projects: int) -> dict:
    from agentdetox import library
    from agentdetox.integrity import store_dir

    scans: Counter[str] = Counter()
    scanner = library.scan_text

    def counted(*args):
        scans['n'] += 1
        return scanner(*args)

    library.scan_text = counted

    def scan(label: str, *, stop=None, **options) -> dict:
        scans['n'] = 0
        with library.runner_lock() as held:
            assert held, 'another library scan holds the lock'
            job = library.prepare(root, **options)
            start, cpu = time.perf_counter(), time.process_time()
            state = library.run(job['run'], stop=stop)
            finished = time.perf_counter()
            seconds, cpu_seconds = finished - start, time.process_time() - cpu
        result = library.status(root)[0]
        verified = result['inspected'] + result['uninspected'] + result['failed']
        return {'label': label, 'state': state, 'run': job['run'], 'resumed': job['resumed'], 'seconds': seconds,
                'cpu_seconds': cpu_seconds, 'finished': finished,
                'rule_scans': scans['n'], 'files_per_second': verified / seconds if seconds else None,
                'peak_rss_bytes': peak_rss(),
                **{key: result[key] for key in ('candidates', 'inspected', 'suspicious', 'high', 'low_only', 'no_findings',
                                                'stale', 'queued', 'uninspected', 'failed', 'missing', 'excluded', 'links')},
                'uninspected_reasons': result['uninspected_reasons'], 'failed_reasons': result['failed_reasons']}

    start = time.perf_counter()
    built = build(root, count, minimum_bytes, projects)
    generated = time.perf_counter() - start
    phases = [scan('full first scan')]
    expected = phases[0]
    phases.append(scan('unchanged incremental'))

    changed = max(1, count // 100)
    for index in range(changed):
        path = location(root, index * 7 % count, projects)
        path.write_bytes(path.read_bytes() + b'A later benign note.\n')
    phases.append(scan('incremental, 1% of files appended to'))

    # Every 20th file is a plain note; index 7 is one in each block of 20.
    unreadable = [location(root, 7 + 20 * n, projects) for n in range(min(EXTRA, count // 20))]
    deleted = [location(root, 8 + 20 * n, projects) for n in range(min(EXTRA, count // 20))]
    locked = os.name != 'nt' and getattr(os, 'geteuid', lambda: 1)() != 0
    if locked:
        for path in unreadable:
            path.chmod(0)
    for path in deleted:
        path.unlink()
    phases.append(scan('incremental with unreadable and deleted files'))
    for path in unreadable:
        path.chmod(0o600)

    seen: Counter[str] = Counter()
    capture = library._capture

    def counting(*args):
        seen['n'] += 1
        return capture(*args)

    library._capture = counting
    requested: list[float] = []

    def stop() -> bool:
        if seen['n'] >= count // 2 and not requested:
            requested.append(time.perf_counter())
        return bool(requested)

    cancelled = scan('full scan cancelled half-way', stop=stop, full=True)
    cancelled['seconds_from_request_to_stop'] = cancelled['finished'] - requested[0] if requested else None
    phases.append(cancelled)
    library._capture = capture
    phases.append(scan('resumed to completion'))
    final = phases[-1]
    for phase in phases:
        del phase['finished']

    families: dict[str, Counter] = {}
    with library.connect() as db:
        high = {row[0] for row in db.execute("SELECT DISTINCT f.rel FROM files f JOIN findings n ON n.file_id=f.id "
                                             "WHERE n.severity='high' AND f.state='inspected'")}
    gone = {p.relative_to(root).as_posix() for p in deleted}
    for index in range(count):
        rel = location(root, index, projects).relative_to(root).as_posix()
        if rel in gone:
            continue
        _, family, wanted, known_gap = fixture(index, minimum_bytes)
        detected = rel in high
        families.setdefault(family, Counter()).update(
            total=1, high=int(detected), expected_high=int(wanted), known_gap=int(known_gap),
            regression=int(detected != wanted and not known_gap), known_miss=int(wanted and not detected and known_gap))
    database = library.db_path()
    objects = store_dir() / 'objects'
    checks = {
        'first scan inspects every candidate that can be inspected':
            expected['inspected'] == count and expected['uninspected_reasons'] == {'too-large': EXTRA, 'not-utf8': EXTRA}
            and expected['excluded'] == EXTRA and expected['links'] == built['links'],
        'unchanged incremental runs no rule scan': phases[1]['rule_scans'] == 0 and phases[1]['stale'] == 0,
        'changed incremental rescans exactly the changed files': phases[2]['rule_scans'] == changed,
        'unreadable files are failed and deleted files missing, none inspected':
            phases[3]['missing'] == len(deleted) and (not locked or phases[3]['failed_reasons'] == {'unreadable': len(unreadable)}),
        'a cancelled run is resumed, not restarted, and ends with full coverage':
            cancelled['state'] == 'cancelled' and final['resumed'] and final['run'] == cancelled['run']
            and final['inspected'] == count - len(deleted) and final['stale'] == 0 and final['queued'] == 0,
        'no content copies and no hook store': not objects.exists() and not (store_dir() / 'state.sqlite3').exists(),
        'known rule families are detected (acknowledged semantic misses excluded)':
            not any(row['regression'] for row in families.values()),
    }
    return dict(schema=1, scope='synthetic end-to-end library inspection through the library module, in one process',
                platform=platform.platform(), python=platform.python_version(), files=count, projects=projects,
                minimum_file_bytes=minimum_bytes, corpus_bytes=built['bytes'], corpus_bytes_with_extras=built['all_bytes'],
                corpus_sha256=built['sha256'], generation_seconds=generated,
                detector=library.detector_id(), phases=phases, families=families,
                known_semantic_misses=sum(row['known_miss'] for row in families.values()),
                inventory_bytes=database.stat().st_size, inventory_bytes_per_file=database.stat().st_size / count,
                content_copy_bytes=sum(p.stat().st_size for p in objects.iterdir()) if objects.is_dir() else 0,
                process_peak_rss_bytes=peak_rss(), checks=checks, passed=all(checks.values()),
                exclusions=['hook latency while scanning', 'the detached worker and process kills (covered by tests)',
                            'cleanup', 'NLI and semantic detection', 'real-world accuracy or false-positive rates',
                            'production support at this scale', 'filesystems other than the one measured'])


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--files', type=int, choices=(1000, 10000, 100000), default=1000)
    parser.add_argument('--minimum-bytes', type=int, default=1024)
    parser.add_argument('--projects', type=int, default=10)
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    if args.minimum_bytes < 1 or args.projects < 1:
        parser.error('minimum-bytes and projects must be positive')
    with tempfile.TemporaryDirectory(prefix='agentdetox-library-') as folder:
        base = Path(folder).resolve()
        os.environ.update(AGENTDETOX_HOME=str(base / 'store'), AGENTDETOX_USER_HOME=str(base / 'home'))
        (base / 'home').mkdir()
        (base / 'library').mkdir()
        result = run(base / 'library', args.files, args.minimum_bytes, args.projects)
    encoded = json.dumps(result, indent=2) + '\n'
    if args.output:
        args.output.parent.mkdir(parents=True, exist_ok=True)
        args.output.write_text(encoded, encoding='utf-8')
    print(encoded, end='')
    return 0 if result['passed'] else 1


if __name__ == '__main__':
    raise SystemExit(main())
