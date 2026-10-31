"""Review exact observed versions without granting permanent source trust."""

from __future__ import annotations

import difflib
import hashlib
import json
import os
import re
import time
import uuid
from collections import Counter
from pathlib import Path

from . import events, ledger, storage
from .context import short_path
from .integrity import (
    StoreError,
    baseline_entries,
    private_dir,
    restore_object,
    store_dir,
    store_lock,
    store_object,
    write_private,
)


def number(value: str, prefix: str = 'C') -> int:
    if not re.fullmatch(prefix + r'[1-9][0-9]*', value.upper()):
        raise ValueError(f'Expected a {prefix} id, such as {prefix}42')
    return int(value[1:])


def get(change_id: str) -> dict:
    with storage.connection() as db:
        row = db.execute('SELECT * FROM changes WHERE id=?', (number(change_id),)).fetchone() if db else None
        if row is None:
            raise ValueError(f'Unknown change {change_id}')
        return dict(row)


def _digest(path: Path) -> str | None:
    if path.is_symlink():
        raise StoreError(f'Symbolic links are not supported for review actions: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _check_current(row: dict) -> Path:
    path = Path(row['path'])
    if _digest(path) != row['after_hash']:
        raise StoreError(f'{path} changed after C{row["id"]}; inspect the latest file before taking action')
    return path


def list_changes(since: str | None = None, all_changes: bool = False) -> list[dict]:
    args = []
    where = '' if all_changes or since else " WHERE review_state='pending'"
    if since:
        if not re.fullmatch(r'[1-9][0-9]*d', since):
            raise ValueError('Use a duration such as --since 7d')
        where = ' WHERE ts>=?'
        args.append(time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - int(since[:-1]) * 86400)))
    with storage.connection() as db:
        if db is None:
            return []
        return [dict(r) for r in db.execute('SELECT * FROM changes' + where + ' ORDER BY id DESC LIMIT 200', args)]


def render_list(rows: list[dict], summary: bool = False) -> str:
    if not rows:
        return 'No changes in this period.' if summary else 'Nothing needs attention. Use `agentdetox review --since 7d` for recent changes.'
    counts = Counter(row['review_state'] for row in rows)
    lines = [f"{len(rows)} changes shown: " + ', '.join(f'{n} {state}' for state, n in sorted(counts.items())),
             'Recent context changes:' if summary else 'Changes needing attention:']
    for row in rows:
        data = json.loads(row['data'])
        operation = 'deleted' if row['after_hash'] is None else 'added' if row['before_hash'] is None else 'modified'
        lines.append(f"C{row['id']}  {row['review_state']:<10} {operation:<8} {short_path(row['path'])}")
        lines.append(f"    {data.get('actor') or data.get('origin', 'unknown')} · {row['ts']}")
    lines.append('Open a change: agentdetox review C<ID> (showing up to 200 changes).')
    return '\n'.join(lines)


def detail(change_id: str) -> str:
    row = get(change_id)
    data = json.loads(row['data'])
    before = _object_text(row['before_hash'])
    after = _object_text(row['after_hash'])
    lines = [f"C{row['id']} · {short_path(row['path'])} · {row['review_state']}",
             f"Observed writer: {data.get('actor') or data.get('origin', 'unknown')}",
             f"Session: {data.get('session') or 'unknown'}; tool: {data.get('tool') or 'unknown'}",
             'Content attribution is evidence-based inference, not proof of authorship.']
    evidence = sorted({(s.get('attribution', 'unknown'), s.get('source', '')) for s in data.get('spans', [])})
    lines += [f'  {what}' + (f': {source}' if source else '') for what, source in evidence]
    if not evidence:
        lines.append(f"  {data.get('attribution', 'unknown')} ({data.get('method', 'legacy')})")
    lines += list(difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile='before', tofile='after', lineterm=''))
    with storage.connection() as db:
        findings = db.execute('SELECT * FROM findings WHERE change_id=? ORDER BY id', (row['id'],)).fetchall()
    lines += [f"F{f['id']} [{f['severity']}, {f['status']}] {f['reason']}" for f in findings]
    try:
        _check_current(row)
    except StoreError:
        lines.append('STALE: the file no longer matches this change. Actions will refuse to overwrite newer work.')
    lines += [f'Accept only this version: agentdetox review accept C{row["id"]}',
              f'Preview recovery: agentdetox restore C{row["id"]}',
              'Dismiss one finding: agentdetox review dismiss F<ID>. This grants no permanent exception.']
    return '\n'.join(lines)


def accept(change_id: str) -> None:
    with store_lock(), storage.connection(write=True) as db:
        row = get(change_id)
        path = _check_current(row)
        db.execute('UPDATE files SET accepted_hash=?, accepted_change=? WHERE path=?',
                   (row['after_hash'], row['id'], row['path']))
        db.execute("UPDATE changes SET review_state='accepted' WHERE id=?", (row['id'],))
        db.execute("UPDATE findings SET status='accepted' WHERE change_id=?", (row['id'],))
        if _digest(path) != row['after_hash']:
            raise StoreError('File changed while accepting; no approval was saved')
        events.record("review_accepted", change=change_id, path=row["path"])


def dismiss(finding_id: str) -> None:
    with storage.connection(write=True) as db:
        row = db.execute("SELECT change_id FROM findings WHERE id=? AND status='pending'", (number(finding_id, 'F'),)).fetchone()
        if row is None:
            raise ValueError(f'Unknown or already handled finding {finding_id}')
        db.execute("UPDATE findings SET status='dismissed' WHERE id=?", (number(finding_id, 'F'),))
        pending = db.execute("SELECT 1 FROM findings WHERE change_id=? AND status='pending'", (row[0],)).fetchone()
        events.record("review_dismissed", finding=finding_id)
        if not pending:
            db.execute("UPDATE changes SET review_state='dismissed' WHERE id=?", (row[0],))


def accepted_versions() -> dict[str, str | None]:
    with storage.connection() as db:
        return {r['path']: r['accepted_hash'] for r in db.execute('SELECT path, accepted_hash FROM files WHERE accepted_change IS NOT NULL')} if db else {}


def restore(change_id: str, apply: bool = False) -> str:
    with store_lock():
        row = get(change_id)
        path = _check_current(row)
        if not apply:
            return detail(change_id) + f'\nRestore the version before this change: agentdetox restore {change_id} --apply\nThe current version will be backed up; file permissions will be preserved.'
        operation = uuid.uuid4().hex
        backup_path = store_dir() / 'quarantine' / operation / 'content'
        mode = baseline_entries().get(str(path), {}).get('mode', 0o600)
        with storage.connection(write=True) as db:
            db.execute('INSERT INTO operations(id, path, before_hash, after_hash, stage, backup) VALUES (?, ?, ?, ?, ?, ?)',
                       (operation, str(path), row['after_hash'], row['before_hash'], 'preparing', str(backup_path)))
        backup = None
        data: bytes | None = None
        try:
            _check_current(row)
            if row['before_hash'] is not None:
                backup = restore_object(path, row['before_hash'], mode, row['after_hash'], backup_path.parent)
            elif path.exists():
                data = path.read_bytes()
                qdir = private_dir(store_dir() / 'quarantine' / operation)
                backup = qdir / 'content'
                write_private(backup, data)
                with backup.open('r+b') as f:
                    os.fsync(f.fileno())
                write_private(qdir / 'manifest.json', json.dumps({'content': str(path)}).encode())
                if backup.read_bytes() != data or _digest(path) != row['after_hash']:
                    raise StoreError('File changed during recovery; original was left in place')
                path.unlink()
            with storage.connection(write=True) as db:
                data = path.read_bytes() if path.exists() else None
                if (hashlib.sha256(data).hexdigest() if data is not None else None) != row['before_hash']:
                    raise StoreError('File changed during recovery; inspect it and the backup')
                entry = ledger.record(path, 'restored', row['after_hash'], data)
                if entry is None:
                    raise StoreError('Could not record recovery')
                db.execute("UPDATE changes SET review_state='restored' WHERE id=?", (row['id'],))
                db.execute("UPDATE findings SET status='restored' WHERE change_id=?", (row['id'],))
                checkpoint = db.execute('SELECT checkpoint FROM files WHERE path=?', (str(path),)).fetchone()
                if row['before_hash'] is None:
                    db.execute('UPDATE files SET checkpoint=NULL WHERE path=?', (str(path),))
                elif checkpoint and checkpoint[0]:
                    value = json.loads(checkpoint[0])
                    assert data is not None
                    value['sha256'] = store_object(data)
                    from .persistence import guarded_sections
                    value['sections'] = guarded_sections(path, data.decode('utf-8', errors='replace')) if value['kind'] == 'config' else {}
                    db.execute('UPDATE files SET checkpoint=? WHERE path=?', (json.dumps(value), str(path)))
                db.execute("UPDATE operations SET stage='completed', backup=? WHERE id=?", (str(backup) if backup else None, operation))
        except (OSError, StoreError) as e:
            with storage.connection(write=True) as db:
                db.execute("UPDATE operations SET stage='failed', backup=?, error=? WHERE id=?",
                           (str(backup_path), str(e), operation))
            raise
        return f'Restored {short_path(str(path))}. Backup: {backup or "file was absent"}.'


def handled_findings() -> set[tuple[str, str | None, str]]:
    with storage.connection() as db:
        if db is None:
            return set()
        return {(r['path'], r['after_hash'], r['flag_id']) for r in db.execute(
            "SELECT c.path, c.after_hash, f.flag_id FROM findings f JOIN changes c ON c.id=f.change_id "
            "WHERE f.status IN ('dismissed', 'accepted')")}


def prune(older_than: str, apply: bool = False) -> dict:
    if not re.fullmatch(r'[1-9][0-9]*d', older_than):
        raise ValueError('Use a duration such as 90d')
    cutoff = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - int(older_than[:-1]) * 86400))
    with storage.connection(write=apply) as db:
        if db is None:
            return {'changes': 0, 'events': 0, 'applied': apply}
        query = """SELECT id FROM changes WHERE ts<? AND review_state IN ('recorded', 'dismissed', 'restored')
            AND id NOT IN (SELECT accepted_change FROM files WHERE accepted_change IS NOT NULL)
            AND id NOT IN (SELECT max(id) FROM changes GROUP BY path)
            AND id NOT IN (SELECT change_id FROM findings WHERE status='pending')"""
        count = db.execute('SELECT count(*) FROM (' + query + ')', (cutoff,)).fetchone()[0]
        event_query = "ts<? AND NOT (event='hook_error' AND resolved=0)"
        event_count = db.execute('SELECT count(*) FROM events WHERE ' + event_query, (cutoff,)).fetchone()[0]
        if apply:
            db.execute('DELETE FROM findings WHERE change_id IN (' + query + ')', (cutoff,))
            db.execute('DELETE FROM changes WHERE id IN (' + query + ')', (cutoff,))
            db.execute('DELETE FROM events WHERE ' + event_query, (cutoff,))
        return {'changes': count, 'events': event_count, 'applied': apply}


def _object_text(digest: str | None) -> str:
    if digest is None:
        return ''
    path = store_dir() / 'objects' / digest
    if not path.is_file():
        raise StoreError(f'Missing content object {digest}; cannot show a reliable diff')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise StoreError(f'Corrupt content object {digest}; cannot show a reliable diff')
    return data.decode('utf-8', errors='replace')


def acknowledge_recovery(operation_id: str) -> None:
    with storage.connection(write=True) as db:
        row = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown recovery operation')
        current = _digest(Path(row['path']))
        if current not in (row['before_hash'], row['after_hash']):
            raise StoreError('File matches neither side of this recovery; inspect and resolve it before acknowledging')
        db.execute("UPDATE operations SET stage='acknowledged' WHERE id=?", (operation_id,))
        events.record('recovery_acknowledged', operation=operation_id, current=current)
