"""Transactional metadata and migration of the original JSON store."""

from __future__ import annotations

import contextlib
import hashlib
import json
import os
import sqlite3
from contextvars import ContextVar
from pathlib import Path
from typing import Any

_ACTIVE: ContextVar[tuple[Path, sqlite3.Connection] | None] = ContextVar('agentdetox_database', default=None)
VERSION = 2
_SCHEMA = (
    'CREATE TABLE meta (key TEXT PRIMARY KEY, value TEXT NOT NULL)',
    '''CREATE TABLE files (path TEXT PRIMARY KEY, checkpoint TEXT, observed_hash TEXT,
       accepted_hash TEXT, accepted_change INTEGER)''',
    '''CREATE TABLE changes (id INTEGER PRIMARY KEY AUTOINCREMENT, path TEXT NOT NULL, ts TEXT NOT NULL,
       before_hash TEXT, after_hash TEXT, data TEXT NOT NULL, review_state TEXT NOT NULL DEFAULT 'recorded')''',
    'CREATE INDEX changes_path ON changes(path, id DESC)',
    'CREATE INDEX changes_review ON changes(review_state, id DESC)',
    'CREATE INDEX changes_ts ON changes(ts, id DESC)',
    '''CREATE TABLE findings (id INTEGER PRIMARY KEY AUTOINCREMENT, change_id INTEGER NOT NULL,
       flag_id TEXT NOT NULL, severity TEXT NOT NULL, reason TEXT NOT NULL, status TEXT NOT NULL DEFAULT 'pending',
       UNIQUE(change_id, flag_id), FOREIGN KEY(change_id) REFERENCES changes(id))''',
    '''CREATE TABLE events (id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, event TEXT NOT NULL,
       data TEXT NOT NULL, resolved INTEGER NOT NULL DEFAULT 0)''',
    'CREATE INDEX events_kind ON events(event, resolved, id DESC)',
    '''CREATE TABLE operations (id TEXT PRIMARY KEY, path TEXT NOT NULL, before_hash TEXT, after_hash TEXT,
       stage TEXT NOT NULL, backup TEXT, error TEXT)''',
)


def path() -> Path:
    from .integrity import store_dir

    return store_dir() / 'state.sqlite3'


def exists() -> bool:
    from .integrity import StoreError, store_dir

    if path().exists():
        return True
    if (store_dir() / 'sqlite-migrated').exists():
        raise StoreError('state.sqlite3 is missing after migration; restore the database backup before proceeding')
    return False


@contextlib.contextmanager
def connection(*, write: bool = False, seed: dict | None = None):
    from .integrity import StoreError, private_dir, store_dir, store_lock, write_private

    active = _ACTIVE.get()
    if active and active[0] == path():
        yield active[1]
        return
    with store_lock() if write else contextlib.nullcontext():
        present = exists()
        if not present and not write:
            yield None
            return
        db = None
        token = None
        try:
            if write:
                private_dir(store_dir())
                if not present:
                    write_private(path(), b'')
                db = sqlite3.connect(path(), timeout=10)
                os.chmod(path(), 0o600)
            else:
                db = sqlite3.connect(path().as_uri() + '?mode=ro', uri=True, timeout=10)
            db.row_factory = sqlite3.Row
            db.execute('PRAGMA foreign_keys=ON')
            version = db.execute('PRAGMA user_version').fetchone()[0]
            if version > VERSION:
                raise StoreError('Metadata was written by a newer AgentDetox; upgrade before opening it')
            if version < VERSION:
                if not write and version == 0:
                    yield None
                    return
                if write:
                    db.execute('BEGIN IMMEDIATE')
                    if version == 0:
                        _migrate(db, seed)
                    _upgrade_observation(db)
                    db.execute(f'PRAGMA user_version={VERSION}')
                    db.commit()
            if write:
                db.execute('BEGIN IMMEDIATE')
            token = _ACTIVE.set((path(), db))
            yield db
            if write:
                db.commit()
                marker = store_dir() / 'sqlite-migrated'
                if not marker.exists():
                    write_private(marker, b'1\n')
        except sqlite3.Error as e:
            raise StoreError(f'Metadata database is unavailable or damaged: {e}') from e
        finally:
            if token is not None:
                _ACTIVE.reset(token)
            if db is not None:
                db.close()


def _json_lines(file: Path) -> list[dict]:
    from .integrity import StoreError

    if not file.exists():
        return []
    out = []
    for n, line in enumerate(file.read_text(encoding='utf-8').splitlines(), 1):
        try:
            item = json.loads(line)
            if not isinstance(item, dict):
                raise ValueError('expected an object')
            out.append(item)
        except ValueError as e:
            raise StoreError(f'Cannot migrate {file.name}, line {n}: {e}; original files were kept') from e
    return out


def _upgrade_observation(db) -> None:
    db.execute('''CREATE TABLE tool_runs (id TEXT PRIMARY KEY, agent TEXT NOT NULL, session TEXT NOT NULL,
        project TEXT NOT NULL, created REAL NOT NULL)''')
    db.execute('CREATE INDEX tool_runs_created ON tool_runs(created)')
    db.execute('''CREATE TABLE tool_versions (run_id TEXT NOT NULL, path TEXT NOT NULL, digest TEXT NOT NULL,
        kind TEXT NOT NULL, scope TEXT NOT NULL, mode INTEGER NOT NULL, PRIMARY KEY(run_id, path),
        FOREIGN KEY(run_id) REFERENCES tool_runs(id) ON DELETE CASCADE)''')


def _migrate(db, seed: dict | None) -> None:
    from .integrity import StoreError, _load_legacy_baseline, store_dir

    baseline = _load_legacy_baseline() if (store_dir() / 'baseline.json').exists() else seed if seed is not None else _load_legacy_baseline()
    changes = _json_lines(store_dir() / 'ledger.jsonl')
    events = _json_lines(store_dir() / 'events.jsonl')
    refs = {e['sha256'] for e in baseline['files'].values()}
    refs.update(d for e in changes for d in (e.get('before'), e.get('after')) if d)
    for digest in refs:
        obj = store_dir() / 'objects' / digest
        if not obj.is_file() or hashlib.sha256(obj.read_bytes()).hexdigest() != digest:
            raise StoreError(f'Cannot migrate: missing or corrupt object {digest}; original files were kept')
    for statement in _SCHEMA:
        db.execute(statement)
    db.execute('INSERT INTO meta VALUES (?, ?)', ('last_gc', str(baseline.get('last_gc', 0))))
    for file, entry in baseline['files'].items():
        db.execute('INSERT INTO files(path, checkpoint, observed_hash) VALUES (?, ?, ?)',
                   (file, json.dumps(entry), entry['sha256']))
    for entry in changes:
        if not all(k in entry for k in ('path', 'ts', 'origin', 'before', 'after')):
            raise StoreError('Cannot migrate an incomplete ledger entry; original files were kept')
        entry.update(actor={'you': 'agent', 'copied': 'agent'}.get(entry['origin'], entry['origin']),
                     method='legacy', attribution='legacy inference')
        append_change(db, entry)
    for event in events:
        append_event(db, event)
    if db.execute('SELECT count(*) FROM changes').fetchone()[0] != len(changes):
        raise StoreError('Ledger migration count mismatch')


def baseline() -> dict | None:
    from .integrity import SCHEMA_VERSION

    with connection() as db:
        if db is None:
            return None
        rows = db.execute('SELECT path, checkpoint FROM files WHERE checkpoint IS NOT NULL')
        return {'version': SCHEMA_VERSION, 'files': {r['path']: json.loads(r['checkpoint']) for r in rows},
                'last_gc': float(db.execute("SELECT value FROM meta WHERE key='last_gc'").fetchone()[0])}


def save_baseline(data: dict) -> None:
    with connection(write=True, seed=data) as db:
        for file, entry in data['files'].items():
            db.execute('''INSERT INTO files(path, checkpoint, observed_hash) VALUES (?, ?, ?)
                ON CONFLICT(path) DO UPDATE SET checkpoint=excluded.checkpoint, observed_hash=excluded.observed_hash
                WHERE checkpoint IS NOT excluded.checkpoint''',
                       (file, json.dumps(entry), entry['sha256']))
        db.execute("UPDATE meta SET value=? WHERE key='last_gc'", (str(data.get('last_gc', 0)),))


def append_change(db, entry: dict) -> int:
    state = 'pending' if entry.get('flagged') else 'recorded'
    cursor = db.execute('''INSERT INTO changes(path, ts, before_hash, after_hash, data, review_state)
        VALUES (?, ?, ?, ?, ?, ?)''', (entry['path'], entry['ts'], entry.get('before'), entry.get('after'),
                                      json.dumps(entry, ensure_ascii=False), state))
    db.execute('''INSERT INTO files(path, observed_hash) VALUES (?, ?)
        ON CONFLICT(path) DO UPDATE SET observed_hash=excluded.observed_hash''', (entry['path'], entry.get('after')))
    return cursor.lastrowid


def changes(file: str | None = None, limit: int | None = None) -> list[dict] | None:
    with connection() as db:
        if db is None:
            return None
        args: list[Any] = [file] if file is not None else []
        where = ' WHERE path=?' if file is not None else ''
        query = 'SELECT id, data, review_state FROM changes' + where + ' ORDER BY id DESC'
        if limit is not None:
            query += ' LIMIT ?'
            args.append(limit)
        return [dict(json.loads(r['data']), id=r['id'], review_state=r['review_state'])
                for r in reversed(db.execute(query, args).fetchall())]


def append_event(db, event: dict) -> None:
    db.execute('INSERT INTO events(ts, event, data) VALUES (?, ?, ?)',
               (event.get('ts', ''), event.get('event', ''), json.dumps(event, ensure_ascii=False)))


def events(limit: int | None = 50) -> list[dict] | None:
    with connection() as db:
        if db is None:
            return None
        query = 'SELECT id, data, resolved FROM events ORDER BY id DESC'
        args: tuple[int, ...] = ()
        if limit is not None:
            query += ' LIMIT ?'
            args = (limit,)
        return [dict(json.loads(r['data']), event_id=r['id'], resolved=bool(r['resolved']))
                for r in reversed(db.execute(query, args).fetchall())]


def references() -> set[str]:
    with connection() as db:
        if db is None:
            return set()
        rows = db.execute('''SELECT before_hash FROM changes UNION SELECT after_hash FROM changes
            UNION SELECT accepted_hash FROM files UNION SELECT observed_hash FROM files
            UNION SELECT before_hash FROM operations UNION SELECT after_hash FROM operations''')
        refs = {r[0] for r in rows if r[0]}
        if db.execute('PRAGMA user_version').fetchone()[0] >= 2:
            refs.update(r[0] for r in db.execute('SELECT digest FROM tool_versions'))
        return refs
