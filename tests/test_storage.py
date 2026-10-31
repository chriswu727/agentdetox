import hashlib
import json
import sqlite3

import pytest

from agentdetox import ledger, storage
from agentdetox.integrity import StoreError, baseline_entries, private_dir, store_dir, write_private


def legacy():
    root = private_dir(store_dir())
    objects = private_dir(root / 'objects')
    data = b'Use pnpm.\n'
    digest = hashlib.sha256(data).hexdigest()
    write_private(objects / digest, data)
    baseline = {'version': 1, 'files': {'/project/CLAUDE.md': {'sha256': digest, 'kind': 'instructions',
                'agent': 'claude-code', 'scope': 'project', 'sections': {}, 'taken': '2020-01-01T00:00:00'}}}
    write_private(root / 'baseline.json', json.dumps(baseline).encode())
    entry = {'ts': '2020-01-01T00:00:01', 'path': '/project/CLAUDE.md', 'origin': 'you',
             'before': digest, 'after': digest}
    write_private(root / 'ledger.jsonl', (json.dumps(entry) + '\n').encode())
    return root, digest


def test_migration_preserves_originals_and_marks_attribution_as_legacy():
    root, digest = legacy()
    before = {p.name: p.read_bytes() for p in root.glob('*.json*')}
    with storage.connection(write=True):
        pass
    with storage.connection(write=True):
        pass
    assert {p.name: p.read_bytes() for p in root.glob('*.json*')} == before
    assert len(ledger.entries()) == 1
    assert ledger.entries()[0].method == 'legacy'
    assert baseline_entries()['/project/CLAUDE.md']['sha256'] == digest
    with storage.connection() as db:
        assert db.execute('SELECT accepted_hash FROM files').fetchone()[0] is None


def test_interrupted_migration_is_rolled_back_and_retryable(monkeypatch):
    root, _ = legacy()
    real = storage.append_change
    monkeypatch.setattr(storage, 'append_change', lambda *a: (_ for _ in ()).throw(RuntimeError('interrupted')))
    with pytest.raises(RuntimeError):
        with storage.connection(write=True):
            pass
    monkeypatch.setattr(storage, 'append_change', real)
    with storage.connection(write=True):
        pass
    assert len(ledger.entries()) == 1


def test_missing_object_prevents_migration():
    root, digest = legacy()
    (root / 'objects' / digest).unlink()
    with pytest.raises(StoreError, match='missing or corrupt'):
        with storage.connection(write=True):
            pass
    assert (root / 'ledger.jsonl').exists()


def test_deleted_database_cannot_silently_reimport_stale_json():
    legacy()
    with storage.connection(write=True):
        pass
    storage.path().unlink()
    with pytest.raises(StoreError, match='missing after migration'):
        baseline_entries()


def test_newer_database_is_not_modified():
    legacy()
    with storage.connection(write=True):
        pass
    with sqlite3.connect(storage.path()) as db:
        db.execute('PRAGMA user_version=999')
    with pytest.raises(StoreError, match='newer'):
        ledger.entries()


def test_checkpoint_and_ledger_transaction_roll_back_together():
    _, digest = legacy()
    with storage.connection(write=True):
        pass
    with pytest.raises(RuntimeError):
        with storage.connection(write=True) as db:
            db.execute('UPDATE files SET checkpoint=NULL')
            ledger.record('/project/CLAUDE.md', 'agent', digest, b'New\n')
            raise RuntimeError('interrupted')
    assert len(ledger.entries()) == 1
    assert baseline_entries()['/project/CLAUDE.md']['sha256'] == digest


def test_path_lookup_uses_index():
    legacy()
    with storage.connection(write=True) as db:
        plan = db.execute('EXPLAIN QUERY PLAN SELECT data FROM changes WHERE path=? ORDER BY id DESC LIMIT 1',
                          ('/project/CLAUDE.md',)).fetchall()
        assert 'changes_path' in str([tuple(r) for r in plan])
