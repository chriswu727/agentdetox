"""The store and the library inventory survive what real use does to them: a line cut short
by a crash, a process killed mid-step, a reader and a writer at the same moment."""

import hashlib
import json
import os
import sqlite3
import subprocess
import sys

import pytest

from agentdetox import events, integrity, ledger, library, review, safefs, storage
from agentdetox.integrity import StoreError, gc, store_dir

posix = pytest.mark.skipif(not safefs.PINNED, reason="needs directory descriptors")


def put(data: bytes) -> str:
    digest = hashlib.sha256(data).hexdigest()
    objects = store_dir() / "objects"
    objects.mkdir(parents=True, exist_ok=True)
    (objects / digest).write_bytes(data)
    return digest


def legacy_store(tmp_path, *, torn=True):
    """A store as 0.2 left it: baseline.json, ledger.jsonl, events.jsonl and objects."""
    store_dir().mkdir(parents=True, exist_ok=True)
    path = str(tmp_path / "proj" / "CLAUDE.md")
    v1, v2, v3 = put(b"one\n"), put(b"two\n"), put(b"three\n")
    (store_dir() / "baseline.json").write_text(json.dumps({"version": 2, "files": {path: {
        "sha256": v3, "mode": 0o644, "agent": "claude-code", "kind": "instructions", "scope": "project",
        "sections": {}, "taken": "2026-10-01T00:00:02"}}}), encoding="utf-8")
    entry = {"path": path, "ts": "2026-10-01T00:00:01", "origin": "agent", "before": v1, "after": v2}
    (store_dir() / "ledger.jsonl").write_text(json.dumps(entry) + "\n" + ('{"path": "cut sho' if torn else ""),
                                              encoding="utf-8")
    line = json.dumps({"ts": "2026-10-01T00:00:00", "event": "write_checked", "reason": "a\u2028b"}, ensure_ascii=False)
    (store_dir() / "events.jsonl").write_text(line + "\n" + ("[1, 2]\n{not json\n" if torn else ""), encoding="utf-8")
    return path, (v1, v2, v3)


def test_old_store_with_lines_cut_short_still_migrates(tmp_path):
    path, (v1, v2, v3) = legacy_store(tmp_path)
    ledger.record(path, "external", v3, b"four\n")          # the first write migrates
    assert [e.after for e in ledger.entries(path)][0] == v2
    recorded = events.read(None)
    assert any(e["event"] == "write_checked" and e["reason"] == "a\u2028b" for e in recorded)
    [skipped] = [e for e in recorded if e["event"] == "migration_skipped"]
    assert skipped["lines"] == {"ledger.jsonl": 1, "events.jsonl": 2}
    assert (store_dir() / "ledger.jsonl").exists() and (store_dir() / "events.jsonl").exists()
    assert gc(force=True)["objects"] == 0
    assert all((store_dir() / "objects" / digest).exists() for digest in (v1, v2, v3))


def test_migration_that_fails_leaves_no_empty_database_and_gc_deletes_nothing(tmp_path):
    path, (v1, v2, v3) = legacy_store(tmp_path, torn=False)
    (store_dir() / "objects" / v1).write_bytes(b"corrupted")
    with pytest.raises(StoreError, match="missing or corrupt object"):
        ledger.record(path, "external", v3, b"four\n")
    assert not storage.path().exists()
    assert ledger.referenced() == {v1, v2}
    assert [e.after for e in ledger.entries(path)] == [v2]             # the old files are still read
    with pytest.raises(StoreError):
        gc(force=True)
    assert all((store_dir() / "objects" / digest).exists() for digest in (v1, v2, v3))


def test_references_are_unknown_until_the_history_is_in_the_database(tmp_path):
    path, (v1, v2, _) = legacy_store(tmp_path, torn=False)
    storage.path().write_bytes(b"")             # what an interrupted first write used to leave
    assert storage.references() is None
    assert ledger.referenced() == {v1, v2}


def migrated(tmp_path):
    path, versions = legacy_store(tmp_path, torn=False)
    ledger.record(path, "external", versions[2], b"four\n")
    assert (store_dir() / "sqlite-migrated").exists()
    return path


def test_emptied_database_of_a_migrated_store_is_reported_not_rebuilt(tmp_path):
    path = migrated(tmp_path)
    storage.path().write_bytes(b"")
    with pytest.raises(StoreError, match="empty after migration"):
        ledger.entries(path)
    with pytest.raises(StoreError, match="empty after migration"):
        ledger.record(path, "external", None, b"five\n")
    assert storage.path().stat().st_size == 0   # nothing was written back into it


@pytest.mark.parametrize("damage", ["deleted", "emptied", "garbage"])
def test_reset_starts_over_from_a_lost_database_without_the_old_files(damage, tmp_path):
    path = migrated(tmp_path)
    if damage == "deleted":
        storage.path().unlink()
    else:
        storage.path().write_bytes(b"" if damage == "emptied" else b"this is not a database")
    integrity.reset_baseline()
    assert ledger.entries(path) == [] and integrity.baseline_paths() == set()
    kept = sorted(p.name.split(".before-reset-")[0] for p in store_dir().iterdir() if ".before-reset-" in p.name)
    assert kept == ["baseline.json", "events.jsonl", "ledger.jsonl"]
    assert bool(list(store_dir().glob("state.sqlite3.broken-*"))) is (damage == "garbage")
    ledger.record(path, "external", None, b"six\n")
    assert len(ledger.entries(path)) == 1


def test_backup_left_empty_by_a_killed_upgrade_is_made_again(tmp_path):
    source = sqlite3.connect(tmp_path / "source.sqlite3")
    source.execute("CREATE TABLE t(x)")
    source.execute("INSERT INTO t VALUES (1)")
    source.execute("PRAGMA user_version=1")
    source.commit()
    target = tmp_path / "state.v1.sqlite3"
    target.write_bytes(b"")
    storage._backup(source, target)
    copy = sqlite3.connect(target)
    assert copy.execute("SELECT x FROM t").fetchall() == [(1,)]
    copy.close()
    before = target.read_bytes()
    storage._backup(source, target)             # a complete one is left alone
    assert target.read_bytes() == before and not target.with_name(target.name + ".partial").exists()
    source.close()


def test_review_list_sizes_changes_with_the_database_closed(tmp_path, monkeypatch):
    path = tmp_path / "CLAUDE.md"
    ledger.record(path, "external", None, b"one\n")
    ledger.record(path, "external", hashlib.sha256(b"one\n").hexdigest(), b"one\ntwo\n")
    sizing = review._line_changes
    written = []

    def size_and_write(old, new):
        # What a hook does while the list is being drawn: it must get the store at once.
        entry = ledger.record(tmp_path / "other.md", "external", None, f"write {len(written)}\n".encode())
        written.append(entry.id)
        return sizing(old, new)

    monkeypatch.setattr(review, "_line_changes", size_and_write)
    monkeypatch.setattr(integrity, "LOCK_TIMEOUT", 2.0)
    page = review.page(all_changes=True, group_by="change")
    assert written and [(row["added"], row["removed"]) for row in page["rows"]][-2:] == [(1, 0), (1, 0)]


def test_json_lines_end_at_a_line_feed_only(tmp_path):
    store_dir().mkdir(parents=True, exist_ok=True)
    line = json.dumps({"ts": "t", "event": "x", "note": "a\u2028b\u0085c"}, ensure_ascii=False)
    (store_dir() / "events-fallback.jsonl").write_text(line + "\n", encoding="utf-8")
    assert [e["note"] for e in events.read(None)] == ["a\u2028b\u0085c"]


# The library inventory ----------------------------------------------------------------

@pytest.fixture
def root(tmp_path):
    folder = tmp_path.resolve() / "library"
    folder.mkdir()
    return folder


def scan(target, **options) -> str:
    stop = options.pop("stop", None)
    with library.runner_lock() as held:
        assert held
        return library.run(library.prepare(target, **options)["run"], stop=stop)


def test_another_command_gets_the_inventory_while_folders_are_listed(root, monkeypatch):
    for n in range(12):
        (root / f"d{n}").mkdir()
        (root / f"d{n}" / "a.md").write_text("Use pnpm.\n", encoding="utf-8")
    real = os.scandir
    waited = []

    def slow_listing(*args, **kwargs):
        # A second command, as `library cancel` is one, writes while this folder is being read.
        other = sqlite3.connect(library.db_path(), timeout=0.2, isolation_level=None)
        try:
            other.execute("BEGIN IMMEDIATE")
            other.execute("UPDATE runs SET heartbeat=heartbeat")
            other.execute("COMMIT")
            waited.append(True)
        finally:
            other.close()
        return real(*args, **kwargs)

    monkeypatch.setattr(library.os, "scandir", slow_listing)
    assert scan(root) == "completed"
    assert len(waited) >= 13


@posix
def test_root_replaced_while_a_large_folder_is_listed_records_nothing(root, monkeypatch):
    monkeypatch.setattr(library, "DIR_CHUNK", 5)
    for n in range(40):
        (root / f"n{n:02}.md").write_text("Use pnpm.\n", encoding="utf-8")
    real = os.scandir
    moved = root.with_name("library-moved")

    class Moving:
        def __init__(self, entries):
            self.entries = entries

        def __enter__(self):
            return self

        def __exit__(self, *exc):
            self.entries.close()

        def __iter__(self):
            for seen, entry in enumerate(self.entries, 1):
                if seen == 3 and not moved.exists():
                    root.rename(moved)
                    root.mkdir()
                yield entry

    monkeypatch.setattr(library.os, "scandir", lambda *a, **k: Moving(real(*a, **k)))
    with pytest.raises(library.RootReplaced):
        scan(root)
    with library.connect() as db:
        assert db.execute("SELECT count(*) FROM files").fetchone()[0] == 0


@pytest.mark.skipif(os.name != "posix", reason="leaves a journal by exiting mid-transaction")
def test_reader_recovers_an_inventory_left_mid_commit(root):
    (root / "a.md").write_text("Use pnpm.\n", encoding="utf-8")
    assert scan(root) == "completed"
    # A writer that spills its changes to the file and dies before committing leaves a
    # journal that has to be rolled back before anything can be read.
    code = ("import os, sqlite3, sys\n"
            "db = sqlite3.connect(sys.argv[1], isolation_level=None)\n"
            "db.execute('PRAGMA cache_size=1')\n"
            "db.execute('BEGIN IMMEDIATE')\n"
            "db.execute('CREATE TABLE filler(x)')\n"
            "db.executemany('INSERT INTO filler VALUES (?)', [('y' * 3000,) for _ in range(400)])\n"
            "os._exit(0)\n")
    subprocess.run([sys.executable, "-c", code, str(library.db_path())], check=True)
    assert library.db_path().with_name(library.db_path().name + "-journal").exists()
    [status] = library.status(root)
    assert status["path"] == str(root)
    with library.connect() as db:
        assert db.execute("SELECT count(*) FROM sqlite_master WHERE name='filler'").fetchone()[0] == 0
