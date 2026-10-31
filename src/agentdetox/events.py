"""Append-only local log of what AgentDetox checked, asked, blocked or noticed.

Lives next to the snapshots (same 0600/0700 permissions) and never leaves the machine.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from . import storage
from .integrity import StoreError, private_dir, store_dir


def log_path() -> Path:
    return store_dir() / "events.jsonl"


def record(event: str, **fields) -> None:
    path = store_dir() / 'events-fallback.jsonl'
    row = {"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **fields}
    try:
        with storage.connection(write=True) as db:
            storage.append_event(db, row)
        return
    except (OSError, StoreError):
        pass
    try:
        private_dir(store_dir())
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **fields},
                               ensure_ascii=False) + "\n")
    except OSError:  # TimeoutError from the lock is one too
        pass  # logging must never break a hook


def read(limit: int | None = 50) -> list[dict]:
    """The most recent `limit` events, oldest first; None for all of them."""
    rows = storage.events(limit)
    if rows is not None:
        rows += _read_file(store_dir() / 'events-fallback.jsonl', limit)
        rows.sort(key=lambda row: row.get('ts', ''))
        return rows[-limit:] if limit else rows
    return _read_file(log_path(), limit) + _read_file(store_dir() / 'events-fallback.jsonl', limit)


def _read_file(path: Path, limit: int | None) -> list[dict]:
    if not path.exists():
        return []
    out = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-limit:] if limit else lines:
        try:
            row = json.loads(line)
            if isinstance(row, dict):
                if path.name == "events-fallback.jsonl":
                    row["event_id"] = "fallback"
                out.append(row)
        except ValueError:
            continue
    return out
