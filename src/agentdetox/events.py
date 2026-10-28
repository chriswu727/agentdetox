"""Append-only local log of what AgentDetox checked, asked, blocked or noticed.

Lives next to the snapshots (same 0600/0700 permissions) and never leaves the machine.
"""

from __future__ import annotations

import json
import os
import time
from pathlib import Path

from .integrity import private_dir, store_dir, store_lock

MAX_BYTES = 5_000_000


def log_path() -> Path:
    return store_dir() / "events.jsonl"


def record(event: str, **fields) -> None:
    path = log_path()
    try:
        private_dir(store_dir())
        if path.exists() and path.stat().st_size > MAX_BYTES:
            with store_lock():
                if path.exists() and path.stat().st_size > MAX_BYTES:
                    path.replace(path.with_suffix(".jsonl.1"))  # keep one rotated generation
        fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
        with os.fdopen(fd, "a", encoding="utf-8") as f:
            f.write(json.dumps({"ts": time.strftime("%Y-%m-%dT%H:%M:%S"), "event": event, **fields},
                               ensure_ascii=False) + "\n")
    except OSError:  # TimeoutError from the lock is one too
        pass  # logging must never break a hook


def read(limit: int | None = 50) -> list[dict]:
    """The most recent `limit` events, oldest first; None for all of them."""
    path = log_path()
    if not path.exists():
        return []
    out = []
    lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
    for line in lines[-limit:] if limit else lines:
        try:
            out.append(json.loads(line))
        except ValueError:
            continue
    return out
