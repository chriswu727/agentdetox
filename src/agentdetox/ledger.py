"""Where each change to an agent's context came from.

One JSON line per change in `ledger.jsonl`, next to the snapshots. Each names the stored
copies of the version before and after (kept while the ledger refers to them, so history
can be replayed) and the change's origin:

  you        text the user typed or pasted in the session
  agent      written by the agent through its own edit tools ("requested" when the user had
             asked it to remember something)
  copied     written by the agent, mostly copied from input it had just read; `source` says what
  external   changed outside the agent's edit tools: another program, a person, a sync, or a
             shell command, which is not yet told apart
  restored   put back by `agentdetox agent restore`
"""

from __future__ import annotations

import difflib
import json
import os
import time
from dataclasses import asdict, dataclass
from pathlib import Path

from .integrity import object_text, private_dir, store_dir, store_object

# Blame labels for lines no recorded change explains.
EARLIER = "earlier"          # there before the first recorded change
UNRECORDED = "unrecorded"    # changed since the last recorded change


@dataclass
class Entry:
    ts: str
    path: str
    origin: str
    before: str | None   # stored copy of the previous version; None for a new file
    after: str | None    # stored copy of this version; None if the file was deleted
    agent: str = ""
    session: str = ""
    tool: str = ""
    source: str = ""
    requested: bool = False
    flagged: bool = False

    def describe(self) -> str:
        if self.origin == "copied":
            what = f"copied by the agent from {self.source}" if self.source else "copied by the agent"
        else:
            what = {"you": "your own words", "agent": "written by the agent",
                    "external": "changed outside the agent's edit tools",
                    "restored": "restored from the snapshot"}.get(self.origin, self.origin)
        if self.requested and self.origin in ("agent", "copied"):
            what += ", after you asked it to remember"
        if self.flagged:
            what += " (flagged)"
        return what


def ledger_path() -> Path:
    return store_dir() / "ledger.jsonl"


def record(path: Path | str, origin: str, before: str | None, after: bytes | None, **fields) -> Entry | None:
    """Append one change; `after` is the new content, None if the file was deleted. Never
    raises: recording must not break a hook."""
    try:
        entry = Entry(time.strftime("%Y-%m-%dT%H:%M:%S"), str(path), origin, before,
                      store_object(after) if after is not None else None, **fields)
        private_dir(store_dir())
        fd = os.open(ledger_path(), os.O_WRONLY | os.O_CREAT | os.O_APPEND | getattr(os, "O_BINARY", 0), 0o600)
        with os.fdopen(fd, "a", encoding="utf-8", newline="\n") as f:
            f.write(json.dumps(asdict(entry), ensure_ascii=False) + "\n")
        return entry
    except OSError:
        return None


def entries(path: str | None = None) -> list[Entry]:
    """Recorded changes, oldest first; only those to `path` when given."""
    log = ledger_path()
    if not log.exists():
        return []
    out = []
    for line in log.read_text(encoding="utf-8", errors="replace").splitlines():
        try:
            data = json.loads(line)
            entry = Entry(**{k: v for k, v in data.items() if k in Entry.__dataclass_fields__})
        except (ValueError, TypeError):
            continue
        if path is None or entry.path == path:
            out.append(entry)
    return out


def last_version(path: str) -> str | None:
    """The stored copy the most recent change to `path` produced."""
    history = entries(path)
    return history[-1].after if history else None


def referenced() -> set[str]:
    return {d for e in entries() for d in (e.before, e.after) if d}


def blame(path: Path) -> list[tuple[str, Entry | str]]:
    """Each current line of `path` with the change that introduced it, or EARLIER /
    UNRECORDED when no recorded change explains it."""
    history = entries(str(path))
    current = path.read_text(encoding="utf-8", errors="replace").splitlines() if path.exists() else []
    if not history:
        return [(line, EARLIER) for line in current]
    first = history[0]
    lines: list[tuple[str, Entry | str]]
    if first.before is None:
        lines = []
    elif _stored(first.before):
        lines = [(line, EARLIER) for line in object_text(first.before).splitlines()]
    else:  # the version before the first change is gone; its lines cannot be told apart
        lines = [(line, EARLIER) for line in _version(first.after)]
        history = history[1:]
    for entry in history:
        lines = _carry(lines, _version(entry.after), entry)
    return _carry(lines, current, UNRECORDED)


def _carry(lines: list[tuple[str, Entry | str]], new: list[str], cause: Entry | str) -> list[tuple[str, Entry | str]]:
    """The lines of `new`, keeping the attribution of lines carried over from `lines` and
    giving `cause` to the rest."""
    out: list[tuple[str, Entry | str]] = []
    matcher = difflib.SequenceMatcher(None, [text for text, _ in lines], new, autojunk=False)
    for tag, i1, i2, j1, j2 in matcher.get_opcodes():
        if tag == "equal":
            out += lines[i1:i2]
        elif tag in ("replace", "insert"):
            out += [(text, cause) for text in new[j1:j2]]
    return out


def _version(digest: str | None) -> list[str]:
    return object_text(digest).splitlines() if digest else []


def _stored(digest: str) -> bool:
    return (store_dir() / "objects" / digest).exists()
