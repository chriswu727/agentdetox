"""Findings the user reviewed and allowed: "always allow this one".

Ids come from what was flagged (the line, the conflicting pair, the untrusted source),
not from where or when, so one `agentdetox allow <id>` covers the write check, the
session notice and `agentdetox agent scan`. The file sits with the snapshots, and the
hooks make an agent ask before changing it, or an injected instruction could allow
itself.
"""

from __future__ import annotations

import json
import re
import time
from dataclasses import dataclass
from pathlib import Path

from .consistency import Contradiction
from .findings import ID_LENGTH, Finding, finding_id, make_id, pair_anchor
from .integrity import private_dir, store_dir, store_lock, write_private
from .provenance import CopyFinding

ID_RE = re.compile(rf"^[0-9a-f]{{{ID_LENGTH}}}$")
SCHEMA_VERSION = 1


@dataclass
class Flag:
    id: str
    what: str


def path() -> Path:
    return store_dir() / "allowlist.json"


def entries() -> dict[str, dict]:
    """Allowed ids. An unreadable file allows nothing: failing closed only costs a prompt."""
    p = path()
    try:
        data = json.loads(p.read_text(encoding="utf-8")) if p.exists() else {}
    except (OSError, ValueError):
        return {}
    if not isinstance(data, dict) or data.get("version", SCHEMA_VERSION) > SCHEMA_VERSION:
        return {}
    allowed = data.get("allowed")
    return allowed if isinstance(allowed, dict) else {}


def _save(allowed: dict[str, dict]) -> None:
    p = path()
    if p.exists():
        try:
            data = json.loads(p.read_text(encoding="utf-8"))
        except ValueError:
            raise ValueError(f"{p} is not valid JSON; fix or delete it first") from None
        if isinstance(data, dict) and data.get("version", SCHEMA_VERSION) > SCHEMA_VERSION:
            raise ValueError(f"{p} was written by a newer AgentDetox; upgrade agentdetox")
    tmp = private_dir(store_dir()) / "allowlist.json.tmp"
    write_private(tmp, json.dumps({"version": SCHEMA_VERSION, "allowed": allowed}, indent=1,
                                  ensure_ascii=False).encode())
    tmp.replace(p)


def add(flag_id: str, what: str = "", note: str = "") -> None:
    with store_lock():
        allowed = entries()
        allowed[flag_id] = {"what": what, "note": note, "added": time.strftime("%Y-%m-%dT%H:%M:%S")}
        _save(allowed)


def remove(flag_id: str) -> bool:
    with store_lock():
        allowed = entries()
        if allowed.pop(flag_id, None) is None:
            return False
        _save(allowed)
    return True


def unsuppressed(findings: list[Finding]) -> list[Finding]:
    allowed = entries()
    return [f for f in findings if finding_id(f) not in allowed] if allowed else findings


def finding_flag(f: Finding) -> Flag:
    detail = " ".join((f.anchor or f.evidence).split())[:100]
    return Flag(finding_id(f), f"{f.message}" + (f" | {detail}" if detail and detail != f.message else ""))


def source_id(tool: str, origin: str) -> str:
    return make_id("copied", tool, origin)


def copy_flag(c: CopyFinding) -> Flag:
    return Flag(source_id(c.tool, c.origin), f"copied from {c.tool} {c.origin}".strip())


def contradiction_flag(c: Contradiction) -> Flag:
    return Flag(make_id("contradiction", pair_anchor(c.new.text, c.existing.text)),
                f'"{c.new.text[:100]}" contradicts "{c.existing.text[:100]}"')
