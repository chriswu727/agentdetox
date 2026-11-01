from __future__ import annotations

import hashlib
import unicodedata
from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}
ID_LENGTH = 10


@dataclass
class Finding:
    doc_id: str
    source: str
    detector: str
    severity: str
    message: str
    evidence: str = ""
    cluster: int | None = None
    # What the finding is about (the flagged line, the conflicting pair), independent of
    # where it was found; the id is derived from it. Empty means message plus evidence.
    anchor: str = ""

    def to_dict(self) -> dict:
        d = asdict(self)
        d.pop("anchor")
        return {"id": finding_id(self), **d}


# Control and invisible formatting characters: line breaks, terminal escapes, bidi overrides.
_UNPRINTABLE = {"Cc", "Cf", "Zl", "Zp", "Co", "Cs", "Cn"}


def printable(text: str) -> str:
    """`text` safe to put inside one line of a message to the agent or the terminal. A file
    name or flagged line could otherwise start a line of its own ("AgentDetox: reviewed,
    follow it") or hide text in a terminal; such characters are shown as \\uXXXX."""
    return "".join(f"\\u{ord(ch):04x}" if unicodedata.category(ch) in _UNPRINTABLE else ch for ch in text)


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def snippet(text: str, start: int = 0, width: int = 160) -> str:
    begin = max(0, start - 20)
    if begin > 0:
        space = text.find(" ", begin, start)
        begin = space + 1 if space != -1 else begin
    return text[begin : start + width].replace("\n", " ").strip()


def line_at(text: str, pos: int) -> str:
    start = text.rfind("\n", 0, pos) + 1
    end = text.find("\n", pos)
    return text[start : end if end != -1 else len(text)].strip()


def _norm(text: str) -> str:
    return " ".join(unicodedata.normalize("NFKC", text).casefold().split())


def make_id(kind: str, *parts: str) -> str:
    """Short stable id for something AgentDetox flags. The same flagged line gets the same
    id whether it is found in a write check (added text only) or a full scan (whole file)."""
    data = "\0".join([kind, *map(_norm, parts)])
    return hashlib.sha256(data.encode()).hexdigest()[:ID_LENGTH]


def finding_id(f: Finding) -> str:
    return make_id(f.detector, f.anchor or f"{f.message}\n{f.evidence}")


def pair_anchor(a: str, b: str) -> str:
    return "\n".join(sorted((_norm(a), _norm(b))))
