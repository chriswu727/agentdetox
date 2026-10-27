from __future__ import annotations

from dataclasses import asdict, dataclass

SEVERITY_ORDER = {"low": 0, "medium": 1, "high": 2}


@dataclass
class Finding:
    doc_id: str
    source: str
    detector: str
    severity: str
    message: str
    evidence: str = ""
    cluster: int | None = None

    def to_dict(self) -> dict:
        return asdict(self)


def at_least(severity: str, threshold: str) -> bool:
    return SEVERITY_ORDER[severity] >= SEVERITY_ORDER[threshold]


def snippet(text: str, start: int = 0, width: int = 160) -> str:
    s = text[max(0, start - 20) : start + width].replace("\n", " ")
    return s.strip()
