"""Attribute a wrong RAG answer to the passages most likely responsible.

Loosely follows RAGOrigin (IEEE S&P 2026, arXiv 2509.13772): z-score several
responsibility signals over an attribution scope, average them, and split the scope
with 1-D 2-means. RAGOrigin's two LLM log-probability signals are replaced here by
embedding similarity to the wrong answer and literal answer containment, so this is
a cheaper approximation, not a reproduction.
"""

from __future__ import annotations

from dataclasses import dataclass

import numpy as np

from .corpus import Doc
from .hidden import normalize, scan_doc


@dataclass
class TraceRow:
    doc: Doc
    retrieval: float
    answer_sim: float
    contains_answer: bool
    score: float
    responsible: bool
    markers: list[str]


def trace(
    docs: list[Doc],
    vectors: np.ndarray,
    embedder,
    question: str,
    answer: str,
    top_k: int = 5,
    scope_mult: int = 4,
) -> list[TraceRow]:
    qv, av = embedder.encode([question, answer])
    retrieval = vectors @ qv
    scope = np.argsort(-retrieval)[: min(len(docs), top_k * scope_mult)]
    if len(scope) == 0:
        return []

    norm_answer = " ".join(normalize(answer).lower().split())
    es = retrieval[scope]
    asim = vectors[scope] @ av
    contains = np.array(
        [bool(norm_answer) and norm_answer in " ".join(normalize(docs[i].text).lower().split()) for i in scope],
        dtype=float,
    )
    score = (_z(es) + _z(asim) + _z(contains)) / 3
    upper = _two_means_upper(score)

    rows = [
        TraceRow(
            doc=docs[i],
            retrieval=float(es[r]),
            answer_sim=float(asim[r]),
            contains_answer=bool(contains[r]),
            score=float(score[r]),
            responsible=bool(upper[r]),
            markers=sorted({f.detector for f in scan_doc(docs[i]) if f.severity != "low"}),
        )
        for r, i in enumerate(scope)
    ]
    return sorted(rows, key=lambda row: -row.score)


def _z(x: np.ndarray) -> np.ndarray:
    sd = x.std()
    return np.zeros_like(x, dtype=float) if sd < 1e-9 else (x - x.mean()) / sd


def _two_means_upper(x: np.ndarray) -> np.ndarray:
    """Exact 1-D 2-means; returns a mask of the higher-mean cluster."""
    n = len(x)
    if n < 2 or x.std() < 1e-9:
        return np.zeros(n, dtype=bool)
    order = np.argsort(x)
    s = x[order]
    best_split, best_cost = 1, np.inf
    for split in range(1, n):
        lo, hi = s[:split], s[split:]
        cost = ((lo - lo.mean()) ** 2).sum() + ((hi - hi.mean()) ** 2).sum()
        if cost < best_cost:
            best_split, best_cost = split, cost
    mask = np.zeros(n, dtype=bool)
    mask[order[best_split:]] = True
    return mask
