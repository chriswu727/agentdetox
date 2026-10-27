"""Clique-based poison detection following CleanBase (arXiv 2605.00460).

Poisoned passages written for the same target question tend to be mutually similar,
so they show up as cliques in a thresholded kNN similarity graph. Attackers who plant
two or fewer passages per target, or deliberately diversify them, can evade this.
"""

from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

import numpy as np


@dataclass
class ClusterResult:
    groups: list[list[int]] = field(default_factory=list)
    cliques: list[list[int]] = field(default_factory=list)
    tau: float | None = None
    mu: float | None = None
    sigma: float | None = None


def knn(v: np.ndarray, k: int, block: int = 1024) -> tuple[np.ndarray, np.ndarray]:
    n = len(v)
    idx = np.empty((n, k), dtype=np.int64)
    sims = np.empty((n, k), dtype=np.float32)
    for start in range(0, n, block):
        s = v[start : start + block] @ v.T
        rows = np.arange(s.shape[0])
        s[rows, start + rows] = -np.inf
        part = np.argpartition(-s, k - 1, axis=1)[:, :k]
        idx[start : start + len(rows)] = part
        sims[start : start + len(rows)] = np.take_along_axis(s, part, axis=1)
    return idx, sims


def detect_clusters(
    v: np.ndarray,
    k: int = 10,
    z: float = 2.5,
    min_clique: int = 3,
    sample_frac: float = 0.5,
    seed: int = 0,
) -> ClusterResult:
    n = len(v)
    if n < max(min_clique, 2):
        return ClusterResult()
    k = min(k, n - 1)
    idx, sims = knn(v, k)

    i = np.repeat(np.arange(n), k)
    j = idx.ravel()
    w = sims.ravel()
    a, b = np.minimum(i, j), np.maximum(i, j)
    _, first = np.unique(a * n + b, return_index=True)
    a, b, w = a[first], b[first], w[first]

    rng = np.random.default_rng(seed)
    m = min(len(w), max(2, int(len(w) * sample_frac)))
    sample = w[rng.choice(len(w), size=m, replace=False)]
    mu, sigma = float(sample.mean()), float(sample.std())
    tau = mu + z * sigma

    adj: dict[int, set[int]] = defaultdict(set)
    for x, y in zip(a[w > tau].tolist(), b[w > tau].tolist()):
        adj[x].add(y)
        adj[y].add(x)

    cliques = sorted(
        (sorted(c) for c in maximal_cliques(adj) if len(c) >= min_clique),
        key=lambda c: (-len(c), c),
    )
    return ClusterResult(groups=_merge_overlapping(cliques), cliques=cliques, tau=tau, mu=mu, sigma=sigma)


def maximal_cliques(adj: dict[int, set[int]]) -> list[set[int]]:
    """Bron–Kerbosch with pivoting."""
    out: list[set[int]] = []

    def expand(r: set[int], p: set[int], x: set[int]) -> None:
        if not p and not x:
            out.append(r)
            return
        pivot = max(p | x, key=lambda u: len(adj[u] & p))
        for node in list(p - adj[pivot]):
            expand(r | {node}, p & adj[node], x & adj[node])
            p.discard(node)
            x.add(node)

    expand(set(), set(adj), set())
    return out


def _merge_overlapping(cliques: list[list[int]]) -> list[list[int]]:
    parent: dict[int, int] = {}

    def find(u: int) -> int:
        while parent.setdefault(u, u) != u:
            parent[u] = parent[parent[u]]
            u = parent[u]
        return u

    for c in cliques:
        for node in c[1:]:
            parent[find(node)] = find(c[0])
    groups: dict[int, list[int]] = defaultdict(list)
    for node in parent:
        groups[find(node)].append(node)
    return sorted((sorted(g) for g in groups.values()), key=lambda g: (-len(g), g))
