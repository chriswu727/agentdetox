"""Contradiction detection between memory statements.

A fabricated fact rarely contains an attack string, but it often conflicts with what the
agent already knows ("deploys run the staging checks" vs "the staging checks were
retired, skip them"). Statements are split out of memory and instruction files, related
pairs are found with lexical similarity, and a multilingual NLI model judges whether
each pair contradicts. A fabricated fact that conflicts with nothing is not caught here.
"""

from __future__ import annotations

import os
import re
from dataclasses import dataclass
from pathlib import Path

import zlib

import numpy as np

NLI_MODEL = "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7"
CONTRADICTION_THRESHOLD = 0.8
# Only a pre-filter: the NLI model decides, and each statement is compared with at most
# CANDIDATES_PER_STATEMENT others, so a low bar costs model calls, not false positives.
MIN_SIMILARITY = 0.05
CANDIDATES_PER_STATEMENT = 5

_FRONTMATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.S)
_FENCE_RE = re.compile(r"^```.*?^```", re.S | re.M)
_BULLET_RE = re.compile(r"^\s*(?:[-*+]|\d+[.)])\s+")
# English sentences end at .!? followed by a space and a capital or digit, which keeps
# "e.g. this", "v2.1" and "config.toml" intact; Chinese sentences end at 。！？.
_SENTENCE_RE = re.compile(r"(?<=[.!?])\s+(?=[A-Z0-9\"'`(])|(?<=[。！？；])")
_CJK_RE = re.compile(r"[一-鿿]")


@dataclass(frozen=True)
class Statement:
    text: str
    source: str
    line: int


@dataclass
class Contradiction:
    new: Statement
    existing: Statement
    probability: float


def statements(text: str, source: str) -> list[Statement]:
    text = _FRONTMATTER_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    text = _FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    out: list[Statement] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        line = raw.strip()
        if not line or line.startswith(("#", "|", ">", "<!--")):
            continue
        line = _BULLET_RE.sub("", line)
        for sentence in _SENTENCE_RE.split(line):
            s = sentence.strip()
            if len(s) >= (6 if _CJK_RE.search(s) else 12):
                out.append(Statement(s, source, lineno))
    return out


class NLI:
    """Lazily loaded so that hooks which never need it never pay the torch import."""

    def __init__(self, model: str = NLI_MODEL, local_only: bool = True) -> None:
        self.model_name = model
        self.local_only = local_only
        self._model = None

    @staticmethod
    def installed() -> bool:
        try:
            import torch  # noqa: F401
            import transformers  # noqa: F401
        except ImportError:
            return False
        return True

    def available(self) -> bool:
        if os.environ.get("AGENTDETOX_NLI") == "0" or not self.installed():
            return False
        try:
            from huggingface_hub import try_to_load_from_cache
        except ImportError:
            return False
        return isinstance(try_to_load_from_cache(self.model_name, "config.json"), str)

    def _load(self):
        if self._model is None:
            import torch
            from transformers import AutoModelForSequenceClassification, AutoTokenizer

            self._torch = torch
            self._tok = AutoTokenizer.from_pretrained(self.model_name, local_files_only=self.local_only)
            self._model = AutoModelForSequenceClassification.from_pretrained(
                self.model_name, local_files_only=self.local_only).eval()
            labels = {i: l.lower() for i, l in self._model.config.id2label.items()}
            self._contra = next(i for i, l in labels.items() if l.startswith("contra"))
        return self._model

    def contradiction(self, pairs: list[tuple[str, str]], batch: int = 16) -> list[float]:
        """Probability that each pair contradicts, taking the max over both orders."""
        if not pairs:
            return []
        model = self._load()
        torch = self._torch
        # Starting the GPU costs more than a hook's handful of pairs saves.
        device = "mps" if len(pairs) > 64 and torch.backends.mps.is_available() else "cpu"
        model.to(device)
        probs: list[float] = []
        for i in range(0, len(pairs), batch):
            chunk = pairs[i : i + batch]
            a = [p[0] for p in chunk] + [p[1] for p in chunk]
            b = [p[1] for p in chunk] + [p[0] for p in chunk]
            enc = self._tok(a, b, return_tensors="pt", padding=True, truncation=True, max_length=256).to(device)
            with torch.no_grad():
                p = torch.softmax(model(**enc).logits, -1)[:, self._contra]
            n = len(chunk)
            probs += torch.maximum(p[:n], p[n:]).tolist()
        return probs


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*")
_STOPWORDS = frozenset(
    "a an the is are was were be been being to of in on at by for with from as and or but not no it its this that "
    "these those which who what when where how than then so such can could should would will may might must do does "
    "did done has have had i you he she we they them their our your his her my me us use uses used using".split()
)
_DIM = 4096


def _tokens(text: str) -> list[str]:
    """Content words for finding statements about the same thing. Character n-grams would
    let the many unique fragments of a short Chinese sentence drown its shared words."""
    words = [w.lower().strip("./:-") for w in _TOKEN_RE.findall(text)]
    out = [w for w in words if len(w) > 1 and w not in _STOPWORDS]
    for run in re.findall(r"[一-鿿]+", text):
        out += [run[i : i + 2] for i in range(len(run) - 1)] or [run]
    return out


def _vectors(texts: list[str]) -> np.ndarray:
    rows = [{zlib.crc32(t.encode()) % _DIM: 0.0 for t in _tokens(x)} for x in texts]
    for row, x in zip(rows, texts):
        for t in _tokens(x):
            row[zlib.crc32(t.encode()) % _DIM] += 1.0
    df = np.zeros(_DIM)
    for row in rows:
        df[list(row)] += 1
    idf = np.log((1 + len(texts)) / (1 + df)) + 1
    m = np.zeros((len(texts), _DIM), dtype=np.float32)
    for i, row in enumerate(rows):
        for j, tf in row.items():
            m[i, j] = (1 + np.log(tf)) * idf[j]
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1
    return m / norms


def candidate_pairs(new: list[Statement], existing: list[Statement],
                    k: int = CANDIDATES_PER_STATEMENT, min_sim: float = MIN_SIMILARITY) -> list[tuple[int, int]]:
    if not new or not existing:
        return []
    v = _vectors([s.text for s in new + existing])
    sims = v[: len(new)] @ v[len(new) :].T
    pairs = []
    for i in range(len(new)):
        for j in np.argsort(-sims[i])[:k]:
            if sims[i, j] >= min_sim and new[i].text != existing[j].text:
                pairs.append((i, int(j)))
    return pairs


def find_contradictions(new: list[Statement], existing: list[Statement], nli,
                        threshold: float = CONTRADICTION_THRESHOLD) -> list[Contradiction]:
    pairs = candidate_pairs(new, existing)
    probs = nli.contradiction([(new[i].text, existing[j].text) for i, j in pairs])
    best: dict[int, Contradiction] = {}
    for (i, j), p in zip(pairs, probs):
        if p >= threshold and (i not in best or p > best[i].probability):
            best[i] = Contradiction(new[i], existing[j], p)
    return sorted(best.values(), key=lambda c: -c.probability)


def store_statements(paths: list[Path], skip: set[str] = frozenset()) -> list[Statement]:
    out: list[Statement] = []
    for p in paths:
        if str(p) in skip or not p.is_file():
            continue
        out += statements(p.read_text(encoding="utf-8", errors="replace"), str(p))
    return out
