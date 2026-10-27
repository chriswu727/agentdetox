from __future__ import annotations

import math
import re
import zlib

import numpy as np

from .hidden import normalize

_WORD_RE = re.compile(r"\w+")
_CJK_RUN_RE = re.compile(r"[一-鿿]{2,}")


class HashingEmbedder:
    """Signed feature hashing over character n-grams and words.

    Lexical rather than semantic: it catches near-duplicate and template-reused
    poison well, but paraphrased poison needs a semantic embedder (st:<model>).
    """

    def __init__(self, dim: int = 2048, ngram_range: tuple[int, int] = (3, 5)) -> None:
        self.dim = dim
        self.ngram_range = ngram_range
        self.idf: np.ndarray | None = None
        self.name = f"hashing(dim={dim}, idf)"

    def fit(self, texts: list[str]) -> "HashingEmbedder":
        # Without IDF, function-word n-grams dominate cosine similarity and hide the
        # rare terms (names, claims) that poisoned passages for one target share.
        df = (self._raw(texts) != 0).sum(axis=0)
        self.idf = (np.log((1 + len(texts)) / (1 + df)) + 1).astype(np.float32)
        return self

    def _features(self, text: str) -> dict[str, int]:
        t = " ".join(normalize(text).lower().split())
        feats: dict[str, int] = {}
        lo, hi = self.ngram_range
        for n in range(lo, hi + 1):
            for i in range(len(t) - n + 1):
                g = t[i : i + n]
                feats[g] = feats.get(g, 0) + 1
        for w in _WORD_RE.findall(t):
            key = "w:" + w
            feats[key] = feats.get(key, 0) + 1
        # Chinese has no spaces and its words are mostly two characters, which the
        # 3-5 char n-grams above miss ("用户", "回答"); add CJK bigrams.
        for run in _CJK_RUN_RE.findall(t):
            for i in range(len(run) - 1):
                key = "c:" + run[i : i + 2]
                feats[key] = feats.get(key, 0) + 1
        return feats

    def _raw(self, texts: list[str]) -> np.ndarray:
        m = np.zeros((len(texts), self.dim), dtype=np.float32)
        for row, text in enumerate(texts):
            for feat, count in self._features(text).items():
                h = zlib.crc32(feat.encode("utf-8"))
                sign = 1.0 if h & 0x80000000 else -1.0
                m[row, h % self.dim] += sign * (1.0 + math.log(count))
        return m

    def encode(self, texts: list[str]) -> np.ndarray:
        m = self._raw(texts)
        if self.idf is not None:
            m *= self.idf
        return _l2_normalize(m)


class SentenceTransformerEmbedder:
    def __init__(self, model_name: str) -> None:
        try:
            from sentence_transformers import SentenceTransformer
        except ImportError as e:
            raise SystemExit("st:<model> needs the optional extra: pip install 'agentdetox[st]'") from e
        self.model = SentenceTransformer(model_name)
        self.name = f"st:{model_name}"

    def encode(self, texts: list[str]) -> np.ndarray:
        v = self.model.encode(texts, batch_size=64, show_progress_bar=False, convert_to_numpy=True)
        return _l2_normalize(np.asarray(v, dtype=np.float32))


DEFAULT_ST_MODEL = "sentence-transformers/all-MiniLM-L6-v2"


def get_embedder(spec: str):
    if spec == "auto":
        try:
            import sentence_transformers  # noqa: F401
        except ImportError:
            return HashingEmbedder()
        return SentenceTransformerEmbedder(DEFAULT_ST_MODEL)
    if spec == "hashing":
        return HashingEmbedder()
    if spec.startswith("st:"):
        return SentenceTransformerEmbedder(spec[3:])
    raise SystemExit(f"unknown embedder {spec!r}; use 'auto', 'hashing' or 'st:<sentence-transformers model>'")


def _l2_normalize(m: np.ndarray) -> np.ndarray:
    norms = np.linalg.norm(m, axis=1, keepdims=True)
    norms[norms == 0] = 1.0
    return m / norms
