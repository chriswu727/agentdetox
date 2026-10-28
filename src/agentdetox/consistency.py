"""Contradiction detection between memory statements.

A fabricated fact rarely contains an attack string, but it often conflicts with what the
agent already knows ("deploys run the staging checks" vs "the staging checks were
retired, skip them"). Statements are split out of memory and instruction files, related
pairs are found with lexical similarity, and a multilingual NLI model judges whether
each pair contradicts. A fabricated fact that conflicts with nothing is not caught here.
"""

from __future__ import annotations

import importlib.util
import os
import re
from dataclasses import dataclass
from pathlib import Path

import zlib

import numpy as np

NLI_MODEL = "MoritzLaurer/mDeBERTa-v3-base-xnli-multilingual-nli-2mil7"
CONTRADICTION_THRESHOLD = 0.8
# The NLI model also misreads unrelated pairs as contradictions, so this pre-filter does
# real work: only statements that share content words get compared. Set on the dev split
# of bench/memory_eval.py: 0.15 is the lowest value with no false alarm on its benign cases.
MIN_SIMILARITY = 0.15
CANDIDATES_PER_STATEMENT = 5
# Statements compared must share this many content words; one shared common word let the
# NLI model compare unrelated notes (set on the dev split and on real memory).
MIN_SHARED_TOKENS = 2

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
    context: str = ""  # nearest heading and parent list item, so the model knows the subject
    subject: str = ""  # the label of a "label: value" line ("Prod DB: db.acme.internal")


_HEADING_RE = re.compile(r"^(#{1,6})\s+(.*)$")
_LABEL_RE = re.compile(r"^\**`?(?P<label>[^:：—–`*\n]{1,48}?)`?\**\s*(?:[:：]|\s[—–]\s|\s-\s)\s*\**\s*(?P<value>\S.*)$")
_GENERIC_LABELS = {"note", "notes", "tip", "warning", "important", "update", "nb", "why", "how to apply", "example",
                   "注意", "备注", "提示", "说明", "原因", "例如"}
# Shorter fragments are list items whose subject lives in their context; 3 still keeps
# short claims such as "Node 22 is required."
MIN_CONTENT_TOKENS = 3


def _clean(s: str) -> str:
    return " ".join(s.replace("**", "").replace("`", "").split())


def _label(line: str) -> str:
    m = _LABEL_RE.match(line)
    if not m:
        return ""
    label = _clean(m.group("label")).strip(" -")
    if label.lower() in _GENERIC_LABELS or len(label.split()) > 5 or (_CJK_RE.search(label) and len(label) > 12):
        return ""
    return label


@dataclass
class Contradiction:
    new: Statement
    existing: Statement
    probability: float


def statements(text: str, source: str) -> list[Statement]:
    text = _FRONTMATTER_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    text = _FENCE_RE.sub(lambda m: "\n" * m.group(0).count("\n"), text)
    out: list[Statement] = []
    headings: list[tuple[int, str]] = []
    parents: list[tuple[int, str]] = []
    for lineno, raw in enumerate(text.splitlines(), 1):
        stripped = raw.strip()
        if not stripped:
            continue
        h = _HEADING_RE.match(stripped)
        if h:
            level = len(h.group(1))
            headings = [x for x in headings if x[0] < level] + [(level, _clean(h.group(2)))]
            parents = []
            continue
        # Index entries ("- [Title](file.md) — hook") point at facts that are compared in
        # their own files; as fragments they only feed the NLI model noise.
        if stripped.startswith(("|", ">", "<!--")) or _INDEX_LINE_RE.match(stripped):
            continue
        indent = len(raw) - len(raw.lstrip())
        bullet = bool(_BULLET_RE.match(raw))
        line = _BULLET_RE.sub("", stripped)
        if bullet:
            parents = [p for p in parents if p[0] < indent]
        context = " > ".join([x[1] for x in headings[-1:]] + [p[1] for p in parents[-1:]])[:100]
        if bullet:
            parents.append((indent, _clean(line)[:80]))
        elif line.endswith((":", "：")):
            parents = [(-1, _clean(line[:-1])[:80])]  # a paragraph introducing the list below
        else:
            parents = []
        subject = _label(line)
        for i, sentence in enumerate(_SENTENCE_RE.split(line)):
            s = sentence.strip()
            if not s or s.endswith((":", "：")) or len(_tokens(s)) < MIN_CONTENT_TOKENS:
                continue
            out.append(Statement(s, source, lineno, context, subject if i == 0 else ""))
    return out


def _same_subject(a: Statement, b: Statement) -> bool:
    """Two "label: value" lines only conflict if they are about the same label; a labelled
    line and a sentence only if the sentence mentions the label."""
    sa, sb = set(_tokens(a.subject)), set(_tokens(b.subject))
    if sa and sb:
        return bool(sa & sb)
    if sa:
        return bool(sa & set(_tokens(b.text)))
    if sb:
        return bool(sb & set(_tokens(a.text)))
    return True


def _nli_text(s: Statement) -> str:
    return f"{s.context}: {s.text}" if s.context else s.text


class NLI:
    """Lazily loaded so that hooks which never need it never pay the torch import."""

    def __init__(self, model: str = NLI_MODEL, local_only: bool = True) -> None:
        self.model_name = model
        self.local_only = local_only
        self._model = None

    @staticmethod
    def installed() -> bool:
        # find_spec, not import: importing torch alone costs ~2 s per hook process.
        return all(importlib.util.find_spec(m) is not None for m in ("torch", "transformers"))

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
        """Probability that each pair contradicts, taking the min over both orders.

        A real contradiction holds both ways. NLI models also call topic shifts
        "contradiction", but usually in one direction only (0.995 one way, 0.35 the other
        for two unrelated memory lines), so the max produced a flood of false alarms."""
        if not pairs:
            return []
        model = self._load()
        torch = self._torch
        # Starting the GPU costs more than a hook's handful of pairs saves; a long-running
        # process (a benchmark) can opt in with AGENTDETOX_NLI_DEVICE=mps.
        device = os.environ.get("AGENTDETOX_NLI_DEVICE") or (
            "mps" if len(pairs) > 64 and torch.backends.mps.is_available() else "cpu")
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
            probs += torch.minimum(p[:n], p[n:]).tolist()
        return probs


_TOKEN_RE = re.compile(r"[A-Za-z0-9][A-Za-z0-9_./:@-]*")
# Shared function words are not shared topics ("Forget everything before that" and "Run
# the linter before committing" share only "before").
_STOPWORDS = frozenset(
    "a an the is are was were be been being to of in on at by for with from as and or but not no nor it its this "
    "that these those which who whom whose what when where why how than then so such can could should would will "
    "may might must shall do does did done has have had having i you he she we they them their theirs our ours your "
    "yours his her hers my mine me us use uses used using before after again also all any both each every everything "
    "everyone few more most other some same only own too very just now here there into onto over under above below "
    "up down out off about against between through during until while if else because since though although unless "
    "whether yet ever never always often sometimes once still already instead rather etc via per please make makes "
    "made get gets got let lets like one two first new old".split()
)
_ZH_STOP_BIGRAMS = frozenset(
    "可以 需要 已经 我们 你们 他们 这个 那个 一个 没有 不是 就是 还是 以及 或者 但是 因为 所以 如果 进行 之前 之后 时候 什么 怎么 这样 那样".split()
)
_INDEX_LINE_RE = re.compile(r"^\s*(?:[-*+]\s+)?\[[^\]]+\]\([^)]+\)")
_DIM = 4096


def _tokens(text: str) -> list[str]:
    """Content words for finding statements about the same thing. Character n-grams would
    let the many unique fragments of a short Chinese sentence drown its shared words."""
    words = [w.lower().strip("./:-") for w in _TOKEN_RE.findall(text)]
    out = [w for w in words if len(w) > 1 and w not in _STOPWORDS]
    for run in re.findall(r"[一-鿿]+", text):
        out += [b for b in (run[i : i + 2] for i in range(len(run) - 1)) if b not in _ZH_STOP_BIGRAMS] or [run]
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
                    k: int = CANDIDATES_PER_STATEMENT, min_sim: float | None = None) -> list[tuple[int, int]]:
    if not new or not existing:
        return []
    min_sim = MIN_SIMILARITY if min_sim is None else min_sim
    v = _vectors([s.text for s in new + existing])
    sims = v[: len(new)] @ v[len(new) :].T
    pairs = []
    for i in range(len(new)):
        for j in np.argsort(-sims[i])[:k]:
            if (sims[i, j] >= min_sim and new[i].text != existing[j].text and _same_subject(new[i], existing[j])
                    and len(set(_tokens(new[i].text)) & set(_tokens(existing[j].text))) >= MIN_SHARED_TOKENS):
                pairs.append((i, int(j)))
    return pairs


def find_contradictions(new: list[Statement], existing: list[Statement], nli,
                        threshold: float | None = None) -> list[Contradiction]:
    threshold = CONTRADICTION_THRESHOLD if threshold is None else threshold
    pairs = candidate_pairs(new, existing)
    if not pairs:
        return []
    if callable(nli):  # a factory, so callers with nothing to compare never load the model
        nli = nli()
        if nli is None:
            return []
    probs = nli.contradiction([(_nli_text(new[i]), _nli_text(existing[j])) for i, j in pairs])
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
