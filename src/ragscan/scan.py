from __future__ import annotations

import re
from collections import defaultdict
from dataclasses import dataclass, field

from .cluster import ClusterResult, detect_clusters
from .corpus import Doc
from .findings import Finding, snippet
from .hidden import normalize, scan_doc

# Periods are allowed so abbreviations ("Gerald R. Ford", "U.S.") and two-sentence
# questions still group together; grouping needs 3+ identical prefixes, so this
# loose match is safe there.
_LEADING_QUESTION_RE = re.compile(r"^\s*[^!?。！？\n]{8,300}[?？]")
# Escalating a similarity clique needs a stricter test, otherwise any text with a "?"
# in its first 300 chars (code samples, diff output) counts as opening with a question.
_SENTENCE_BREAK_RE = re.compile(r"(?<!\b[A-Z])[.。]\s")


def opens_with_question(text: str) -> bool:
    m = _LEADING_QUESTION_RE.match(text)
    return bool(m) and not _SENTENCE_BREAK_RE.search(m.group(0))


@dataclass
class ScanResult:
    findings: list[Finding]
    n_docs: int
    embedder: str | None = None
    cluster: ClusterResult = field(default_factory=ClusterResult)


def scan(
    docs: list[Doc],
    embedder=None,
    k: int = 10,
    z: float = 2.5,
    min_clique: int = 3,
) -> ScanResult:
    findings: list[Finding] = []
    for doc in docs:
        findings.extend(scan_doc(doc))

    if embedder is None:
        return ScanResult(findings, len(docs))

    # Exact duplicates are collapsed first so legitimate boilerplate repeated across a
    # knowledge base does not form trivially perfect cliques.
    by_text: dict[str, list[int]] = defaultdict(list)
    for i, doc in enumerate(docs):
        by_text[" ".join(normalize(doc.text).split())].append(i)
    unique_texts = list(by_text)
    members = list(by_text.values())

    for text, idxs in zip(unique_texts, members):
        if len(idxs) >= min_clique and text:
            first = docs[idxs[0]]
            findings.append(
                Finding(first.id, first.source, "duplicate-text", "low",
                        f"identical text appears {len(idxs)} times", snippet(text))
            )

    findings.extend(_question_template_findings(docs, unique_texts, members, min_clique))

    if hasattr(embedder, "fit"):
        embedder.fit(unique_texts)
    vectors = embedder.encode(unique_texts)
    result = detect_clusters(vectors, k=k, z=z, min_clique=min_clique)
    flagged_ids = {f.doc_id for f in findings if f.severity in ("medium", "high")}

    for cid, group in enumerate(result.groups, 1):
        question_led = {u: opens_with_question(unique_texts[u]) for u in group}
        templated = sum(question_led.values()) * 3 >= len(group) * 2
        reason = "mutually similar passages"
        if templated:
            reason += "; most open with a question, the PoisonedRAG template"
        for u in group:
            for i in members[u]:
                # Severity is per member: a clean passage on the attacked topic can be
                # pulled into a poison clique, and should not inherit "high" from it.
                own_evidence = docs[i].id in flagged_ids or (templated and question_led[u])
                findings.append(
                    Finding(docs[i].id, docs[i].source, "poison-cluster", "high" if own_evidence else "medium",
                            f"member of a {len(group)}-passage similarity clique ({reason})",
                            snippet(docs[i].text), cluster=cid)
                )

    return ScanResult(findings, len(docs), embedder.name, result)


def _question_template_findings(
    docs: list[Doc], unique_texts: list[str], members: list[list[int]], min_count: int
) -> list[Finding]:
    """PoisonedRAG's black-box attack prepends the target question verbatim to every
    poisoned passage, so several distinct passages opening with one question is a
    precise signal that does not depend on any similarity threshold."""
    by_question: dict[str, list[int]] = defaultdict(list)
    for u, text in enumerate(unique_texts):
        m = _LEADING_QUESTION_RE.match(text)
        if m:
            by_question[re.sub(r"\W+", " ", m.group(0).lower()).strip()].append(u)
    out = []
    for question, group in by_question.items():
        if len(group) < min_count:
            continue
        for u in group:
            for i in members[u]:
                out.append(
                    Finding(docs[i].id, docs[i].source, "question-template", "high",
                            f"{len(group)} different passages open with the same question, the PoisonedRAG template",
                            question[:160])
                )
    return out
