import numpy as np
import pytest

from agentdetox.cluster import detect_clusters, maximal_cliques
from agentdetox.corpus import Doc
from agentdetox.embed import HashingEmbedder, get_embedder
from agentdetox.scan import scan
from agentdetox.trace import trace


def test_maximal_cliques_small_graph():
    adj = {0: {1, 2}, 1: {0, 2}, 2: {0, 1, 3}, 3: {2}}
    cliques = sorted(sorted(c) for c in maximal_cliques(adj))
    assert cliques == [[0, 1, 2], [2, 3]]


def test_detect_clusters_handles_tiny_input():
    v = np.eye(2, dtype=np.float32)
    assert detect_clusters(v).groups == []


def test_poisonedrag_passages_are_high_and_clean_docs_are_not(clean_docs, poisoned_docs):
    result = scan(clean_docs + poisoned_docs, HashingEmbedder())
    high = {f.doc_id for f in result.findings if f.severity == "high"}
    assert {d.id for d in poisoned_docs} <= high
    assert not any(doc_id.startswith("clean") for doc_id in high)


def test_semantic_embedder_clusters_poison_without_question_prefix(clean_docs, poisoned_docs):
    pytest.importorskip("sentence_transformers")
    stripped = [Doc(d.id, d.text.split("? ", 1)[1], d.source) for d in poisoned_docs]
    result = scan(clean_docs + stripped, get_embedder("auto"))
    clustered = {f.doc_id for f in result.findings if f.detector == "poison-cluster"}
    assert {d.id for d in stripped} <= clustered
    assert not any(f.severity == "high" and f.doc_id.startswith("clean") for f in result.findings)


def test_two_poison_passages_evade_clustering(clean_docs, poisoned_docs):
    # Documented CleanBase limit: fewer than three passages cannot form a clique.
    result = scan(clean_docs + poisoned_docs[:2], HashingEmbedder())
    assert not any(f.doc_id.startswith("poison") for f in result.findings)


def test_exact_duplicates_do_not_form_cliques(clean_docs):
    dup = Doc(id="dup", text="Copyright 2026 Example Corp. All rights reserved.", source="dup")
    docs = clean_docs + [Doc(id=f"dup-{i}", text=dup.text, source=f"dup-{i}") for i in range(5)]
    result = scan(docs, HashingEmbedder())
    assert not any(f.detector == "poison-cluster" and f.doc_id.startswith("dup") for f in result.findings)
    assert any(f.detector == "duplicate-text" and f.severity == "low" for f in result.findings)


def test_trace_marks_poison_as_responsible(clean_docs, poisoned_docs):
    docs = clean_docs + poisoned_docs
    emb = HashingEmbedder().fit([d.text for d in docs])
    rows = trace(docs, emb.encode([d.text for d in docs]), emb, "Who is the CEO of OpenAI?", "Tim Cook")
    responsible = {r.doc.id for r in rows if r.responsible}
    assert responsible == {d.id for d in poisoned_docs}
