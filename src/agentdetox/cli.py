from __future__ import annotations

import argparse
import json
import sys
from collections import Counter
from pathlib import Path

from . import __version__
from .corpus import load_corpus
from .embed import get_embedder
from .findings import SEVERITY_ORDER, at_least
from .scan import scan
from .trace import trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdetox", description=__doc__)
    parser.add_argument("--version", action="version", version=f"agentdetox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True)

    def corpus_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("path", type=Path, help="directory of .txt/.md/.html files, or a .jsonl file")
        p.add_argument("--text-field", default="text", help="JSONL field holding the passage text")
        p.add_argument("--id-field", default="id", help="JSONL field holding the passage id")
        p.add_argument("--chunk-chars", type=int, default=0, help="split files into ~N-char chunks (0 = whole file)")
        p.add_argument("--embedder", default="auto",
                       help="'auto' (MiniLM if agentdetox[st] is installed, else hashing), 'hashing', or 'st:<model>'")
        p.add_argument("--format", choices=["text", "json"], default="text")

    p_scan = sub.add_parser("scan", help="scan a knowledge base for poisoned or injected documents")
    corpus_args(p_scan)
    p_scan.add_argument("--no-cluster", action="store_true", help="only run the per-document injection detectors")
    p_scan.add_argument("--k", type=int, default=10, help="neighbours per passage in the similarity graph")
    p_scan.add_argument("--z", type=float, default=2.5, help="edge threshold = mean + z * std of kNN similarities")
    p_scan.add_argument("--min-clique", type=int, default=3)
    p_scan.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high",
                        help="exit 1 if any finding is at least this severe (default: high)")

    p_trace = sub.add_parser("trace", help="find which passages likely caused a wrong answer")
    corpus_args(p_trace)
    p_trace.add_argument("--question", "-q", required=True)
    p_trace.add_argument("--answer", "-a", required=True, help="the wrong answer the RAG system produced")
    p_trace.add_argument("--top-k", type=int, default=5, help="passages your RAG retrieves per query")

    args = parser.parse_args(argv)
    if not args.path.exists():
        parser.error(f"{args.path} does not exist")
    docs = load_corpus(args.path, args.text_field, args.id_field, args.chunk_chars)
    if not docs:
        parser.error(f"no readable documents under {args.path}")

    if args.command == "scan":
        embedder = None if args.no_cluster else get_embedder(args.embedder)
        result = scan(docs, embedder, k=args.k, z=args.z, min_clique=args.min_clique)
        _print_scan(result, args.format)
        if args.fail_on != "none" and any(at_least(f.severity, args.fail_on) for f in result.findings):
            return 1
        return 0

    embedder = get_embedder(args.embedder)
    texts = [d.text for d in docs]
    if hasattr(embedder, "fit"):
        embedder.fit(texts)
    rows = trace(docs, embedder.encode(texts), embedder, args.question, args.answer, args.top_k)
    _print_trace(rows, args.format)
    return 0


def _print_scan(result, fmt: str) -> None:
    findings = sorted(result.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.cluster or 0, f.doc_id))
    if fmt == "json":
        c = result.cluster
        json.dump(
            {
                "version": __version__,
                "documents": result.n_docs,
                "embedder": result.embedder,
                "cluster_threshold": None if c.tau is None else {"tau": c.tau, "mu": c.mu, "sigma": c.sigma},
                "findings": [f.to_dict() for f in findings],
            },
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        print()
        return

    print(f"agentdetox {__version__}: scanned {result.n_docs} passages", end="")
    print(f" (embedder: {result.embedder})" if result.embedder else " (clustering off)")
    c = result.cluster
    if c.tau is not None:
        print(f"similarity-clique threshold tau={c.tau:.3f} (mu={c.mu:.3f}, sigma={c.sigma:.3f}); "
              f"{len(c.groups)} suspicious cluster(s)")
    print()
    for f in findings:
        tag = f" [cluster {f.cluster}]" if f.cluster else ""
        print(f"{f.severity.upper():<6} {f.detector:<17} {f.source}{tag}")
        print(f"       {f.message}")
        if f.evidence:
            print(f"       > {' '.join(f.evidence.split())[:160]}")
    counts = Counter(f.severity for f in findings)
    docs_hit = len({f.doc_id for f in findings})
    print(f"\n{counts['high']} high, {counts['medium']} medium, {counts['low']} low across {docs_hit} passage(s)")


def _print_trace(rows, fmt: str) -> None:
    if fmt == "json":
        json.dump(
            [
                {
                    "id": r.doc.id, "source": r.doc.source, "score": r.score, "responsible": r.responsible,
                    "retrieval": r.retrieval, "answer_similarity": r.answer_sim,
                    "contains_answer": r.contains_answer, "injection_markers": r.markers,
                }
                for r in rows
            ],
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        print()
        return
    print("Approximate attribution (embedding signals only; see README for limits)\n")
    print(f"{'':2}{'score':>7} {'retr':>6} {'ans':>6} {'has-ans':>7}  source")
    for r in rows:
        mark = "=>" if r.responsible else "  "
        extra = f"  [{', '.join(r.markers)}]" if r.markers else ""
        print(f"{mark}{r.score:7.2f} {r.retrieval:6.3f} {r.answer_sim:6.3f} {str(r.contains_answer):>7}  {r.doc.source}{extra}")
    n = sum(r.responsible for r in rows)
    print(f"\n{n} passage(s) marked => as likely responsible")


if __name__ == "__main__":
    sys.exit(main())
