"""Evaluate agentdetox against the published PoisonedRAG adversarial texts.

Clean background: Wikipedia paragraphs (see fetch_squad.py). Poison: PoisonedRAG's
released adv_texts (5 per target question), either with the target question prepended
(the black-box attack as published) or without it (a paraphrase-only attacker).

Usage:
  python bench/poisonedrag_eval.py ADV.json CLEAN.jsonl [--mode prefix|noprefix]
      [--embedder hashing|auto|st:MODEL] [--targets 100] [--trace]
"""

import argparse
import json
import time

import numpy as np

from agentdetox.corpus import Doc
from agentdetox.embed import get_embedder
from agentdetox.scan import scan
from agentdetox.trace import trace


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("adv")
    ap.add_argument("clean")
    ap.add_argument("--mode", choices=["prefix", "noprefix"], default="prefix")
    ap.add_argument("--embedder", default="hashing")
    ap.add_argument("--targets", type=int, default=100)
    ap.add_argument("--trace", action="store_true")
    args = ap.parse_args()

    with open(args.adv, encoding="utf-8") as f:
        adv = list(json.load(f).values())[: args.targets]
    with open(args.clean, encoding="utf-8") as f:
        clean = [Doc(r["id"], r["text"], r["id"]) for r in map(json.loads, f)]

    poison: list[Doc] = []
    for t in adv:
        for j, text in enumerate(t["adv_texts"]):
            body = f"{t['question']}? {text}" if args.mode == "prefix" else text
            poison.append(Doc(f"poison-{t['id']}-{j}", body, t["id"]))
    docs = clean + poison
    poison_ids = {d.id for d in poison}
    clean_ids = {d.id for d in clean}

    embedder = get_embedder(args.embedder)
    t0 = time.time()
    result = scan(docs, embedder)
    elapsed = time.time() - t0

    def flagged(min_sev: set[str], detector: str | None = None) -> set[str]:
        return {f.doc_id for f in result.findings
                if f.severity in min_sev and (detector is None or f.detector == detector)}

    high, medplus = flagged({"high"}), flagged({"medium", "high"})
    print(f"corpus: {len(clean)} clean + {len(poison)} poison ({len(adv)} targets), mode={args.mode}, "
          f"embedder={result.embedder}, scan {elapsed:.1f}s")
    print(f"poison recall  high: {len(high & poison_ids) / len(poison_ids):.3f}   "
          f"medium+: {len(medplus & poison_ids) / len(poison_ids):.3f}")
    print(f"clean FPR      high: {len(high & clean_ids) / len(clean_ids):.4f}   "
          f"medium+: {len(medplus & clean_ids) / len(clean_ids):.4f}")
    for det in ("poison-cluster", "question-template", "injection-phrase"):
        hit = flagged({"low", "medium", "high"}, det)
        print(f"  {det:<18} poison {len(hit & poison_ids):>4}   clean {len(hit & clean_ids):>4}")
    c = result.cluster
    print(f"  clique threshold tau={c.tau:.3f} (mu={c.mu:.3f}, sigma={c.sigma:.3f}), {len(c.groups)} groups")

    if args.trace:
        texts = [d.text for d in docs]
        if hasattr(embedder, "fit"):
            embedder.fit(texts)
        vectors = embedder.encode(texts)
        precisions, recalls = [], []
        for t in adv:
            truth = {d.id for d in poison if d.source == t["id"]}
            rows = trace(docs, vectors, embedder, t["question"], t["incorrect answer"])
            marked = {r.doc.id for r in rows if r.responsible}
            precisions.append(len(marked & truth) / len(marked) if marked else 0.0)
            recalls.append(len(marked & truth) / len(truth))
        print(f"trace          precision {np.mean(precisions):.3f}   recall {np.mean(recalls):.3f}   "
              f"(per target question, averaged over {len(adv)})")


if __name__ == "__main__":
    main()
