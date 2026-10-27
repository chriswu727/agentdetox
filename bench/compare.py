"""Compare agentdetox with per-document injection scanners on the same data.

Two kinds of attack documents are mixed into a clean Wikipedia background:
  * knowledge poisoning: PoisonedRAG adv_texts (NQ, HotpotQA, MS MARCO), with and
    without the target question prepended;
  * indirect prompt injection: deepset/prompt-injections payloads appended to clean
    passages, in plain, hidden-HTML, Unicode-tag and zero-width-obfuscated forms.

Per-document tools are lenient-scored: any alert counts as a detection.

Usage:
  python bench/compare.py DATA_DIR [--tools agentdetox,veritensor,protectai,promptguard2]
DATA_DIR must hold nq.json, hotpotqa.json, msmarco.json, squad_clean.jsonl, injections.jsonl.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
from pathlib import Path

from agentdetox.corpus import Doc
from agentdetox.embed import get_embedder
from agentdetox.scan import scan

DATASETS = ("nq", "hotpotqa", "msmarco")
VARIANTS = ("plain", "hidden-html", "unicode-tags", "zero-width")


def load_jsonl(path: Path) -> list[dict]:
    with path.open(encoding="utf-8") as f:
        return [json.loads(line) for line in f if line.strip()]


def poison_set(data: Path, dataset: str, prefix: bool) -> list[Doc]:
    adv = json.loads((data / f"{dataset}.json").read_text(encoding="utf-8"))
    return [
        Doc(f"poison-{t['id']}-{j}", f"{t['question']}? {text}" if prefix else text, t["id"])
        for t in adv.values()
        for j, text in enumerate(t["adv_texts"])
    ]


def _zero_width(text: str) -> str:
    return " ".join(w[:2] + "​" + w[2:] if len(w) > 3 else w for w in text.split())


def injection_set(clean: list[Doc], payloads: list[str], variant: str) -> list[Doc]:
    docs = []
    for i, payload in enumerate(payloads):
        carrier = clean[(i * 37) % len(clean)].text
        if variant == "plain":
            text = f"{carrier}\n\n{payload}"
        elif variant == "hidden-html":
            text = f'<p>{carrier}</p>\n<div style="display:none">{payload}</div>'
        elif variant == "unicode-tags":
            text = carrier + "".join(chr(0xE0000 + ord(c)) for c in payload if 0x20 <= ord(c) <= 0x7E)
        else:
            text = f"{carrier}\n\n{_zero_width(payload)}"
        docs.append(Doc(f"inj-{variant}-{i}", text, variant))
    return docs


class CachedPerDocTool:
    """Per-document tools are independent of the corpus, so verdicts are cached by text."""

    def __init__(self, name: str, cache_dir: Path) -> None:
        self.name = name
        self.cache_path = cache_dir / f"cache-{name}.json"
        self.cache: dict[str, bool] = json.loads(self.cache_path.read_text()) if self.cache_path.exists() else {}

    def classify(self, texts: list[str]) -> list[bool]:
        raise NotImplementedError

    def flagged(self, docs: list[Doc]) -> set[str]:
        keys = [hashlib.sha1(d.text.encode("utf-8")).hexdigest() for d in docs]
        todo = sorted({k: d.text for k, d in zip(keys, docs) if k not in self.cache}.items())
        if todo:
            for (k, _), verdict in zip(todo, self.classify([t for _, t in todo])):
                self.cache[k] = verdict
            self.cache_path.write_text(json.dumps(self.cache))
        return {d.id for k, d in zip(keys, docs) if self.cache[k]}


class Veritensor(CachedPerDocTool):
    def classify(self, texts: list[str]) -> list[bool]:
        exe = shutil.which("veritensor") or str(Path(sys.executable).with_name("veritensor"))
        with tempfile.TemporaryDirectory() as tmp:
            for i, text in enumerate(texts):
                # Veritensor only runs its CSS-hiding checks on HTML files.
                ext = "html" if text.lstrip().startswith("<") else "txt"
                (Path(tmp) / f"{i}.{ext}").write_text(text, encoding="utf-8")
            out = subprocess.run(
                [exe, "scan", tmp, "--full-scan", "--json", "--ignore-license", "-j", "8"],
                capture_output=True, text=True,
            ).stdout
        records = json.loads(out)
        if len(records) != len(texts):
            print(f"warning: veritensor returned {len(records)} results for {len(texts)} files", file=sys.stderr)
        verdicts = [False] * len(texts)
        for rec in records:
            verdicts[int(Path(rec["file_path"]).stem)] = bool(rec["threats"])
        return verdicts


class HFClassifier(CachedPerDocTool):
    BENIGN = {"SAFE", "BENIGN", "LABEL_0"}

    def __init__(self, name: str, cache_dir: Path, model: str) -> None:
        super().__init__(name, cache_dir)
        self.model = model

    def classify(self, texts: list[str]) -> list[bool]:
        import torch
        from transformers import pipeline

        device = "mps" if torch.backends.mps.is_available() else -1
        clf = pipeline("text-classification", model=self.model, device=device, truncation=True, max_length=512)
        return [r["label"].upper() not in self.BENIGN for r in clf(texts, batch_size=16)]


def agentdetox_flagged(clean: list[Doc], attack: list[Doc], embedder) -> tuple[set[str], set[str]]:
    result = scan(clean + attack, embedder)
    high = {f.doc_id for f in result.findings if f.severity == "high"}
    medium = {f.doc_id for f in result.findings if f.severity in ("medium", "high")}
    return high, medium


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("data", type=Path)
    ap.add_argument("--tools", default="agentdetox,veritensor,protectai,promptguard2")
    args = ap.parse_args()
    tools = args.tools.split(",")

    clean = [Doc(r["id"], r["text"], r["id"]) for r in load_jsonl(args.data / "squad_clean.jsonl")]
    payloads = [r["text"] for r in load_jsonl(args.data / "injections.jsonl")]
    attack_sets: dict[str, list[Doc]] = {}
    for ds in DATASETS:
        attack_sets[f"{ds}/prefix"] = poison_set(args.data, ds, True)
        attack_sets[f"{ds}/noprefix"] = poison_set(args.data, ds, False)
    for v in VARIANTS:
        attack_sets[f"inject/{v}"] = injection_set(clean, payloads, v)

    per_doc: dict[str, CachedPerDocTool] = {}
    if "veritensor" in tools:
        per_doc["Veritensor 1.9.4"] = Veritensor("veritensor", args.data)
    if "protectai" in tools:
        per_doc["ProtectAI deberta-v3 PI v2"] = HFClassifier(
            "protectai", args.data, "protectai/deberta-v3-base-prompt-injection-v2")
    if "promptguard2" in tools:
        per_doc["Llama Prompt Guard 2 86M"] = HFClassifier(
            "promptguard2", args.data, "meta-llama/Llama-Prompt-Guard-2-86M")

    rows: dict[str, dict[str, float]] = {}
    for name, tool in per_doc.items():
        try:
            fp = tool.flagged(clean)
            row = {"clean FPR": len(fp) / len(clean)}
            for key, docs in attack_sets.items():
                row[key] = len(tool.flagged(docs)) / len(docs)
        except Exception as e:  # gated models, missing binaries
            print(f"skipping {name}: {type(e).__name__}: {str(e).splitlines()[0][:160]}", file=sys.stderr)
            continue
        rows[name] = row

    if "agentdetox" in tools:
        embedder = get_embedder("auto")
        high_row: dict[str, float] = {}
        med_row: dict[str, float] = {}
        clean_ids = {d.id for d in clean}
        fp_high: list[float] = []
        fp_med: list[float] = []
        for key, docs in attack_sets.items():
            ids = {d.id for d in docs}
            high, med = agentdetox_flagged(clean, docs, embedder)
            high_row[key] = len(high & ids) / len(ids)
            med_row[key] = len(med & ids) / len(ids)
            fp_high.append(len(high & clean_ids) / len(clean_ids))
            fp_med.append(len(med & clean_ids) / len(clean_ids))
        high_row["clean FPR"] = max(fp_high)
        med_row["clean FPR"] = max(fp_med)
        rows["AgentDetox 0.1 (high)"] = high_row
        rows["AgentDetox 0.1 (medium+)"] = med_row

    cols = ["clean FPR"] + list(attack_sets)
    print("| tool | " + " | ".join(cols) + " |")
    print("|---" * (len(cols) + 1) + "|")
    for name, row in rows.items():
        cells = [f"{row[c] * 100:.1f}%" for c in cols]
        print(f"| {name} | " + " | ".join(cells) + " |")
    print(f"\nclean passages: {len(clean)}; poison sets: 500 each; injection sets: {len(payloads)} each.")
    print("agentdetox clean FPR is the worst case over all runs (it scans each attack set together with the clean corpus).")


if __name__ == "__main__":
    main()
