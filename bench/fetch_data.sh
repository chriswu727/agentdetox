#!/usr/bin/env bash
# Download everything the benchmarks need into DATA_DIR (default: bench/data).
#   PoisonedRAG adversarial texts (MIT): github.com/sleeepeer/PoisonedRAG
#   SQuAD v1.1 paragraphs as the clean background (CC BY-SA 4.0)
#   deepset/prompt-injections, injection-labelled rows (Apache-2.0)
# Then: python bench/compare.py DATA_DIR
set -euo pipefail
cd "$(dirname "$0")/.."
DATA="${1:-bench/data}"
mkdir -p "$DATA"
for ds in nq hotpotqa msmarco; do
  curl -fsSL "https://raw.githubusercontent.com/sleeepeer/PoisonedRAG/main/results/adv_targeted_results/$ds.json" -o "$DATA/$ds.json"
done
python3 -I bench/fetch_squad.py "$DATA/squad_clean.jsonl"
python3 -I bench/fetch_injections.py "$DATA/injections.jsonl"
