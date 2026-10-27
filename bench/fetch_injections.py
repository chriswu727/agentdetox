"""Fetch the injection-labelled rows of deepset/prompt-injections (Apache-2.0).

Usage: python bench/fetch_injections.py OUT.jsonl
"""

import argparse
import json
import urllib.request

API = "https://datasets-server.huggingface.co/rows?dataset=deepset/prompt-injections&config=default&split={}&offset={}&length=100"


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    args = ap.parse_args()

    payloads: dict[str, None] = {}
    for split, total in (("train", 546), ("test", 116)):
        for offset in range(0, total, 100):
            with urllib.request.urlopen(API.format(split, offset), timeout=30) as r:
                for row in json.load(r)["rows"]:
                    if row["row"]["label"] == 1:
                        payloads[" ".join(row["row"]["text"].split())] = None

    with open(args.out, "w", encoding="utf-8") as f:
        for i, text in enumerate(payloads):
            f.write(json.dumps({"id": f"inj-{i}", "text": text}, ensure_ascii=False) + "\n")
    print(f"wrote {len(payloads)} injection payloads to {args.out}")


if __name__ == "__main__":
    main()
