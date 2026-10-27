"""Fetch unique Wikipedia paragraphs from SQuAD v1.1 (train) as a clean background corpus.

Usage: python bench/fetch_squad.py OUT.jsonl [--pages 250]
"""

import argparse
import json
import time
import urllib.request

API = "https://datasets-server.huggingface.co/rows?dataset=rajpurkar/squad&config=plain_text&split=train&offset={}&length=100"
TOTAL_ROWS = 87599


def main() -> None:
    ap = argparse.ArgumentParser()
    ap.add_argument("out")
    ap.add_argument("--pages", type=int, default=250)
    args = ap.parse_args()

    stride = TOTAL_ROWS // args.pages
    seen: dict[str, str] = {}
    for p in range(args.pages):
        for attempt in range(3):
            try:
                with urllib.request.urlopen(API.format(p * stride), timeout=30) as r:
                    rows = json.load(r)["rows"]
                break
            except Exception:
                time.sleep(2 * (attempt + 1))
        else:
            print(f"skipping page {p}")
            continue
        for row in rows:
            seen.setdefault(row["row"]["context"], row["row"]["title"])

    with open(args.out, "w", encoding="utf-8") as f:
        for i, (context, title) in enumerate(seen.items()):
            f.write(json.dumps({"id": f"squad-{i}", "title": title, "text": context}, ensure_ascii=False) + "\n")
    print(f"wrote {len(seen)} unique paragraphs from {len(set(seen.values()))} articles to {args.out}")


if __name__ == "__main__":
    main()
