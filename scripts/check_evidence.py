"""Do the documents still say what the recorded results say?

Checks, without running anything:
- every result file a Markdown file links to exists;
- every hook latency the READMEs quote in bold (`**110.3 ms**`) is a P95 in one of the
  recorded hook results, so a figure cannot outlive the run it came from unnoticed;
- every result recorded from now on names the commit and command it came from (older ones
  are listed in KNOWN_WITHOUT and are not added to).
"""

from __future__ import annotations

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
DOCS = [ROOT / "README.md", ROOT / "README.zh-CN.md", *sorted((ROOT / "docs").glob("*.md")),
        *sorted((ROOT / "bench").glob("*.md")), *sorted((ROOT / "lab").glob("*.md"))]
LINK = re.compile(r"\]\(([^)#\s]+\.json)\)")
QUOTED = re.compile(r"\*\*([0-9]+(?:\.[0-9]+)?)\s*ms\*\*")
# Hook results recorded before the benchmark wrote its own metadata.
KNOWN_WITHOUT = {"hooks-2026-10-30.json", "hooks-2026-11-01.json", "hooks-2026-11-05.json",
                 "hooks-clients-2026-11-10.json", "hooks-followup-2026-11-05.json", "hooks-loaded-2026-11-05.json",
                 "hooks-paired-2026-11-05.json", "hooks-phase1-2026-11-09.json", "hooks-post-audit-2026-11-05.json",
                 "hooks-release-rerun-2026-11-05.json", "hooks-self-use-2026-10-30.json",
                 "hooks-windows-2026-11-09.json", "hooks-windows-io-2026-11-09.json",
                 "hooks-windows-io-paired-2026-11-09.json", "hooks-windows-paired-2026-11-09.json"}


def numbers(value) -> set[str]:
    """Every number in a result, as the documents would print it."""
    found: set[str] = set()
    if isinstance(value, dict):
        for item in value.values():
            found |= numbers(item)
    elif isinstance(value, list):
        for item in value:
            found |= numbers(item)
    elif isinstance(value, (int, float)) and not isinstance(value, bool):
        found.add(f"{value:.1f}")
    return found


def main() -> int:
    problems = []
    for doc in DOCS:
        text = doc.read_text(encoding="utf-8")
        for link in LINK.findall(text):
            if link.startswith(("http://", "https://")):
                link = link.split("/blob/main/", 1)[-1] if "/blob/main/" in link else ""
                target = ROOT / link if link else None
            else:
                target = (doc.parent / link).resolve()
            if target is not None and not target.exists():
                problems.append(f"{doc.relative_to(ROOT)}: links to {link}, which does not exist")
    hooks = sorted((ROOT / "bench" / "results").glob("hooks-*.json"))
    measured: set[str] = set()
    for path in hooks:
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except ValueError:
            problems.append(f"{path.relative_to(ROOT)}: not JSON")
            continue
        measured |= numbers(data)
        missing = [key for key in ("source_commit", "command") if not (isinstance(data, dict) and data.get(key))]
        if missing and path.name not in KNOWN_WITHOUT:
            problems.append(f"{path.relative_to(ROOT)}: does not say its {' or '.join(missing)}")
    for doc in (ROOT / "README.md", ROOT / "README.zh-CN.md"):
        for quoted in QUOTED.findall(doc.read_text(encoding="utf-8")):
            if f"{float(quoted):.1f}" not in measured:
                problems.append(f"{doc.name}: quotes {quoted} ms, which is in no recorded hook result")
    for problem in problems:
        print(problem)
    print(f"{len(DOCS)} documents and {len(hooks)} hook results checked: "
          + ("all consistent" if not problems else f"{len(problems)} problem(s)"))
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main())
