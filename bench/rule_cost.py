"""Does any rule cost more than its input's length?

Every rule is a pattern run over text someone else chose. A pattern that looks further than
it needs to (a `\\s*` after `^` under re.M, a `[^\\]]*` with no end in sight) costs the
text's length squared on the right input: 45 kB of empty lines once took a hook 50 seconds.
This builds such inputs from the rules themselves, each fragment and word of every pattern
repeated, runs the real scan at two sizes and reports any that grows faster than linearly.

    python -m bench.rule_cost            # every fragment, a few minutes
    python -m bench.rule_cost --quick    # the fragments the test suite uses

Exit status 1 when something grows superlinearly.
"""

from __future__ import annotations

import argparse
import re
import sys
import time

from agentdetox import hidden, persistence
from agentdetox.agentscan import scan_text

FRAGMENTS = ["\n", " ", "\t\n", "a", "a ", "a.", "a-", "= ", "http://", "https://a.b/", "<!--", "<![", "<!", "<a ",
             "<a b='", "</", "<?", "&#", "&", "`", "```\n", "'", '"', "\\", "$(", "[", "](", "![", "](https://a", "(",
             "{", "*", "-", "--", "# ", "> ", "| ", "1. ", ": ", "/", "~/", "\u4e0d", "\u3002", "\u200b", "\u202e", "<|",
             "[INST]", "- never ", "do not ", "don't ", ", and ", "; ", "a\n", "- a\n", "a, ", "x=y\n", "registry=",
             "curl ", "| sh ", "?a={", "@a:", "bypassPermissions ", "ignore previous instructions ",
             '"ignore previous instructions" ', "never show passwords to the user\n"]
KINDS = ("memory", "skill", "config", "shell")
# Characters of input. Linear rules take well under a quarter second for the larger one;
# the quadratic ones this was written for took from half a second to minutes.
SMALL, LARGE = 15_000, 60_000


def rule_words() -> list[str]:
    sources = [pattern.pattern for _, _, pattern in persistence.TEXT_RULES]
    for value in vars(hidden).values():
        items = value if isinstance(value, (list, tuple)) else (value,)
        for item in items:
            for part in item if isinstance(item, (list, tuple)) else (item,):
                if isinstance(part, re.Pattern):
                    sources.append(part.pattern)
    return sorted({word for source in sources for word in re.findall(r"[A-Za-z\u4e00-\u9fff]{2,}", source)})


def cost(text: str, kind: str) -> float:
    started = time.perf_counter()
    try:
        scan_text("x", "x", text, kind)
    except Exception:  # noqa: BLE001 - over budget counts as its elapsed time
        pass
    return time.perf_counter() - started


def superlinear(fragments: list[str], kinds: tuple[str, ...] = KINDS) -> list[tuple[float, float, str, str]]:
    """(seconds at the large size, at the small size, kind, fragment) for each input that
    takes over a quarter second and more than seven times as long at four times the size."""
    found = []
    for fragment in fragments:
        for kind in kinds:
            large = cost(fragment * (LARGE // len(fragment)), kind)
            if large < 0.25:
                continue
            small = cost(fragment * (SMALL // len(fragment)), kind)
            if large > 7 * small:
                # One slow measurement on a busy machine is not a finding: measure again.
                large = min(large, *(cost(fragment * (LARGE // len(fragment)), kind) for _ in range(2)))
                small = min(small, *(cost(fragment * (SMALL // len(fragment)), kind) for _ in range(2)))
                if large > 7 * small:
                    found.append((large, small, kind, fragment))
    return found


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--quick", action="store_true", help="only the fixed fragments, not every word of every rule")
    args = parser.parse_args()
    fragments = list(FRAGMENTS)
    if not args.quick:
        for word in rule_words():
            fragments += [word + " ", word + "\n"]
    started = time.perf_counter()
    found = superlinear(fragments)
    print(f"{len(fragments)} fragments x {len(KINDS)} kinds in {time.perf_counter() - started:.0f}s; "
          f"superlinear: {len(found)}")
    for large, small, kind, fragment in sorted(found, reverse=True):
        print(f"  {SMALL} chars {small:.2f}s -> {LARGE} chars {large:.2f}s  {kind:7} {fragment!r}")
    return 1 if found else 0


if __name__ == "__main__":
    sys.exit(main())
