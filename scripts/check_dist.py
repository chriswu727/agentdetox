"""Check built distributions: the package is all there, and nothing that must not ship is.

Usage: python scripts/check_dist.py dist/*
"""

import re
import sys
import tarfile
import zipfile
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
VERSION = re.search(r'__version__ = "([^"]+)"', (ROOT / "src/agentdetox/__init__.py").read_text(encoding="utf-8"))[1]
# research/ is private notes; bench/data holds downloaded third-party datasets.
NEVER = ("research/", "bench/data/", ".venv/", "__pycache__/")
WHEEL_NEEDS = ("agentdetox/__init__.py", "agentdetox/hooks.py", "agentdetox/demo.py")
SDIST_NEEDS = ("src/agentdetox/__init__.py", "tests/test_plugin.py", "LICENSE", "README.md", "CHANGELOG.md",
               "pyproject.toml")


def names(path: Path) -> list[str]:
    if path.suffix == ".whl":
        with zipfile.ZipFile(path) as z:
            return z.namelist()
    with tarfile.open(path) as t:
        return [m.name.split("/", 1)[1] for m in t.getmembers() if "/" in m.name]


def main(paths: list[str]) -> int:
    problems = []
    kinds = set()
    for p in map(Path, paths):
        kind = "wheel" if p.suffix == ".whl" else "sdist"
        kinds.add(kind)
        if f"-{VERSION}" not in p.name:
            problems.append(f"{p.name}: not version {VERSION}")
        members = names(p)
        problems += [f"{p.name}: ships {m}" for m in members if any(bad in m for bad in NEVER)]
        needs = WHEEL_NEEDS if kind == "wheel" else SDIST_NEEDS
        problems += [f"{p.name}: missing {n}" for n in needs if n not in members]
    problems += [f"no {k} built" for k in ("wheel", "sdist") if k not in kinds]
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"distributions for {VERSION} look right: {', '.join(Path(p).name for p in paths)}")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
