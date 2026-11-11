"""Which code a measurement was taken on, recorded with the result.

A number without the commit it was measured at cannot be checked later, and "the latest
run" stops being the latest without anyone noticing.
"""

from __future__ import annotations

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def run_metadata() -> dict[str, str]:
    """The commit the working tree is at (marked when it has uncommitted changes) and the
    command line, for a result file."""
    def git(*args: str) -> str:
        try:
            return subprocess.run(["git", *args], cwd=ROOT, capture_output=True, text=True, timeout=20).stdout.strip()
        except (OSError, subprocess.SubprocessError):
            return ""

    commit = git("rev-parse", "HEAD") or "unknown"
    if commit != "unknown" and git("status", "--porcelain", "--untracked-files=no"):
        commit += "-dirty"
    return {"source_commit": commit, "command": " ".join(["python", _program(), *sys.argv[1:]])}


def _program() -> str:
    """The program as someone else would type it: `-m bench.name`, not this machine's path to it."""
    try:
        relative = Path(sys.argv[0]).resolve().relative_to(ROOT)
    except (OSError, ValueError):
        return Path(sys.argv[0]).name
    if relative.suffix == ".py" and relative.parts[0] == "bench":
        return "-m " + ".".join(relative.with_suffix("").parts)
    return relative.as_posix()
