"""Check a release tag against every version in the repository, and that the changelog
entry for it is dated rather than "unreleased". The release workflow runs this before
anything is built or published.

Usage: python scripts/check_release.py v0.2.0
"""

import json
import re
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main(tag: str) -> int:
    version = re.search(r'__version__ = "([^"]+)"', (ROOT / "src/agentdetox/__init__.py").read_text(encoding="utf-8"))[1]
    plugin = json.loads((ROOT / "plugins/agentdetox/.claude-plugin/plugin.json").read_text(encoding="utf-8"))["version"]
    pinned = re.search(r"^VERSION=(\S+)$", (ROOT / "plugins/agentdetox/scripts/hook").read_text(encoding="utf-8"), re.M)[1]
    changelog = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    problems = []
    if tag != f"v{version}":
        problems.append(f"tag {tag} does not match the package version {version}")
    if plugin != version:
        problems.append(f"the plugin manifest says {plugin}")
    if pinned != version:
        problems.append(f"the plugin's hook script pins {pinned}")
    if not re.search(rf"^## \[{re.escape(version)}\] - \d{{4}}-\d{{2}}-\d{{2}}$", changelog, re.M):
        problems.append(f"CHANGELOG.md has no dated entry for {version}")
    for problem in problems:
        print(problem, file=sys.stderr)
    if not problems:
        print(f"release {tag}: versions agree and the changelog entry is dated")
    return 1 if problems else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1]))
