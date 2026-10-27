"""Discovery of the persistent context an agent reloads: memory, instructions, skills, config."""

from __future__ import annotations

import glob
import os
from dataclasses import dataclass
from pathlib import Path

KINDS = ("memory", "instructions", "skill", "config")


@dataclass(frozen=True)
class ContextFile:
    agent: str
    kind: str
    scope: str  # "user" or "project"
    path: Path


@dataclass(frozen=True)
class AgentProfile:
    name: str
    # (kind, glob) pairs; user globs are relative to $HOME, project globs to the project root.
    user: tuple[tuple[str, str], ...]
    project: tuple[tuple[str, str], ...]


CLAUDE_CODE = AgentProfile(
    name="claude-code",
    user=(
        ("instructions", ".claude/CLAUDE.md"),
        ("memory", ".claude/projects/*/memory/*.md"),
        ("skill", ".claude/skills/**/SKILL.md"),
        ("instructions", ".claude/agents/*.md"),
        ("instructions", ".claude/commands/**/*.md"),
        ("config", ".claude/settings.json"),
        ("config", ".claude.json"),
    ),
    project=(
        ("instructions", "CLAUDE.md"),
        ("instructions", "CLAUDE.local.md"),
        ("instructions", ".claude/CLAUDE.md"),
        ("skill", ".claude/skills/**/SKILL.md"),
        ("instructions", ".claude/agents/*.md"),
        ("instructions", ".claude/commands/**/*.md"),
        ("config", ".claude/settings.json"),
        ("config", ".claude/settings.local.json"),
        ("config", ".mcp.json"),
    ),
)

PROFILES: dict[str, AgentProfile] = {p.name: p for p in (CLAUDE_CODE,)}


def home_dir() -> Path:
    return Path(os.environ.get("AGENTDETOX_USER_HOME") or Path.home())


def discover(agents: list[str] | None = None, project: Path | None = None, home: Path | None = None) -> list[ContextFile]:
    home = home or home_dir()
    found: dict[Path, ContextFile] = {}
    for name in agents or list(PROFILES):
        profile = PROFILES[name]
        roots = [("user", home, profile.user)]
        if project is not None:
            roots.append(("project", project, profile.project))
        for scope, root, patterns in roots:
            for kind, pattern in patterns:
                for p in sorted(glob.glob(str(root / pattern), recursive=True)):
                    path = Path(p)
                    if path.is_file() and path not in found:
                        found[path] = ContextFile(profile.name, kind, scope, path)
    return list(found.values())
