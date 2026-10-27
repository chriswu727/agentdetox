"""Discovery of the persistent context an agent reloads: memory, instructions, skills, config."""

from __future__ import annotations

import glob
import os
import re
from dataclasses import dataclass
from functools import lru_cache
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
    verified: bool = True


CLAUDE_CODE = AgentProfile(
    name="claude-code",
    user=(
        ("instructions", ".claude/CLAUDE.md"),
        ("instructions", ".claude/rules/**/*.md"),
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
        ("instructions", ".claude/rules/**/*.md"),
        ("instructions", "AGENTS.md"),
        ("skill", ".claude/skills/**/SKILL.md"),
        ("instructions", ".claude/agents/*.md"),
        ("instructions", ".claude/commands/**/*.md"),
        ("config", ".claude/settings.json"),
        ("config", ".claude/settings.local.json"),
        ("config", ".mcp.json"),
    ),
)

CODEX = AgentProfile(
    name="codex",
    user=(
        ("instructions", ".codex/AGENTS.md"),
        ("instructions", ".codex/AGENTS.override.md"),
        ("memory", ".codex/memories/**/*.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("config", ".codex/config.toml"),
        ("config", ".codex/hooks.json"),
        # Approved-command allowlist; Codex appends to it when the user approves a command.
        ("config", ".codex/rules/*.rules"),
    ),
    project=(
        ("instructions", "AGENTS.md"),
        ("instructions", "AGENTS.override.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("config", ".codex/config.toml"),
        ("config", ".codex/hooks.json"),
        ("config", ".codex/rules/*.rules"),
    ),
)

CURSOR = AgentProfile(
    name="cursor",
    user=(
        ("config", ".cursor/mcp.json"),
        ("config", ".cursor/hooks.json"),
    ),
    project=(
        ("instructions", ".cursor/rules/**/*.mdc"),
        ("instructions", ".cursor/rules/**/*.md"),
        ("instructions", ".cursorrules"),
        ("instructions", "AGENTS.md"),
        ("skill", ".cursor/skills/**/SKILL.md"),
        ("config", ".cursor/mcp.json"),
        ("config", ".cursor/hooks.json"),
    ),
)

# OpenClaw profiles live in ~/.openclaw-<profile>/, hence the wildcard.
OPENCLAW = AgentProfile(
    name="openclaw",
    user=(
        ("instructions", ".openclaw*/workspace/AGENTS.md"),
        ("instructions", ".openclaw*/workspace/SOUL.md"),
        ("instructions", ".openclaw*/workspace/USER.md"),
        ("instructions", ".openclaw*/workspace/IDENTITY.md"),
        ("instructions", ".openclaw*/workspace/BOOT.md"),
        ("instructions", ".openclaw*/workspace/BOOTSTRAP.md"),
        ("memory", ".openclaw*/workspace/MEMORY.md"),
        ("memory", ".openclaw*/workspace/memory/*.md"),
        ("skill", ".openclaw*/workspace/skills/**/SKILL.md"),
        ("skill", ".openclaw*/workspace/.agents/skills/**/SKILL.md"),
        ("skill", ".openclaw*/skills/**/SKILL.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("config", ".openclaw*/openclaw.json"),
        ("config", ".openclaw*/workspace/.openclaw/extensions/**/openclaw.plugin.json"),
    ),
    project=(),
)

# WorkBuddy publishes no file layout; these paths come from a third-party write-up
# (woshipm, 2026-08-07) and need checking against a real install.
WORKBUDDY = AgentProfile(
    name="workbuddy",
    user=(
        ("memory", ".workbuddy/MEMORY.md"),
        ("memory", ".workbuddy/memory/*.md"),
        ("instructions", ".workbuddy/AGENTS.md"),
        ("instructions", ".workbuddy/IDENTITY.md"),
        ("instructions", ".workbuddy/USER.md"),
        ("instructions", ".workbuddy/SOUL.md"),
    ),
    project=(
        ("memory", ".workbuddy/memory/*.md"),
    ),
    verified=False,
)

PROFILES: dict[str, AgentProfile] = {p.name: p for p in (CLAUDE_CODE, CODEX, CURSOR, OPENCLAW, WORKBUDDY)}


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
                for p in sorted(glob.glob(str(root / pattern), recursive=True, include_hidden=True)):
                    path = Path(p)
                    if path.is_file() and path not in found:
                        found[path] = ContextFile(profile.name, kind, scope, path)
    return list(found.values())


def classify(path: Path, agents: list[str] | None = None, project: Path | None = None,
             home: Path | None = None) -> ContextFile | None:
    """Return the ContextFile `path` would be, whether or not it exists yet."""
    home = home or home_dir()
    path = Path(os.path.abspath(path))
    for name in agents or list(PROFILES):
        profile = PROFILES[name]
        roots = [("user", home, profile.user)] + ([("project", project, profile.project)] if project else [])
        for scope, root, patterns in roots:
            try:
                rel = path.relative_to(Path(os.path.abspath(root))).as_posix()
            except ValueError:
                continue
            for kind, pattern in patterns:
                if _glob_regex(pattern).fullmatch(rel):
                    return ContextFile(profile.name, kind, scope, path)
    return None


@lru_cache(maxsize=None)
def _glob_regex(pattern: str) -> re.Pattern:
    out, i = "", 0
    while i < len(pattern):
        if pattern.startswith("**/", i):
            out += "(?:[^/]+/)*"
            i += 3
        elif pattern[i] == "*":
            out += "[^/]*"
            i += 1
        elif pattern[i] == "?":
            out += "[^/]"
            i += 1
        else:
            out += re.escape(pattern[i])
            i += 1
    return re.compile(out)
