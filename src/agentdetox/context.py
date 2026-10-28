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


def claude_dir(home: Path | None = None) -> Path:
    """Where Claude Code keeps user settings, memory and skills. CLAUDE_CONFIG_DIR moves
    ~/.claude and ~/.claude.json there together."""
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured).expanduser() if configured else (home or home_dir()) / ".claude"


def short_path(source: str) -> str:
    home = str(home_dir())
    return "~" + source[len(home):] if source.startswith(home) else source


def _globs(profile: AgentProfile, home: Path, project: Path | None):
    for kind, pattern in profile.user:
        root = home
        if os.environ.get("CLAUDE_CONFIG_DIR") and (pattern.startswith(".claude/") or pattern == ".claude.json"):
            root, pattern = claude_dir(home), pattern.removeprefix(".claude/")
        yield "user", root, kind, pattern
    if project is not None:
        for kind, pattern in profile.project:
            yield "project", project, kind, pattern


def discover(agents: list[str] | None = None, project: Path | None = None, home: Path | None = None) -> list[ContextFile]:
    home = home or home_dir()
    found: dict[Path, ContextFile] = {}
    for name in agents or list(PROFILES):
        profile = PROFILES[name]
        for scope, root, kind, pattern in _globs(profile, home, project):
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
        for scope, root, kind, pattern in _globs(profile, home, project):
            try:
                rel = path.relative_to(Path(os.path.abspath(root))).as_posix()
            except ValueError:
                continue
            if _glob_regex(pattern).fullmatch(rel):
                return ContextFile(profile.name, kind, scope, path)
    return None


_SLUG_MAX = 200


def claude_memory_dir(project: Path, home: Path | None = None) -> Path:
    # Claude Code names a project's dir after its path with every non-alphanumeric
    # UTF-16 unit replaced by "-"; names over 200 characters are cut to 200 and given
    # "-" plus the base-36 absolute value of the path's Java-style string hash.
    data = str(project).encode("utf-16-le")
    units = [int.from_bytes(data[i:i + 2], "little") for i in range(0, len(data), 2)]
    slug = "".join(chr(u) if chr(u).isascii() and chr(u).isalnum() else "-" for u in units)
    if len(slug) > _SLUG_MAX:
        slug = f"{slug[:_SLUG_MAX]}-{_base36(abs(_java_hash(units)))}"
    return claude_dir(home) / "projects" / slug / "memory"


def _java_hash(units) -> int:
    h = 0
    for u in units:
        h = (h * 31 + u) & 0xFFFFFFFF
    return h - (1 << 32) if h >= 1 << 31 else h


def _base36(n: int) -> str:
    digits = ""
    while True:
        n, r = divmod(n, 36)
        digits = "0123456789abcdefghijklmnopqrstuvwxyz"[r] + digits
        if not n:
            return digits


def related_files(cf: ContextFile, project: Path | None, home: Path | None = None) -> list[Path]:
    """Memory and instruction files that describe the same world as `cf`.

    Claude Code keeps one memory dir per project, and project A using pnpm does not
    contradict project B using npm, so other projects' memory dirs are left out."""
    home = home or home_dir()
    projects_root = claude_dir(home) / "projects"
    own_dir = cf.path.parent if _is_under(cf.path, projects_root) else (claude_memory_dir(project, home) if project else None)
    out = []
    for f in discover(project=project, home=home):
        if f.kind not in ("memory", "instructions") or f.path == cf.path:
            continue
        if _is_under(f.path, projects_root) and f.path.parent != own_dir:
            continue
        out.append(f.path)
    return out


def _is_under(path: Path, root: Path) -> bool:
    try:
        path.relative_to(root)
        return True
    except ValueError:
        return False


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
