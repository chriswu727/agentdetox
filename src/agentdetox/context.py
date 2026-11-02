"""Discovery of the persistent context an agent reloads: memory, instructions, skills, config."""

from __future__ import annotations

import fnmatch
import glob
import os
import re
import sys
from dataclasses import dataclass
from functools import lru_cache
from pathlib import Path

from .findings import printable

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
    # File names the agent also loads from every folder above the project.
    ancestors: tuple[tuple[str, str], ...] = ()
    # Project globs checked when the agent writes, but too costly to walk at session start
    # (the agent loads a CLAUDE.md in any subfolder it works in).
    written: tuple[tuple[str, str], ...] = ()


CLAUDE_CODE = AgentProfile(
    name="claude-code",
    user=(
        ("instructions", ".claude/CLAUDE.md"),
        ("instructions", ".claude/rules/**/*.md"),
        ("memory", ".claude/projects/*/memory/*.md"),
        ("skill", ".claude/skills/**/SKILL.md"),
        ("instructions", ".claude/agents/*.md"),
        ("instructions", ".claude/commands/**/*.md"),
        ("instructions", ".claude/output-styles/*.md"),
        ("config", ".claude/settings.json"),
        ("config", ".claude.json"),
        ("config", ".claude/hooks/**/*"),
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
        ("instructions", ".claude/output-styles/*.md"),
        ("config", ".claude/settings.json"),
        ("config", ".claude/settings.local.json"),
        ("config", ".mcp.json"),
        ("config", ".claude/hooks/**/*"),
    ),
    ancestors=(("instructions", "CLAUDE.md"), ("instructions", "CLAUDE.local.md")),
    written=(("instructions", "**/CLAUDE.md"), ("instructions", "**/CLAUDE.local.md")),
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
    ancestors=(("instructions", "AGENTS.md"), ("instructions", "AGENTS.override.md")),
    written=(("instructions", "**/AGENTS.md"), ("instructions", "**/AGENTS.override.md")),
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
    return printable("~" + source[len(home):] if source.startswith(home) else source)


def display_path(path: str) -> str:
    """short_path for lists. Claude Code names memory folders after the whole project path;
    their ends, where the project's own name is, are kept."""
    return os.sep.join(p if len(p) <= 40 else "…" + p[-28:] for p in short_path(path).split(os.sep))


# macOS and Windows file systems ignore case by default: writing claude.md replaces CLAUDE.md.
CASELESS = sys.platform in ("darwin", "win32")


def _globs(profile: AgentProfile, home: Path, project: Path | None, writes: bool = False):
    for kind, pattern in profile.user:
        root = home
        if os.environ.get("CLAUDE_CONFIG_DIR") and (pattern.startswith(".claude/") or pattern == ".claude.json"):
            root, pattern = claude_dir(home), pattern.removeprefix(".claude/")
        yield "user", root, kind, pattern
    if project is not None:
        for kind, pattern in profile.project + (profile.written if writes else ()):
            yield "project", project, kind, pattern
        for parent in Path(os.path.abspath(project)).parents:
            for kind, name in profile.ancestors:
                yield "project", parent, kind, name


_SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
                    ".lua", ".ps1", ".bat", ".cmd"}


def _counts(pattern: str, path: Path) -> bool:
    """Whether a file matching `pattern` is context. In a hooks folder only what can run
    counts; the logs and state a hook keeps beside itself change all the time."""
    if not pattern.endswith("hooks/**/*") or path.suffix.lower() in _SCRIPT_SUFFIXES:
        return True
    try:
        with path.open("rb") as file:
            # Windows reports every file as executable.
            return file.read(2) == b"#!" or (os.name != "nt" and os.access(path, os.X_OK))
    except FileNotFoundError:
        return not path.suffix  # a file not written yet, named like an executable
    except OSError:
        return True


def discover(agents: list[str] | None = None, project: Path | None = None, home: Path | None = None) -> list[ContextFile]:
    home = home or home_dir()
    found: dict[Path, ContextFile] = {}
    for name in agents or list(PROFILES):
        profile = PROFILES[name]
        for scope, root, kind, pattern in _globs(profile, home, project):
            for p in sorted(glob.glob(str(root / pattern), recursive=True, include_hidden=True)):
                path = Path(p)
                if path.is_file() and path not in found and _counts(pattern, path):
                    found[path] = ContextFile(profile.name, kind, scope, path)
    return list(found.values())


def discover_session(project: Path, agent: str) -> list[ContextFile]:
    home = home_dir()
    found: dict[Path, ContextFile] = {}
    for scope, root, kind, pattern in _globs(PROFILES[agent], home, project):
        if pattern in ('.claude/projects/*/memory/*.md', 'projects/*/memory/*.md'):
            root, pattern = claude_memory_dir(project, home), '*.md'
        for value in sorted(glob.glob(str(root / pattern), recursive=True, include_hidden=True)):
            path = Path(value)
            if path.is_file() and not path.is_symlink() and _counts(pattern, path):
                found.setdefault(path, ContextFile(agent, kind, scope, path))
    return list(found.values())


def classify(path: Path, agents: list[str] | None = None, project: Path | None = None,
             home: Path | None = None) -> ContextFile | None:
    """Return the ContextFile `path` would be, whether or not it exists yet. A path is
    matched as written and, failing that, as its real location, so a write through a
    symlink counts. The file is named under `root` as given, as `discover` names it, so
    its snapshot and history stay under one name."""
    home = home or home_dir()
    written = Path(os.path.abspath(path))
    real = Path(os.path.realpath(path))
    for candidate in dict.fromkeys((written, real)):
        for name in agents or list(PROFILES):
            profile = PROFILES[name]
            for scope, root, kind, pattern in _globs(profile, home, project, writes=True):
                given = Path(os.path.abspath(root))
                for base in dict.fromkeys((given, Path(os.path.realpath(root)))):
                    rel = _relative(candidate, base)
                    if rel is not None and _glob_regex(pattern, CASELESS).fullmatch(rel) and _counts(pattern, candidate):
                        return ContextFile(profile.name, kind, scope, given / rel if rel else given)
    return None


def named_like_context(rel: str) -> bool:
    """Whether `rel`, a path relative to a folder that cannot be known in advance, could be
    a file the agent loads: its name, and any folders given, match the end of a watched
    pattern with a fixed file name (CLAUDE.md, settings.json, .mcp.json, …)."""
    parts = [p for p in rel.replace("\\", "/").split("/") if p not in ("", ".")]
    if not parts:
        return False
    for profile in PROFILES.values():
        for _, pattern in profile.user + profile.project + profile.written + profile.ancestors:
            pieces = pattern.split("/")
            if not any(c in pieces[-1] for c in "*?[") and _ends_with(pieces, parts):
                return True
    return False


def _ends_with(pattern: list[str], parts: list[str]) -> bool:
    i, j = len(pattern) - 1, len(parts) - 1
    while i >= 0 and j >= 0:
        if pattern[i] == "**":
            return True
        name, glob_ = (parts[j].lower(), pattern[i].lower()) if CASELESS else (parts[j], pattern[i])
        if parts[j] != ".." and not fnmatch.fnmatchcase(name, glob_):
            return False
        i, j = i - 1, j - 1
    return True


def _relative(path: Path, root: Path) -> str | None:
    """`path` relative to `root`, in `path`'s own spelling; ignoring case where the file
    system does."""
    parts, base = path.parts, root.parts
    if len(parts) < len(base):
        return None
    head = parts[:len(base)]
    if (tuple(p.lower() for p in head) != tuple(p.lower() for p in base)) if CASELESS else head != base:
        return None
    return "/".join(parts[len(base):])


_SLUG_MAX = 200


def claude_memory_dir(project: Path, home: Path | None = None) -> Path:
    # Claude Code names a project's dir after its path with every non-alphanumeric
    # UTF-16 unit replaced by "-"; names over 200 characters are cut to 200 and given
    # "-" plus the base-36 absolute value of the path's Java-style string hash. The path is
    # the physical one Claude Code runs in (macOS's /var is /private/var).
    data = os.path.realpath(project).encode("utf-16-le")
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
def _glob_regex(pattern: str, caseless: bool = False) -> re.Pattern:
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
    return re.compile(out, re.IGNORECASE if caseless else 0)
