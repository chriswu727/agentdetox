"""Discovery of the persistent context an agent reloads: memory, instructions, skills, config.

Each client keeps these files somewhere different and lets the user move them. The profiles
below name the files; the functions after them resolve where a client's folders are on
this machine (CLAUDE_CONFIG_DIR, CODEX_HOME, OpenClaw's state folder and configured
workspaces). A folder that was asked for and cannot be resolved is reported by `survey`,
never passed over: no file found must not read as nothing wrong.
"""

from __future__ import annotations

import fnmatch
import glob
import json
import os
import re
import sys
from collections.abc import Iterator
from dataclasses import dataclass, field
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
    # (the agent loads a CLAUDE.md in any subfolder it works in). `survey` finds them with a
    # bounded walk.
    written: tuple[tuple[str, str], ...] = ()
    # Project globs the agent also loads from every folder between the repository root and
    # the folder it was started in.
    layered: tuple[tuple[str, str], ...] = ()
    # What of this client's persistent context no file check here reaches.
    limits: tuple[str, ...] = ()


CLAUDE_CODE = AgentProfile(
    name="claude-code",
    user=(
        ("instructions", ".claude/CLAUDE.md"),
        ("instructions", ".claude/rules/**/*.md"),
        ("memory", ".claude/projects/*/memory/*.md"),
        ("memory", ".claude/agent-memory/**/*.md"),
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
        ("memory", ".claude/agent-memory/**/*.md"),
        ("memory", ".claude/agent-memory-local/**/*.md"),
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
    limits=(
        "files a CLAUDE.md or AGENTS.md pulls in with @path imports are not followed",
        "auto memory moved with the autoMemoryDirectory setting is not covered",
        "managed policy files outside the home folder are not covered",
    ),
)

CODEX = AgentProfile(
    name="codex",
    user=(
        ("instructions", ".codex/AGENTS.md"),
        ("instructions", ".codex/AGENTS.override.md"),
        ("memory", ".codex/memories/**/*.md"),
        ("memory", ".codex/memories_v2/**/*.md"),
        ("skill", ".codex/skills/**/SKILL.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("config", ".codex/config.toml"),
        # Profiles chosen with --profile <name>.
        ("config", ".codex/*.config.toml"),
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
    written=(
        ("instructions", "**/AGENTS.md"),
        ("instructions", "**/AGENTS.override.md"),
        ("skill", "**/.agents/skills/**/SKILL.md"),
        ("config", "**/.codex/config.toml"),
        ("config", "**/.codex/hooks.json"),
        ("config", "**/.codex/rules/*.rules"),
    ),
    layered=(
        ("instructions", "AGENTS.md"),
        ("instructions", "AGENTS.override.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("config", ".codex/config.toml"),
        ("config", ".codex/hooks.json"),
        ("config", ".codex/rules/*.rules"),
    ),
    limits=(
        "only text files under memories/ and memories_v2/ are read; Codex's SQLite and generated memory "
        "state, and how Codex regenerates memory, are not inspected",
        "project_root_markers and project_doc_fallback_filenames from config.toml are not applied",
        "system and managed layers (/etc/codex, requirements.toml) are not covered",
    ),
)

CURSOR = AgentProfile(
    name="cursor",
    user=(
        ("config", ".cursor/mcp.json"),
        ("config", ".cursor/hooks.json"),
        # Cursor CLI permission lists.
        ("config", ".cursor/cli-config.json"),
        ("skill", ".cursor/skills/**/SKILL.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        # Loaded by Cursor for compatibility with Claude Code and Codex.
        ("skill", ".claude/skills/**/SKILL.md"),
        ("skill", ".codex/skills/**/SKILL.md"),
    ),
    project=(
        ("instructions", ".cursor/rules/**/*.mdc"),
        ("instructions", ".cursor/rules/**/*.md"),
        ("instructions", ".cursorrules"),
        ("instructions", "AGENTS.md"),
        ("skill", ".cursor/skills/**/SKILL.md"),
        ("skill", ".agents/skills/**/SKILL.md"),
        ("skill", ".claude/skills/**/SKILL.md"),
        ("skill", ".codex/skills/**/SKILL.md"),
        ("config", ".cursor/mcp.json"),
        ("config", ".cursor/hooks.json"),
        ("config", ".cursor/cli.json"),
    ),
    written=(
        ("instructions", "**/.cursor/rules/**/*.mdc"),
        ("instructions", "**/AGENTS.md"),
        ("skill", "**/.cursor/skills/**/SKILL.md"),
        ("skill", "**/.agents/skills/**/SKILL.md"),
    ),
    limits=(
        "User Rules and Team Rules are kept by Cursor, not in files, and are not covered",
        "edits made by Tab completion are not checked",
    ),
)

# What OpenClaw loads from an agent's workspace, and from its state folder.
_OPENCLAW_WORKSPACE = (
    ("instructions", "AGENTS.md"),
    ("instructions", "SOUL.md"),
    ("instructions", "USER.md"),
    ("instructions", "IDENTITY.md"),
    ("instructions", "BOOT.md"),
    ("instructions", "BOOTSTRAP.md"),
    ("memory", "MEMORY.md"),
    ("memory", "memory/*.md"),
    ("skill", "skills/**/SKILL.md"),
    ("skill", ".agents/skills/**/SKILL.md"),
    ("config", ".openclaw/extensions/**/openclaw.plugin.json"),
)
_OPENCLAW_STATE = (
    ("skill", "skills/**/SKILL.md"),
    ("config", "openclaw.json"),
    # The Codex home OpenClaw keeps for each agent it runs through Codex.
    ("instructions", "agents/*/agent/codex-home/AGENTS.md"),
    ("instructions", "agents/*/agent/codex-home/AGENTS.override.md"),
    ("skill", "agents/*/agent/codex-home/skills/**/SKILL.md"),
    ("config", "agents/*/agent/codex-home/config.toml"),
)

# State folders are ~/.openclaw and, for a named profile, ~/.openclaw-<profile>; an agent's
# workspace is workspace/ inside one, or workspace-<agent id>/ when several agents share it.
OPENCLAW = AgentProfile(
    name="openclaw",
    user=(
        *((kind, f".openclaw*/{folder}/{pattern}") for folder in ("workspace", "workspace-*")
          for kind, pattern in _OPENCLAW_WORKSPACE),
        *((kind, f".openclaw*/{pattern}") for kind, pattern in _OPENCLAW_STATE),
        ("skill", ".agents/skills/**/SKILL.md"),
    ),
    project=(),
    limits=(
        "there is no OpenClaw hook: files are inspected only when an AgentDetox command or another "
        "client's session runs",
        "session, memory-index and standing-intent state in OpenClaw's SQLite databases is not inspected",
        "sandbox workspaces under sandboxes/ and files named by $include in openclaw.json are not covered",
    ),
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
    limits=(
        "these paths are unverified guesses from a third-party write-up, not a supported integration",
    ),
)

PROFILES: dict[str, AgentProfile] = {p.name: p for p in (CLAUDE_CODE, CODEX, CURSOR, OPENCLAW, WORKBUDDY)}


def home_dir() -> Path:
    return Path(os.environ.get("AGENTDETOX_USER_HOME") or Path.home())


def claude_dir(home: Path | None = None) -> Path:
    """Where Claude Code keeps user settings, memory and skills. CLAUDE_CONFIG_DIR moves
    ~/.claude and ~/.claude.json there together."""
    configured = os.environ.get("CLAUDE_CONFIG_DIR")
    return Path(configured).expanduser() if configured else (home or home_dir()) / ".claude"


def codex_dir(home: Path | None = None) -> Path:
    """Where Codex keeps its config, hooks, rules, skills and memory files. CODEX_HOME moves
    all of them."""
    configured = os.environ.get("CODEX_HOME")
    return Path(os.path.abspath(Path(configured).expanduser())) if configured else (home or home_dir()) / ".codex"


def short_path(source: str) -> str:
    home = str(home_dir())
    return printable("~" + source[len(home):] if source.startswith(home) else source)


def display_path(path: str) -> str:
    """short_path for lists. Claude Code names memory folders after the whole project path;
    their ends, where the project's own name is, are kept."""
    return os.sep.join(p if len(p) <= 40 else "…" + p[-28:] for p in short_path(path).split(os.sep))


# macOS and Windows file systems ignore case by default: writing claude.md replaces CLAUDE.md.
CASELESS = sys.platform in ("darwin", "win32")


@dataclass
class OpenClawLayout:
    """Where OpenClaw's state folders, config files and agent workspaces are."""
    states: list[tuple[Path, str]] = field(default_factory=list)       # (folder, why it is one)
    workspaces: list[tuple[Path, str]] = field(default_factory=list)
    configs: list[Path] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


_OPENCLAW_ENV = ("OPENCLAW_HOME", "OPENCLAW_PROFILE", "OPENCLAW_STATE_DIR", "OPENCLAW_CONFIG_PATH",
                 "OPENCLAW_WORKSPACE_DIR")
_ENV_REFERENCE = re.compile(r"\$\{([A-Za-z_][A-Za-z0-9_]*)\}")
# What each config text says, so one process parses each version of a config file once.
_parsed: dict[str, tuple[object, str]] = {}


def openclaw_layout(home: Path | None = None, *, configured: bool = True) -> OpenClawLayout:
    """OpenClaw's folders as its documentation resolves them: OPENCLAW_HOME replaces the
    home folder, a named profile uses ~/.openclaw-<profile>, OPENCLAW_STATE_DIR and
    OPENCLAW_CONFIG_PATH name the state folder and config file outright, and a workspace
    is OPENCLAW_WORKSPACE_DIR, the one openclaw.json configures, or workspace/ in the state
    folder. Every candidate is returned, not only the one that would win: the Gateway's
    environment is not necessarily this process's, and looking at one folder too many costs
    nothing. Without `configured`, the config files are located but not read."""
    home = home or home_dir()
    env = tuple(os.environ.get(name, "") for name in _OPENCLAW_ENV)
    base = _openclaw_home(home, env[0])
    states = _layout_states(list(dict.fromkeys((home, base))), base, env)
    configs = [folder / "openclaw.json" for folder, _ in states]
    if env[3]:
        configs.append(Path(os.path.abspath(_expand_home(env[3], base))))
    return _openclaw_layout(base, env, states, list(dict.fromkeys(configs)), configured)


def _openclaw_home(home: Path, configured: str) -> Path:
    value = configured.strip()
    if value in ("", "undefined", "null"):
        return home
    if value == "~" or value.startswith(("~/", "~\\")):
        return Path(os.path.abspath(home / value[2:]))
    return Path(os.path.abspath(value))


def _layout_states(homes: list[Path], base: Path, env: tuple[str, ...]) -> list[tuple[Path, str]]:
    states: dict[Path, str] = {}
    for folder in homes:
        try:
            with os.scandir(folder) as found:
                names = sorted(e.name for e in found if e.name == ".openclaw" or e.name.startswith(".openclaw-"))
        except OSError:
            names = []
        for name in names:
            if (folder / name).is_dir():
                states.setdefault(folder / name, "default location")
    if env[1] and env[1] != "default":
        states.setdefault(base / f".openclaw-{env[1]}", "OPENCLAW_PROFILE")
    if env[2]:
        states.setdefault(Path(os.path.abspath(_expand_home(env[2], base))), "OPENCLAW_STATE_DIR")
    return list(states.items())


def _expand_home(value: str, base: Path) -> Path:
    if value == "~" or value.startswith(("~/", "~\\")):
        return base / value[2:]
    return Path(value)


def _openclaw_layout(base: Path, env: tuple[str, ...], states: list[tuple[Path, str]],
                     configs: list[Path], configured: bool) -> OpenClawLayout:
    layout = OpenClawLayout(states=list(states), configs=[c for c in configs if c.is_file()])
    for folder, why in states:
        if why != "default location" and not folder.is_dir():
            layout.problems.append(f"{why} names {folder}, which does not exist")
    if env[3] and configs[-1] not in layout.configs:
        layout.problems.append(f"OPENCLAW_CONFIG_PATH names {configs[-1]}, which does not exist")
    workspaces: dict[Path, str] = {}
    if env[4]:
        # OpenClaw passes this one straight to path.resolve: a leading ~ is not expanded.
        folder = Path(os.path.abspath(env[4]))
        workspaces[folder] = "OPENCLAW_WORKSPACE_DIR"
        if not folder.is_dir():
            layout.problems.append(f"OPENCLAW_WORKSPACE_DIR names {folder}, which does not exist")
    for folder, why in states:
        if why != "default location":
            workspaces.setdefault(folder / "workspace", f"the default workspace of {why}")
    for config in layout.configs if configured else ():
        for folder, why in _configured_workspaces(config, config.parent, base, layout.problems):
            if not folder.is_dir():
                layout.problems.append(f"{config} sets {why} to {folder}, which does not exist")
            workspaces.setdefault(folder, why)
    layout.workspaces = list(workspaces.items())
    return layout


def load_json5(text: str):
    """JSON, or the JSON5 that OpenClaw's config is documented in (comments, unquoted keys,
    trailing commas). The JSON5 parser is loaded only for a file that is not plain JSON."""
    try:
        return json.loads(text)
    except ValueError:
        import json5

        return json5.loads(text)


# An OpenClaw config is written by hand; one larger than this is not parsed, and says so.
CONFIG_BYTES = 262_144


def is_openclaw_config(path: Path) -> bool:
    """Whether `path` is an OpenClaw config file, which may be JSON5 whatever it is called."""
    if path.name == "openclaw.json":
        return True
    configured = os.environ.get("OPENCLAW_CONFIG_PATH")
    return bool(configured) and os.path.abspath(path) == os.path.abspath(Path(configured or "").expanduser())


def _read_config(config: Path) -> tuple[object, str]:
    """(what the config says about workspaces, "") or (None, why it could not be read). The
    file is read every time (a size and a modification time can both be kept across a
    rewrite) and parsed once per content in a process; nothing is kept on disk."""
    try:
        with config.open("rb") as file:
            data = file.read(CONFIG_BYTES + 1)
    except OSError as error:
        return None, f"{type(error).__name__}: {printable(str(error))[:120]}"
    if len(data) > CONFIG_BYTES:
        return None, f"it is larger than {CONFIG_BYTES // 1024} KB"
    try:
        text = data.decode("utf-8")
    except ValueError as error:
        return None, f"{type(error).__name__}: {printable(str(error))[:120]}"
    if text not in _parsed:
        if len(_parsed) > 16:
            _parsed.clear()
        try:
            _parsed[text] = _agents_of(load_json5(text)), ""
        except (ValueError, RecursionError) as error:
            _parsed[text] = None, f"{type(error).__name__}: {printable(str(error))[:120]}"
    return _parsed[text]


def _agents_of(data) -> dict | None:
    """The part of a config that names workspaces, which is all that is kept of it."""
    if not isinstance(data, dict):
        return None
    agents = data.get("agents")
    kept: dict = {"$include": "$include" in data or isinstance(agents, dict) and "$include" in agents}
    if isinstance(agents, dict):
        defaults, entries = agents.get("defaults"), agents.get("entries")
        kept["defaults"] = defaults.get("workspace") if isinstance(defaults, dict) else None
        kept["entries"] = {str(name): entry.get("workspace") if isinstance(entry, dict) else None
                           for name, entry in entries.items()} if isinstance(entries, dict) else {}
    return kept


def _configured_workspaces(config: Path, state: Path, base: Path, problems: list[str]) -> list[tuple[Path, str]]:
    """The workspaces one openclaw.json names: agents.defaults.workspace, each
    agents.entries.<id>.workspace, and for an entry without one, <default>/<id> or the state
    folder's workspace-<id>."""
    data, error = _read_config(config)
    if error:
        problems.append(f"{config} could not be read as JSON or JSON5 ({error}); the workspaces it configures "
                        "were not resolved")
        return []
    if not isinstance(data, dict):
        return []
    if data.get("$include"):
        problems.append(f"{config} takes settings from $include files, which are not followed; workspaces "
                        "configured there were not resolved")
    found: list[tuple[Path, str]] = []

    def resolve(value, what: str) -> Path | None:
        if not isinstance(value, str) or not value.strip():
            return None
        missing = [name for name in _ENV_REFERENCE.findall(value) if not os.environ.get(name)]
        if missing:
            problems.append(f"{config} sets {what} to {printable(value)}, which uses ${{{missing[0]}}}; that "
                            "variable is not set here, so the folder was not resolved")
            return None
        expanded = _expand_home(_ENV_REFERENCE.sub(lambda m: os.environ[m.group(1)], value), base)
        if not expanded.is_absolute():
            problems.append(f"{config} sets {what} to the relative path {printable(value)}, which was not resolved")
            return None
        return Path(os.path.abspath(expanded))

    shared = resolve(data.get("defaults"), "agents.defaults.workspace")
    if shared is not None:
        found.append((shared, "agents.defaults.workspace"))
    for name, workspace in (data.get("entries") or {}).items():
        own = resolve(workspace, f"agents.entries.{name}.workspace")
        if own is not None:
            found.append((own, f"agents.entries.{name}.workspace"))
        elif name and os.sep not in name and "/" not in name and name not in (".", ".."):
            # Reported only when present: a single agent uses the shared workspace itself.
            for folder in ((shared / name,) if shared is not None else ()) + (state / f"workspace-{name}",):
                if folder.is_dir():
                    found.append((folder, f"the workspace of agent {name}"))
    return found


def cursor_cli_configs(home: Path) -> list[tuple[Path, str]]:
    """Cursor CLI's global config besides ~/.cursor/cli-config.json: CURSOR_CONFIG_DIR names
    its folder, and on Linux and BSD so does XDG_CONFIG_HOME."""
    found = []
    if os.environ.get("CURSOR_CONFIG_DIR"):
        found.append((Path(os.path.abspath(Path(os.environ["CURSOR_CONFIG_DIR"]).expanduser())), "CURSOR_CONFIG_DIR"))
    if os.environ.get("XDG_CONFIG_HOME") and sys.platform not in ("darwin", "win32"):
        found.append((Path(os.path.abspath(Path(os.environ["XDG_CONFIG_HOME"]).expanduser())) / "cursor",
                      "XDG_CONFIG_HOME"))
    return found


def repository_root(folder: Path) -> Path | None:
    """The nearest folder at or above `folder` that holds a .git entry."""
    start = Path(os.path.abspath(folder))
    return next((f for f in (start, *start.parents) if os.path.lexists(f / ".git")), None)


def _workspace_name(path: Path) -> bool:
    """Whether `path` is named like a file OpenClaw loads from a workspace. One that is not
    cannot be in a configured workspace either, wherever that is, so the config that says
    where need not be parsed to classify it: most writes a hook sees are to such files."""
    name, parent = (path.name.lower(), path.parent.name.lower()) if CASELESS else (path.name, path.parent.name)
    for _, pattern in _OPENCLAW_WORKSPACE:
        parts = (pattern.lower() if CASELESS else pattern).split("/")
        if fnmatch.fnmatchcase(name, parts[-1]) and (len(parts) < 2 or parts[-2] in ("**", parent)):
            return True
    return False


def _user_entries(profile: AgentProfile, home: Path, candidate: Path | None = None) -> Iterator[tuple[Path, str, str]]:
    """(root, kind, glob) for a profile's user-level files, in the folders this machine's
    environment and configuration put them. `candidate` is the one path being classified,
    when there is one."""
    for kind, pattern in profile.user:
        root = home
        if os.environ.get("CLAUDE_CONFIG_DIR") and (pattern.startswith(".claude/") or pattern == ".claude.json"):
            root, pattern = claude_dir(home), pattern.removeprefix(".claude/")
        elif os.environ.get("CODEX_HOME") and pattern.startswith(".codex/"):
            root, pattern = codex_dir(home), pattern.removeprefix(".codex/")
        yield root, kind, pattern
    if profile.name == "cursor":
        for folder, _ in cursor_cli_configs(home):
            yield folder, "config", "cli-config.json"
    elif profile.name == "openclaw":
        layout = openclaw_layout(home, configured=candidate is None or _workspace_name(candidate))
        for folder, why in layout.states:
            if why != "default location" or folder.parent != home:   # not one the profile's own patterns reach
                for kind, pattern in _OPENCLAW_STATE:
                    yield folder, kind, pattern
                for kind, pattern in _OPENCLAW_WORKSPACE:
                    yield folder, kind, f"workspace/{pattern}"
                    yield folder, kind, f"workspace-*/{pattern}"
        for folder, _ in layout.workspaces:
            for kind, pattern in _OPENCLAW_WORKSPACE:
                yield folder, kind, pattern
        for config in layout.configs:
            yield config.parent, "config", config.name


def _globs(profile: AgentProfile, home: Path, project: Path | None, writes: bool = False, cwd: Path | None = None,
           candidate: Path | None = None):
    for root, kind, pattern in _user_entries(profile, home, candidate):
        yield "user", root, kind, pattern
    if project is not None:
        for kind, pattern in profile.project + (profile.written if writes else ()):
            yield "project", project, kind, pattern
        here = Path(os.path.abspath(project))
        if profile.layered:
            for folder in _layers(here, cwd):
                for kind, pattern in profile.layered:
                    yield "project", folder, kind, pattern
        for parent in here.parents:
            for kind, name in profile.ancestors:
                yield "project", parent, kind, name


def _layers(project: Path, cwd: Path | None) -> list[Path]:
    """The other folders whose layered files apply with `project`'s: those above it up to the
    repository root, and those below it down to the folder the session works in."""
    folders: list[Path] = []
    top = repository_root(project)
    if top is not None and top != project:
        for parent in project.parents:
            folders.append(parent)
            if parent == top:
                break
    if cwd is not None:
        below = Path(os.path.abspath(cwd))
        if below != project and _is_under(below, project):
            folders += [f for f in (below, *below.parents) if f != project and _is_under(f, project)]
    return folders


_SCRIPT_SUFFIXES = {".sh", ".bash", ".zsh", ".fish", ".py", ".js", ".mjs", ".cjs", ".ts", ".rb", ".pl", ".php",
                    ".lua", ".ps1", ".bat", ".cmd", ".exe"}
# What a package manager installs beside a hook. A hook that imports from one can be changed
# through it, as through any installed package; watching every file would bury real changes.
_DEPENDENCY_DIRS = {"node_modules", ".venv", "venv", "site-packages", "__pycache__", ".git"}


def _counts(pattern: str, path: Path) -> bool:
    """Whether a file matching `pattern` is context. In a hooks folder only what can run
    counts; the logs and state a hook keeps beside itself change all the time."""
    if not pattern.endswith("hooks/**/*"):
        return True
    hooks = _hooks_dir(path)
    if hooks and _DEPENDENCY_DIRS.intersection(path.relative_to(hooks).parts[:-1]):
        return False
    if path.suffix.lower() in _SCRIPT_SUFFIXES:
        return True
    try:
        with path.open("rb") as file:
            # Windows reports every file as executable.
            return file.read(2) == b"#!" or (os.name != "nt" and os.access(path, os.X_OK))
    except FileNotFoundError:
        return True  # not written yet: what it will hold, a shebang say, is not known here
    except OSError:
        return True


def watched_roots(project: Path | None) -> list[Path]:
    """The folders snapshots cover; a watched file deleted outside one goes unnoticed. A
    client folder moved out of the home folder is one of them."""
    home = home_dir()
    roots = [home] + ([project] if project else [])
    layout = openclaw_layout(home)
    moved = [claude_dir(), codex_dir(), *(folder for folder, _ in cursor_cli_configs(home)),
             *(folder for folder, _ in layout.states), *(folder for folder, _ in layout.workspaces),
             *(config.parent for config in layout.configs)]
    for folder in moved:
        if not any(folder.is_relative_to(r) for r in roots):
            roots.append(folder)
    return roots


def _hooks_dir(path: Path) -> Path | None:
    return next((d for d in reversed(path.parents)
                 if d.name == "hooks" and (d.parent.name == ".claude" or d.parent == claude_dir())), None)


def is_hook_script(path: Path) -> bool:
    return _hooks_dir(path) is not None


def _matches(root: Path, pattern: str) -> list[Path]:
    """Files under `root` matching `pattern`. The root is taken literally: a folder named
    `notes [old]` is not a character class."""
    return [Path(p) for p in sorted(glob.glob(os.path.join(glob.escape(str(root)), pattern), recursive=True,
                                              include_hidden=True))]


def discover(agents: list[str] | None = None, project: Path | None = None, home: Path | None = None,
             *, cwd: Path | None = None) -> list[ContextFile]:
    home = home or home_dir()
    found: dict[Path, ContextFile] = {}
    for name in agents or list(PROFILES):
        profile = PROFILES[name]
        for scope, root, kind, pattern in _globs(profile, home, project, cwd=cwd):
            for path in _matches(root, pattern):
                if path.is_file() and path not in found and _counts(pattern, path):
                    found[path] = ContextFile(profile.name, kind, scope, path)
    return list(found.values())


def discover_session(project: Path, agent: str) -> list[ContextFile]:
    home = home_dir()
    found: dict[Path, ContextFile] = {}
    for scope, root, kind, pattern in _globs(PROFILES[agent], home, project):
        if pattern in ('.claude/projects/*/memory/*.md', 'projects/*/memory/*.md'):
            root, pattern = claude_memory_dir(project, home), '*.md'
        for path in _matches(root, pattern):
            if path.is_file() and not path.is_symlink() and _counts(pattern, path):
                found.setdefault(path, ContextFile(agent, kind, scope, path))
    return list(found.values())


# Folders a nested search does not enter: what package managers and build tools fill, and
# every hidden folder but the ones a client keeps context in.
_SKIPPED_DIRS = _DEPENDENCY_DIRS | {"dist", "build", "target", "out", "coverage"}
_CONTEXT_DIRS = {".claude", ".codex", ".cursor", ".agents", ".workbuddy"}
NESTED_FOLDERS = 20_000


@dataclass
class ClientCoverage:
    """What was looked at for one client, and what was not."""
    agent: str
    verified: bool
    roots: list[dict] = field(default_factory=list)      # {"path", "scope", "source", "exists"}
    files: int = 0
    limits: list[str] = field(default_factory=list)
    problems: list[str] = field(default_factory=list)


@dataclass
class Survey:
    files: list[ContextFile]
    clients: list[ClientCoverage]
    unread: list[str] = field(default_factory=list)    # files found that then could not be read

    @property
    def problems(self) -> list[str]:
        """Everything that kept part of what was asked for from being looked at."""
        return [f"{c.agent}: {problem}" for c in self.clients for problem in c.problems] + self.unread


def survey(agents: list[str] | None = None, project: Path | None = None, home: Path | None = None) -> Survey:
    """Everything `discover` finds plus the context files in the project's subfolders, with
    the folders that were looked in and whatever kept a folder from being looked in. For
    the commands a person runs; hooks use `discover`, which walks nothing."""
    home = home or home_dir()
    names = agents or list(PROFILES)
    found: dict[Path, ContextFile] = {}
    counts = dict.fromkeys(names, 0)
    for name in names:
        for cf in discover([name], project, home):
            counts[name] += 1
            found.setdefault(cf.path, cf)
    nested, note = _nested(names, project, home) if project is not None else ([], "")
    for cf in nested:
        if cf.path not in found:
            found[cf.path] = cf
            counts[cf.agent] += 1
    clients = []
    for name in names:
        profile = PROFILES[name]
        coverage = ClientCoverage(name, profile.verified, files=counts[name], limits=list(profile.limits))
        _describe_roots(coverage, home, project)
        if note and profile.written:
            coverage.limits.append(note)
        clients.append(coverage)
    return Survey(list(found.values()), clients)


def _nested(names: list[str], project: Path, home: Path) -> tuple[list[ContextFile], str]:
    """Context files in the project's subfolders (a nested CLAUDE.md, AGENTS.md,
    .cursor/rules), found in one walk that stays out of dependency folders and stops after
    NESTED_FOLDERS folders. Returns them with a note when the walk was cut short or not made."""
    patterns = [(PROFILES[name], kind, _glob_regex(pattern, CASELESS)) for name in names
                for kind, pattern in PROFILES[name].written]
    if not patterns:
        return [], ""
    top = Path(os.path.abspath(project))
    if top == Path(top.anchor) or top == Path(os.path.abspath(home)):
        return [], f"subfolders of {top} were not searched: it is a whole home folder or disk"
    found: list[ContextFile] = []
    visited = 0
    for folder, folders, files in os.walk(top):
        visited += 1
        if visited > NESTED_FOLDERS:
            return found, (f"the search of {top}'s subfolders stopped after {NESTED_FOLDERS} folders; nested "
                           "context files beyond them were not looked at")
        folders[:] = sorted(d for d in folders if d not in _SKIPPED_DIRS
                            and (not d.startswith(".") or d in _CONTEXT_DIRS))
        if folder == str(top):
            continue
        for name in sorted(files):
            path = Path(folder, name)
            rel = _relative(path, top)
            for profile, kind, regex in patterns if rel is not None else ():
                if regex.fullmatch(rel) and path.is_file():
                    found.append(ContextFile(profile.name, kind, "project", path))
                    break
    return found, ""


def _describe_roots(coverage: ClientCoverage, home: Path, project: Path | None) -> None:
    def add(path: Path, scope: str, source: str) -> None:
        if not any(r["path"] == str(path) for r in coverage.roots):
            coverage.roots.append({"path": str(path), "scope": scope, "source": source, "exists": path.is_dir()})

    name = coverage.agent
    if name == "claude-code":
        add(claude_dir(home), "user", "CLAUDE_CONFIG_DIR" if os.environ.get("CLAUDE_CONFIG_DIR") else "default")
        if os.environ.get("CLAUDE_CONFIG_DIR") and not claude_dir(home).is_dir():
            coverage.problems.append(f"CLAUDE_CONFIG_DIR names {claude_dir(home)}, which does not exist")
        relocated = _auto_memory_settings(home, project)
        if relocated:
            coverage.problems.append("autoMemoryDirectory moves Claude Code's auto memory to "
                                     + ", ".join(relocated) + "; that folder is not covered")
    elif name == "codex":
        add(codex_dir(home), "user", "CODEX_HOME" if os.environ.get("CODEX_HOME") else "default")
        add(home / ".agents", "user", "default")
        if os.environ.get("CODEX_HOME") and not codex_dir(home).is_dir():
            coverage.problems.append(f"CODEX_HOME names {codex_dir(home)}, which does not exist")
    elif name == "cursor":
        add(home / ".cursor", "user", "default")
        add(home / ".agents", "user", "default")
        for folder, source in cursor_cli_configs(home):
            # XDG_CONFIG_HOME is where the config would be, not a statement that Cursor is used.
            if source == "CURSOR_CONFIG_DIR" or folder.is_dir():
                add(folder, "user", source)
            if source == "CURSOR_CONFIG_DIR" and not folder.is_dir():
                coverage.problems.append(f"{source} names {folder}, which does not exist")
    elif name == "openclaw":
        layout = openclaw_layout(home)
        for folder, source in layout.states:
            add(folder, "user", source)
        for folder, source in layout.workspaces:
            add(folder, "user", source)
        if not layout.states:
            add(home / ".openclaw", "user", "default location")
        coverage.problems += layout.problems
    else:
        add(home / f".{name}", "user", "unverified guess" if not coverage.verified else "default")
    if project is not None and (PROFILES[name].project or PROFILES[name].written):
        add(Path(os.path.abspath(project)), "project", "project")


def _auto_memory_settings(home: Path, project: Path | None) -> list[str]:
    """Values of Claude Code's autoMemoryDirectory setting in the settings files read here."""
    files = [claude_dir(home) / "settings.json"]
    if project is not None:
        files += [project / ".claude" / "settings.json", project / ".claude" / "settings.local.json"]
    found = []
    for file in files:
        try:
            data = json.loads(file.read_text(encoding="utf-8"))
        except (OSError, ValueError):
            continue
        value = data.get("autoMemoryDirectory") if isinstance(data, dict) else None
        if isinstance(value, str) and value.strip():
            found.append(printable(value))
    return list(dict.fromkeys(found))


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
            for scope, root, kind, pattern in _globs(profile, home, project, writes=True, candidate=candidate):
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
    # the physical one of the git repository the session is in (macOS's /var is
    # /private/var), so that every worktree and subfolder of one repository shares one
    # memory folder; outside a repository it is the project folder.
    named = os.environ.get("CLAUDE_CODE_PROJECT_DIR_NAME")
    if named and os.environ.get("CLAUDE_CONFIG_DIR") and Path(named).name == named:
        return claude_dir(home) / "projects" / named / "memory"
    data = str(claude_project_root(project)).encode("utf-16-le")
    units = [int.from_bytes(data[i:i + 2], "little") for i in range(0, len(data), 2)]
    slug = "".join(chr(u) if chr(u).isascii() and chr(u).isalnum() else "-" for u in units)
    if len(slug) > _SLUG_MAX:
        slug = f"{slug[:_SLUG_MAX]}-{_base36(abs(_java_hash(units)))}"
    return claude_dir(home) / "projects" / slug / "memory"


def claude_project_root(project: Path) -> Path:
    """The folder Claude Code keys a project's auto memory on: the main working tree of the
    repository `project` is in, or `project` itself outside one."""
    real = Path(os.path.realpath(project))
    for folder in (real, *real.parents):
        marker = folder / ".git"
        if marker.is_dir():
            return folder
        if marker.is_file():
            # A linked worktree: .git names its own folder under the main repository's
            # .git/worktrees, whose `commondir` leads back to that .git.
            return _main_worktree(marker) or folder
    return real


def _main_worktree(marker: Path) -> Path | None:
    try:
        line = marker.read_text(encoding="utf-8", errors="replace").strip()
        if not line.startswith("gitdir:"):
            return None
        own = Path(os.path.normpath(marker.parent / line[len("gitdir:"):].strip()))
        common = Path(os.path.realpath(own / (own / "commondir").read_text(encoding="utf-8").strip()))
    except OSError:
        return None
    return common.parent if common.name == ".git" and common.is_dir() else None


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
