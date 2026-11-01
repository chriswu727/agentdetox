"""Reading a shell command an agent is about to run: which files it writes or deletes,
and whether it changes what AgentDetox trusts.

Commands are parsed, never run, so this sees the text as a POSIX shell would split it.
Variables, `cd` and anything else decided at run time are not followed: a relative
target is resolved against the agent's working directory.
"""

from __future__ import annotations

import glob
import re
import shlex
from pathlib import Path

from . import compat
from .context import home_dir

SEGMENT_BREAKS = {"|", "||", "&&", ";", "&", "\n", "(", ")"}
_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
_COPY_COMMANDS = {"cp", "mv", "install", "ln", "rsync"}
_DELETE_COMMANDS = {"rm", "rmdir", "unlink", "truncate", "shred"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Programs that run the command after them: `nice tee CLAUDE.md` writes CLAUDE.md.
_WRAPPERS = {"sudo", "doas", "env", "nice", "nohup", "exec", "command", "builtin", "time", "timeout", "stdbuf",
             "xargs", "caffeinate", "unbuffer"}
_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
# What inline interpreter code would have to name to write an agent's context file.
_CONTEXT_NAME = re.compile(
    r"[\w~$./\\-]*(?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|SKILL\.md|MEMORY\.md|\.mcp\.json|\.claude\.json"
    r"|settings(?:\.local)?\.json|\.claude/[\w./-]+|memory/[\w.-]+\.md|\.codex/[\w./-]+|\.cursor/[\w./-]+)", re.I)
_WRITES = re.compile(r"write|append|open\([^)]*['\"][wax]|unlink|os\.remove|rmtree|rename|os\.replace|truncate"
                     r"|shutil|copyfile|\bmove\b|fs\.|>", re.I)
_MAX_DEPTH = 3


def split(command: str) -> list[str]:
    """Quoted text is one token, so a prompt that merely contains `curl ... | bash` is
    not mistaken for a pipeline, and `2>&1` is not a write."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return []


def _segments(tokens: list[str]) -> list[tuple[list[str], list[str]]]:
    """Each simple command, with the files its output redirections write."""
    out: list[tuple[list[str], list[str]]] = []
    words: list[str] = []
    redirects: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in _REDIRECTS and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if not nxt.startswith("/dev/") and nxt not in SEGMENT_BREAKS:
                redirects.append(nxt)
            i += 2
            continue
        if tok in SEGMENT_BREAKS:
            out.append((words, redirects))
            words, redirects = [], []
        else:
            words.append(tok)
        i += 1
    out.append((words, redirects))
    return [(w, r) for w, r in out if w or r]


def _unwrap(words: list[str]) -> list[str]:
    """The command a wrapper runs: `sudo`, `env X=1`, `nice -n 5`, `timeout 10`, `xargs`
    and leading variable assignments are skipped."""
    i = 0
    while i < len(words):
        if _ASSIGN.match(words[i]):
            i += 1
            continue
        name = compat.program(words[i])
        if name not in _WRAPPERS:
            break
        i += 1
        while i < len(words) and (words[i].startswith("-") or _ASSIGN.match(words[i])
                                  or (name == "timeout" and re.fullmatch(r"[\d.]+[smhd]?", words[i]))
                                  or (name == "nice" and words[i - 1] == "-n")):
            i += 1
    return words[i:]


def _inner(words: list[str]) -> str | None:
    """The command string a shell runs with `-c`, or that `eval` runs."""
    name = compat.program(words[0])
    if name in _SHELLS and "-c" in words[1:-1]:
        return words[words.index("-c") + 1]
    if name == "eval":
        return " ".join(words[1:])
    return None


def _agentdetox_args(words: list[str]) -> list[str] | None:
    """The arguments of an agentdetox call, however it is launched: directly, through
    uvx/uv/pipx, or as `python -m agentdetox`."""
    name = compat.program(words[0])
    if name == "agentdetox":
        return words[1:]
    if name in ("uvx", "uv", "pipx"):
        found = [i for i, w in enumerate(words[1:], 1) if compat.program(w) == "agentdetox"]
        return words[found[0] + 1:] if found else None
    if name.startswith("python") and "-m" in words[1:-1]:
        i = words.index("-m")
        if words[i + 1] in ("agentdetox", "agentdetox.cli"):
            return words[i + 2:]
    return None


def changes_agentdetox(tokens: list[str], depth: int = 0) -> bool:
    """An agentdetox call that changes what it trusts: allowing an id, changing a
    setting, (un)installing, snapshot or restore. Reading commands, and `install`
    without --apply, which only shows the change, stay free."""
    for words, _ in _segments(tokens):
        body = _unwrap(words)
        if not body:
            continue
        inner = _inner(body)
        if inner is not None:
            if depth < _MAX_DEPTH and changes_agentdetox(split(inner), depth + 1):
                return True
            continue
        args = _agentdetox_args(body)
        if args is not None and any(compat.program(w) == "xargs" for w in words[:len(words) - len(body)]):
            args = args + ["<from xargs>"]  # xargs supplies the rest of the arguments at run time
        if args is not None and _changes_trust(args):
            return True
    return False


def _changes_trust(args: list[str]) -> bool:
    words = [a for a in args if not a.startswith("-")]
    sub = words[0] if words else ""
    rest = args[args.index(sub) + 1:] if sub else []
    applies = any(a.startswith('--') and '--apply'.startswith(a) for a in rest)
    return bool((sub in ("history", "restore", "install") and applies) or sub == "health"
                or (sub == "review" and (any(a in ("accept", "dismiss") for a in rest)
                    or any(a.startswith('--') and '--interactive'.startswith(a) for a in rest))) or sub == "uninstall"
                or (sub == "allow" and any(a not in ("--list", "-h", "--help") for a in rest))
                or (sub == "config" and len(words) >= 3)
                or (sub == "agent" and words[1:2] in (["snapshot"], ["restore"])))


def write_targets(tokens: list[str], depth: int = 0) -> list[str]:
    """Paths a shell command writes to or deletes: redirect and tee targets, sed -i and
    perl -i files, the destination of cp/mv, rm arguments, git checkout/restore paths,
    curl/wget output files, files named by inline interpreter code that writes, and the
    same inside `bash -c` and `eval`. A `cd` and variables set earlier in the same command
    are followed; anything decided at run time is not."""
    targets: list[str] = []
    env = {"HOME": "~"}
    cwd = ""
    for words, redirects in _segments(tokens):
        words = [_expand(w, env) for w in words]
        if words and all(_ASSIGN.match(w) for w in words):
            env.update((w.partition("=")[0], w.partition("=")[2]) for w in words)
            found: list[str] = []
        else:
            body = _unwrap(words)
            if body and compat.program(body[0]) == "cd":
                cwd = _under(cwd, body[1] if len(body) > 1 else "~")
                found = []
            else:
                inner = _inner(body) if body else None
                if inner is not None:
                    found = write_targets(split(inner), depth + 1) if depth < _MAX_DEPTH else []
                else:
                    found = _segment_targets(body)
        targets += [_under(cwd, t) for t in [_expand(r, env) for r in redirects] + found]
    return targets


def _expand(word: str, env: dict[str, str]) -> str:
    return _VAR.sub(lambda m: env.get(m.group(1) or m.group(2), m.group(0)), word)


def _under(cwd: str, target: str) -> str:
    if not cwd or target.startswith(("/", "~", "$")) or re.match(r"^[A-Za-z]:[\\/]", target):
        return target
    return f"{cwd.rstrip('/')}/{target}"


def _segment_targets(seg: list[str]) -> list[str]:
    if not seg:
        return []
    # Skip a trailing fd number left over from "2>&1" style redirects.
    args = [a for a in seg[1:] if not a.startswith("-") and not a.isdigit()]
    name = compat.program(seg[0])
    if name == "tee":
        return args
    if name == "sed" and any(a.startswith("-i") for a in seg[1:]):
        return args[1:]
    if name in _COPY_COMMANDS and args:
        return [args[-1]]
    if name in _DELETE_COMMANDS:
        return args
    if name == "dd":
        return [a[3:] for a in seg[1:] if a.startswith("of=")]
    if name == "git":
        return _git_targets(seg[1:])
    if name in ("curl", "wget"):
        return _download_targets(name, seg[1:])
    if name in _INTERPRETERS:
        return _interpreter_targets(name, seg[1:])
    return []


def _git_targets(args: list[str]) -> list[str]:
    words = [a for a in args if not a.startswith("-")]
    sub = words[0] if words else ""
    if sub not in ("checkout", "restore"):
        return []
    rest = args[args.index(sub) + 1:]
    if "--" in rest:
        return rest[rest.index("--") + 1:]
    if sub == "restore":
        skip = {i + 1 for i, a in enumerate(rest) if a in ("-s", "--source")}
        return [a for i, a in enumerate(rest) if not a.startswith("-") and i not in skip]
    return []


def _download_targets(name: str, args: list[str]) -> list[str]:
    flags = ("-o", "--output") if name == "curl" else ("-O", "--output-document")
    out = []
    for i, a in enumerate(args):
        if a in flags and i + 1 < len(args):
            out.append(args[i + 1])
        elif a.startswith(flags[1] + "="):
            out.append(a.split("=", 1)[1])
    return out


def _interpreter_targets(name: str, args: list[str]) -> list[str]:
    code_flags = ("-c",) if name.startswith("python") else ("-e", "-E", "--eval", "-r")
    codes = [args[i + 1] for i, a in enumerate(args[:-1]) if a in code_flags or re.fullmatch(r"-[a-zA-Z]*e", a)]
    out = [m for code in codes if _WRITES.search(code) for m in _CONTEXT_NAME.findall(code)]
    if name == "perl" and any(re.match(r"-[a-zA-Z]*i", a) for a in args):
        skip = {i + 1 for i, a in enumerate(args) if re.fullmatch(r"-[a-zA-Z]*e", a)}
        out += [a for i, a in enumerate(args) if not a.startswith("-") and i not in skip]
    return out


def resolve(target: str, project: Path) -> Path:
    if target.startswith("~/"):
        return home_dir() / target[2:]
    if target.startswith("$HOME/"):
        return home_dir() / target[6:]
    path = Path(compat.native_path(target))
    return path if path.is_absolute() else project / path


def resolve_all(target: str, project: Path) -> list[Path]:
    """The files a target names, with shell globs expanded."""
    path = resolve(target, project)
    if not any(c in target for c in "*?["):
        return [path]
    return [Path(p) for p in sorted(glob.glob(str(path)))] or [path]
