"""Reading a shell command an agent is about to run: which files it writes or deletes,
and whether it changes what AgentDetox trusts.

Commands are parsed, never run, so this sees the text as a POSIX shell would split it.
Variables, `cd` and anything else decided at run time are not followed: a relative
target is resolved against the agent's working directory.
"""

from __future__ import annotations

import shlex
from pathlib import Path

from . import compat
from .context import home_dir

SEGMENT_BREAKS = {"|", "||", "&&", ";", "&", "\n", "(", ")"}
_COPY_COMMANDS = {"cp", "mv", "install", "ln", "rsync"}
_DELETE_COMMANDS = {"rm", "rmdir", "unlink", "truncate", "shred"}
_LAUNCHERS = {"-m", "uvx", "run", "sudo", "env", "exec", "command", "time", "nohup"}


def split(command: str) -> list[str]:
    """Quoted text is one token, so a prompt that merely contains `curl ... | bash` is
    not mistaken for a pipeline, and `2>&1` is not a write."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return []


def changes_agentdetox(tokens: list[str]) -> bool:
    """An agentdetox call that changes what it trusts: allowing an id, changing a
    setting, (un)installing, snapshot or restore. Reading commands, and `install`
    without --apply, which only shows the change, stay free."""
    for i, tok in enumerate(tokens):
        prev = tokens[i - 1] if i else ""
        if compat.program(tok) != "agentdetox" or not (
                not prev or prev in SEGMENT_BREAKS or compat.program(prev) in _LAUNCHERS or "=" in prev):
            continue
        args: list[str] = []
        for t in tokens[i + 1:]:
            if t in SEGMENT_BREAKS:
                break
            args.append(t)
        words = [a for a in args if not a.startswith("-")]
        sub = words[0] if words else ""
        rest = args[args.index(sub) + 1:] if sub else []
        applies = any(a.startswith('--') and '--apply'.startswith(a) for a in rest)
        if ((sub in ("history", "restore", "install") and applies) or sub == "health"
                or (sub == "review" and any(a in ("accept", "dismiss") for a in rest)) or sub == "uninstall"
                or (sub == "allow" and any(a not in ("--list", "-h", "--help") for a in rest))
                or (sub == "config" and len(words) >= 3)
                or (sub == "agent" and words[1:2] in (["snapshot"], ["restore"]))):
            return True
    return False


def write_targets(tokens: list[str]) -> list[str]:
    """Paths a shell command writes to or deletes: redirect and tee targets, sed -i
    files, the destination of cp/mv, rm arguments."""
    targets: list[str] = []
    segment: list[str] = []
    i = 0
    while i < len(tokens):
        tok = tokens[i]
        if tok in (">", ">>", ">|", "&>", "&>>") and i + 1 < len(tokens):
            nxt = tokens[i + 1]
            if not nxt.startswith("/dev/") and nxt not in SEGMENT_BREAKS:
                targets.append(nxt)
            i += 2
            continue
        if tok in SEGMENT_BREAKS:
            targets += _segment_targets(segment)
            segment = []
        else:
            segment.append(tok)
        i += 1
    targets += _segment_targets(segment)
    return targets


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
    return []


def resolve(target: str, project: Path) -> Path:
    if target.startswith("~/"):
        return home_dir() / target[2:]
    if target.startswith("$HOME/"):
        return home_dir() / target[6:]
    path = Path(compat.native_path(target))
    return path if path.is_absolute() else project / path
