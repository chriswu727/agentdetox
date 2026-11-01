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
             "xargs", "caffeinate", "unbuffer",
             # Shell keywords and braces run what follows in the current shell.
             "{", "}", "!", "if", "then", "else", "elif", "do", "while", "until"}
_INTERPRETERS = {"python", "python2", "python3", "node", "nodejs", "perl", "ruby", "php", "deno", "bun"}
_ASSIGN = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*=")
_VAR = re.compile(r"\$(?:\{([A-Za-z_][A-Za-z0-9_]*)\}|([A-Za-z_][A-Za-z0-9_]*))")
# What inline interpreter code would have to name to write an agent's context file.
_CONTEXT_NAME = re.compile(
    r"[\w~$./\\-]*(?:CLAUDE(?:\.local)?\.md|AGENTS(?:\.override)?\.md|SKILL\.md|MEMORY\.md|\.mcp\.json|\.claude\.json"
    r"|settings(?:\.local)?\.json|\.claude/[\w./-]+|memory/[\w.-]+\.md|\.codex/[\w./-]+|\.cursor/[\w./-]+)", re.I)
_WRITES = re.compile(r"write|append|open\([^,)]*,\s*(?:mode\s*=\s*)?['\"][rb+]*[wax]|unlink|os\.remove|rmtree|rename"
                     r"|os\.replace|truncate"
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


def _commands(tokens: list[str]) -> list[tuple[list[str], list[str], str | None, str | None, int]]:
    """Each simple command with its output redirections, the separators before and after it,
    and how many subshells `( … )` deep it runs."""
    out: list[tuple[list[str], list[str], str | None, str | None, int]] = []
    words: list[str] = []
    redirects: list[str] = []
    before: str | None = None
    depth = 0

    def end(after: str | None) -> None:
        nonlocal words, redirects, before
        if words or redirects:
            out.append((words, redirects, before, after, depth))
        words, redirects, before = [], [], after

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
            end(tok)
            depth += {"(": 1, ")": -1}.get(tok, 0)
        else:
            words.append(tok)
        i += 1
    end(None)
    return out


class _Scope:
    """What one shell level knows: the folders relative paths may be relative to, and the
    possible values of variables. A `cd` can fail and a branch can be skipped, so a change
    adds a possibility rather than replacing one, except where it is certain: the commands
    chained after `cd x &&` run only if it worked."""

    def __init__(self, cwds: list[str], env: dict[str, list[str]]) -> None:
        self.cwds = cwds
        self.env = env
        self.after_chain: list[str] | None = None   # folders once the current && / || chain ends

    def copy(self) -> _Scope:
        return _Scope(list(self.cwds), {k: list(v) for k, v in self.env.items()})


def write_targets(tokens: list[str], depth: int = 0) -> list[str]:
    """Paths a shell command writes to or deletes: redirect and tee targets, sed -i and
    perl -i files, the destination of cp/mv, rm arguments, git checkout/restore paths,
    curl/wget output files, files named by inline interpreter code that writes, and the
    same inside `bash -c` and `eval`. A `cd` and variables set earlier in the same command
    are followed where the shell would keep them; anything decided at run time is not."""
    targets: list[str] = []
    scopes = [_Scope([""], {"HOME": ["~"]})]        # one per `( … )` level
    for words, redirects, before, after, level in _commands(tokens):
        while len(scopes) - 1 < level:
            scopes.append(scopes[-1].copy())
        del scopes[level + 1:]
        scope = scopes[-1]
        if before in (None, ";", "\n", "&", "(", ")") and scope.after_chain is not None:
            scope.cwds, scope.after_chain = scope.after_chain, None
        # A cd or assignment in a pipeline or in the background runs in a subshell of its own.
        lasting = before != "|" and after not in ("|", "&")
        for variant in _variants(words + redirects, scope.env):
            words_now, redirects_now = variant[:len(words)], variant[len(words):]
            body = _unwrap(words_now)
            found: list[str] = []
            if not (body and compat.program(body[0]) == "cd") and not _assignments(words_now):
                inner = _inner(body) if body else None
                if inner is not None:
                    found = write_targets(split(inner), depth + 1) if depth < _MAX_DEPTH else []
                else:
                    found = _segment_targets(body)
            # A command's own redirections are opened before it runs, in the folder it starts in.
            targets += [_under(cwd, t) for cwd in scope.cwds for t in redirects_now + found]
        body = _unwrap(words)
        if lasting and body and compat.program(body[0]) == "cd":
            target = body[1] if len(body) > 1 else "~"
            new = [_under(cwd, target) for cwd in scope.cwds] if "$" not in target and target != "-" else []
            if after in ("&&", "||"):
                scope.after_chain = _bounded((scope.after_chain or scope.cwds) + new)
                if after == "&&":
                    scope.cwds = new or scope.cwds
            else:
                scope.cwds = _bounded(scope.cwds + new)
        elif lasting and _assignments(words):
            for name, value in _assignments(words):
                certain = before not in ("&&", "||")
                scope.env[name] = [value] if certain else _bounded(scope.env.get(name, ["$" + name]) + [value], 8)
    return list(dict.fromkeys(targets))


_MAX_CWDS = 16
_MAX_VARIANTS = 8


def _bounded(values: list[str], limit: int = _MAX_CWDS) -> list[str]:
    """At most `limit` possibilities, always keeping the first (where the command started)."""
    values = list(dict.fromkeys(values))
    return values if len(values) <= limit else [values[0], *values[-(limit - 1):]]


def _assignments(words: list[str]) -> list[tuple[str, str]]:
    """The variables a command made only of assignments (or `export` of them) sets."""
    rest = words[1:] if words[:1] == ["export"] else words
    if not rest or not all(_ASSIGN.match(w) for w in rest):
        return []
    return [(w.partition("=")[0], w.partition("=")[2]) for w in rest]


def _variants(words: list[str], env: dict[str, list[str]]) -> list[list[str]]:
    """`words` with variables replaced by each combination of their possible values."""
    names = sorted({m.group(1) or m.group(2) for w in words for m in _VAR.finditer(w)} & env.keys())
    combos: list[dict[str, str]] = [{}]
    for name in names:
        combos = [{**c, name: v} for c in combos for v in env[name]][:_MAX_VARIANTS]

    def fill(word: str, values: dict[str, str]) -> str:
        return _VAR.sub(lambda m: values.get(m.group(1) or m.group(2), m.group(0)), word)

    return [[fill(w, c) for w in words] for c in combos]


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
