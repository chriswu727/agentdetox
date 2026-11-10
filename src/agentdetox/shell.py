"""Reading a shell command an agent is about to run: which files it writes or deletes,
and whether it changes what AgentDetox trusts.

Commands are parsed, never run, so this sees the text as a POSIX shell would split it.
Variables, `cd` and anything else decided at run time are not followed: a relative
target is resolved against the agent's working directory.
"""

from __future__ import annotations

import glob
import posixpath
import re
import shlex
import sys
from collections.abc import Sequence
from pathlib import Path

from . import compat
from .context import home_dir

SEGMENT_BREAKS = {"|", "||", "&&", ";", "&", "\n", "(", ")"}
_REDIRECTS = {">", ">>", ">|", "&>", "&>>"}
_COPY_COMMANDS = {"cp", "mv", "install", "ln", "rsync"}
_DELETE_COMMANDS = {"rm", "rmdir", "unlink", "truncate", "shred"}
_SHELLS = {"sh", "bash", "zsh", "dash", "ksh", "fish"}
# Programs that run the command after them: `nice tee CLAUDE.md` writes CLAUDE.md.
# Shell keywords and braces run what follows in the current shell.
_KEYWORDS = {"{", "}", "!", "if", "then", "else", "elif", "do", "while", "until"}
_WRAPPERS = {"sudo", "doas", "env", "nice", "nohup", "exec", "command", "builtin", "time", "timeout", "stdbuf",
             "xargs", "caffeinate", "unbuffer", "ionice", "taskset", "chrt", *_KEYWORDS}
# Options that take the next word as their value, so that word is not the command run:
# `sudo -u root tee CLAUDE.md` runs tee. Long forms may also be written `--user=root`.
_WRAPPER_VALUES = {
    "sudo": {"-C", "-D", "-g", "-h", "-p", "-R", "-r", "-T", "-t", "-U", "-u", "--close-from", "--chdir",
             "--group", "--host", "--prompt", "--chroot", "--role", "--command-timeout", "--type",
             "--other-user", "--user"},
    "doas": {"-C", "-u"},
    "env": {"-u", "-C", "-P", "--unset", "--chdir"},
    "nice": {"-n", "--adjustment"},
    "timeout": {"-s", "-k", "--signal", "--kill-after"},
    # GNU's --replace, --eof and --max-lines take a value only when attached with `=`.
    "xargs": {"-a", "-d", "-E", "-I", "-L", "-n", "-P", "-s", "--arg-file", "--delimiter", "--max-args",
              "--max-procs", "--max-chars", "--process-slot-var"},
    "stdbuf": {"-i", "-o", "-e", "--input", "--output", "--error"},
    "time": {"-f", "-o", "--format", "--output"},
    "exec": {"-a"},
    "caffeinate": {"-t", "-w"},
    "ionice": {"-c", "-n", "-p", "-P", "-u", "--class", "--classdata", "--pid", "--pgid", "--uid"},
}
# Options that make a wrapper run its command in another folder: `env -C .claude tee
# settings.json` writes .claude/settings.json. `sudo -i` starts in the home folder.
_WRAPPER_DIRS = {"env": {"-C", "--chdir"}, "sudo": {"-D", "--chdir"}}
_WRAPPER_HOME = {"sudo": {"-i", "--login"}}
# Wrapper options whose value is a file the wrapper writes: `time -o FILE`.
_WRAPPER_WRITES = {"time": {"-o", "--output"}}
# Words a wrapper takes after its options, before the command: `timeout 10 cmd`,
# `taskset 0x3 cmd`, `chrt 10 cmd`.
_WRAPPER_OPERANDS = {"timeout": 1, "taskset": 1, "chrt": 1}
# Shell options that take the next word as their value.
_SHELL_VALUES = {"-o", "+o", "-O", "+O", "--rcfile", "--init-file"}
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
# Ends a target that acts on everything under it when it is a folder (`rm -r .claude`,
# `git checkout -- .`); a copy's destination folder only receives the copied file. Shell
# words cannot contain NUL.
TREE = "\0"


def split(command: str) -> list[str]:
    """Quoted text is one token, so a prompt that merely contains `curl ... | bash` is
    not mistaken for a pipeline, and `2>&1` is not a write."""
    try:
        lexer = shlex.shlex(command, posix=True, punctuation_chars=";&|<>()")
        lexer.whitespace_split = True
        return list(lexer)
    except ValueError:
        return []


def literal_printf(command: str) -> tuple[str, str, str] | None:
    """A leading printf with literal %s arguments and one static output path. Everything
    after that command remains executable shell text; no substitutions or %b decoding."""
    match = re.match(
        r"\A\s*printf[ \t]+'(?P<format>%s(?:\\n)?)'[ \t]+"
        r"(?P<args>'[^']*'(?:[ \t]+'[^']*')*)[ \t]+"
        r"(?P<redirect>>{1,2})[ \t]*(?P<target>'[^'\n]+'|[A-Za-z0-9_./~-]+)"
        r"(?=[ \t]*(?:$|&&|;|\n))", command,
    )
    if not match:
        return None
    values = re.findall(r"'([^']*)'", match['args'])
    separator = '\n' if match['format'] == r'%s\n' else ''
    body = separator.join(values) + separator
    executable = 'printf ' + match['redirect'] + ' ' + match['target'] + command[match.end():]
    return match['target'].strip("'"), body, executable


def literal_heredoc(command: str) -> tuple[str, str, str] | None:
    match = re.match(
        r"\A[ \t]*cat[ \t]+(?P<redirect>>{1,2})[ \t]*(?P<target>'[^'\n]+'|[A-Za-z0-9_./~-]+)"
        r"[ \t]+<<(?P<quote>['\"])(?P<end>[A-Za-z_][A-Za-z0-9_]*)(?P=quote)[ \t]*\n"
        r"(?P<body>[\s\S]*?)\n(?P=end)(?=\n|$)", command,
    )
    if not match:
        return None
    executable = 'cat ' + match['redirect'] + ' ' + match['target'] + command[match.end():]
    return match['target'].strip("'"), match['body'] + '\n', executable


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


def _options(words: list[str], i: int, values: set[str]) -> tuple[list[tuple[str, str | None]], int]:
    """The options in `words[i]` with the value each takes, and how many words they use:
    `-u root`, `-uroot`, a bundle such as `-Eu root`, `--user root` and `--user=root`."""
    word = words[i]
    following = words[i + 1] if i + 1 < len(words) else ""
    if word.startswith("--"):
        name, eq, value = word.partition("=")
        if eq:
            return [(name, value)], 1
        return ([(name, following)], 2) if name in values else ([(name, None)], 1)
    found: list[tuple[str, str | None]] = []
    for j, letter in enumerate(word[1:], 1):
        if f"-{letter}" in values:
            rest = word[j + 1:]
            return [*found, (f"-{letter}", rest or following)], 1 if rest else 2
        found.append((f"-{letter}", None))
    return found, 1


# Joins a folder to a path named by a variable. Whether the path is taken from the folder is
# only known once the variable is expanded: an absolute value replaces the folder.
_THEN = "\2"


def _join(folder: str, path: str) -> str:
    """`path` taken from `folder`, also when `path` is a variable whose value is not known yet."""
    if not folder or not _relative(path):
        return path
    if path.startswith("$"):
        return f"{folder.rstrip('/') or '/'}{_THEN}{path}"
    return f"{folder.rstrip('/')}/{path}"


def _settle(path: str) -> str:
    """A path joined by `_join`, once its variables are expanded."""
    first, *rest = path.split(_THEN)
    for part in rest:
        first = _under(first, part)
    return first


def _unwrap(words: list[str]) -> list[str]:
    return _unwrap_in(words)[0]


def _unwrap_in(words: list[str], folder: str = "",
               written: list[tuple[str, str]] | None = None) -> tuple[list[str], str]:
    """The command a wrapper runs, and the folder it runs it in relative to where the
    wrapper started ("" for the same one): `sudo -u root`, `env -u X Y=1`, `nice -n 5`,
    `timeout -s KILL 10`, `xargs -I {}` and leading variable assignments are skipped.
    Files the wrappers themselves write are added to `written`, with their folder."""
    i = 0
    while i < len(words):
        if _ASSIGN.match(words[i]):
            i += 1
            continue
        name = compat.program(words[i])
        if name not in _WRAPPERS:
            break
        i += 1
        values = _WRAPPER_VALUES.get(name, set())
        chdir = ""      # the last folder option counts, taken from where this wrapper started
        while i < len(words):
            word = words[i]
            if word == "--":
                i += 1
                break
            if name == "env" and word.startswith(("-S", "--split-string")) and word not in ("-S", "--split-string"):
                value = word.removeprefix("--split-string=") if word.startswith("--") else word[2:]
                words = [*words[:i], "-S", value, *words[i + 1:]]
                continue
            if name == "env" and word in ("-S", "--split-string") and i + 1 < len(words):
                return _unwrap_in(["env", *(["-C", chdir] if chdir else []), *split(words[i + 1]), *words[i + 2:]],
                                  folder, written)
            if word.startswith("-") and word != "-":
                options, used = _options(words, i, values)
                for option, given in options:
                    if option in _WRAPPER_DIRS.get(name, ()) and given:
                        chdir = given
                    elif option in _WRAPPER_HOME.get(name, ()):
                        folder = "~"
                    elif option in _WRAPPER_WRITES.get(name, ()) and given and written is not None:
                        written.append((folder, given))
                i += used
            elif word == "-" or _ASSIGN.match(word):
                i += 1
            else:
                break
        folder = _join(folder, chdir) if chdir else folder
        i += _WRAPPER_OPERANDS.get(name, 0)
    return words[i:], folder


def _inner(words: list[str]) -> str | None:
    """The command string a shell runs with `-c`, also in a bundle such as `-lc` or
    `-ec`, or that `eval` runs."""
    name = compat.program(words[0])
    if name in _SHELLS:
        command = False
        i = 1
        while i < len(words):
            word = words[i]
            if word in _SHELL_VALUES:
                i += 2
                continue
            if word == "--":
                i += 1
                break
            if not word.startswith(("-", "+")) or word in ("-", "+"):
                break
            if re.fullmatch(r"-[A-Za-z]*c[A-Za-z]*", word):
                command = True
            i += 1
        return words[i] if command and i < len(words) else None
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
    setting, (un)installing, snapshot or restore, or stopping or discarding a library
    inspection. Reading commands, and `install` without --apply, which only shows the
    change, stay free."""
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
    return bool((sub in ("history", "restore", "clean", "install") and applies) or sub == "health"
                or (sub == "review" and (any(a in ("accept", "dismiss") for a in rest)
                    or any(a.startswith('--') and '--interactive'.startswith(a) for a in rest))) or sub == "uninstall"
                or (sub == "allow" and any(a not in ("--list", "-h", "--help") for a in rest))
                or (sub == "config" and len(words) >= 3)
                or (sub == "agent" and words[1:2] in (["snapshot"], ["restore"]))
                or (sub == "library" and (words[1:2] == ["cancel"] or any(
                    a.startswith('--') and '--restart'.startswith(a) for a in rest))))


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
            # Never below zero: a `case` pattern or a heredoc body can close more than it opens.
            depth = max(0, depth + {"(": 1, ")": -1}.get(tok, 0))
        else:
            words.append(tok)
        i += 1
    end(None)
    return out


class _Scope:
    """What one shell level may have seen: every folder entered and every value a variable
    was given. These only grow: a `cd` may fail, a branch may be skipped and `popd` may go
    back anywhere earlier, so following exactly which one took effect would risk missing a
    write. Checking every possibility can only add a question."""

    def __init__(self, cwds: list[str], env: dict[str, list[str]], lost: bool = False,
                 made: set[str] | None = None) -> None:
        self.cwds = cwds
        self.env = env
        self.lost = lost            # a folder decided at run time, or too many to follow
        self.made = made or set()   # folders `mkdir` may have created

    def copy(self) -> _Scope:
        return _Scope(list(self.cwds), {k: list(v) for k, v in self.env.items()}, self.lost, set(self.made))


UNKNOWN = "?/"   # prefix of a target whose folder is unknown; only its name can be checked
# Ends a file a copy writes only if its destination is a folder (`cp x/CLAUDE.md dest`):
# whether `dest` is one is known when the command is checked, not here.
INTO = "\1"


def write_targets(tokens: list[str], depth: int = 0) -> list[str]:
    """Paths a shell command writes to or deletes: redirect and tee targets, sed -i and
    perl -i files, the destination of cp/mv, rm arguments, git checkout/restore paths,
    curl/wget output files, files named by inline interpreter code that writes, and the
    same inside `bash -c` and `eval`. Folders entered and variables set earlier in the same
    command are followed. A target in a folder that cannot be known in advance is returned
    as UNKNOWN plus the path, so the caller can still judge it by name."""
    targets: list[str] = []
    scopes = [_Scope([""], {"HOME": ["~"]})]        # one per `( … )` level
    for words, redirects, before, after, level in _commands(tokens):
        while len(scopes) - 1 < level:
            scopes.append(scopes[-1].copy())
        del scopes[level + 1:]
        scope = scopes[-1]
        # A cd or assignment in a pipeline or in the background runs in a subshell of its own.
        lasting = before != "|" and after not in ("|", "&")
        body, runs_in = _unwrap_in(words)
        found: list[tuple[str, str]] = []           # (folder it is relative to, target)
        if body and compat.program(body[0]) in _CHANGE_DIR:
            operands = _cd_operands(body)
            # popd, and pushd +N, return to a folder already seen.
            if lasting and operands is not None:
                arg = operands[0] if operands else "~"
                values = [] if arg == "-" else _expand(arg, scope.env)
                # With CDPATH set, `cd name` may enter a folder under any of its entries.
                if not values or any(v.startswith(UNKNOWN) for v in values) or "CDPATH" in scope.env or any(
                        w.startswith("CDPATH=") for w in words):
                    scope.lost = True
                entered = [_under(cwd, v) for cwd in scope.cwds for v in values if not v.startswith(UNKNOWN)]
                scope.cwds, overflow = _bounded(scope.cwds + entered)
                scope.lost |= overflow
        elif _assignments(words):
            if lasting:
                for name, value in _assignments(words):
                    scope.env[name], overflow = _bounded(scope.env.get(name, []) + _expand(value, scope.env),
                                                         _MAX_VALUES)
                    if overflow:
                        scope.env[name] = [*scope.env[name][:_MAX_VALUES - 1], UNKNOWN]
        else:
            # Words are taken as written: the text of a `bash -c` script or of inline code is
            # parsed as it is, and targets are expanded below. Only a program named by a
            # variable needs expanding to know what it is.
            code = _code_positions(body)
            dynamic = bool(body) and ("$" in body[0] or compat.program(body[0]) in _OPTION_WRITERS and any(
                _may_be_option(w, scope.env) for i, w in enumerate(body) if i and i not in code))
            variants = [words] + (_word_variants(words, scope.env) if dynamic else [])
            if dynamic:
                # A program or option from a variable (`$C`, `sed $O`) may turn on writing, so
                # any of the command's arguments may be written.
                found += [(runs_in, a) for i, a in enumerate(body) if i and i not in code and not a.startswith("-")]
            for variant in variants:
                wrapped: list[tuple[str, str]] = []
                command, folder = _unwrap_in(variant, written=wrapped)
                found += wrapped
                inner = _inner(command) if command else None
                if inner is not None:
                    found += [(folder, t) for t in write_targets(split(inner), depth + 1)] if depth < _MAX_DEPTH else []
                elif command and command[0].startswith(UNKNOWN):
                    # A program named at run time could be anything that writes its arguments.
                    found += [(folder, a) for a in command[1:] if not a.startswith("-")]
                elif command and compat.program(command[0]) == "mkdir":
                    scope.made |= {posixpath.normpath(_under(cwd, v)) for a in command[1:] if not a.startswith("-")
                                   for v in map(_settle, _expand(_join(folder, a), scope.env))
                                   for cwd in scope.cwds}
                else:
                    trees = [w.partition("=")[2] for w in variant[:len(variant) - len(command)]
                             if w.startswith("GIT_WORK_TREE=")] + scope.env.get("GIT_WORK_TREE", [])
                    found += [(_join(folder, f), t) for f, t in _segment_targets(command, trees)]
        # A command's own redirections are opened before it runs, in the folder it starts in.
        for folder, raw in [("", r) for r in redirects] + found:
            for value in (v for e in _expand(raw, scope.env) for v in _within(folder, e, scope.env)):
                if value.endswith(INTO) and posixpath.normpath(posixpath.dirname(value)) in scope.made:
                    value = value.removesuffix(INTO)    # a folder made earlier in the command
                if value.startswith(UNKNOWN) or _relative(value) and scope.lost:
                    targets.append(UNKNOWN + value.removeprefix(UNKNOWN))
                if not value.startswith(UNKNOWN):
                    targets += [_under(cwd, value) for cwd in scope.cwds]
    return list(dict.fromkeys(t for t in targets if t != UNKNOWN))


def _cd_operands(words: list[str]) -> list[str] | None:
    """The folder a cd or pushd names, past its options (`cd -P dir`, `pushd -n dir`):
    an empty list for the home folder, None when it goes back to a folder already seen
    (`popd`, and `pushd +1`, which rotates the stack; for cd, `+1` is a folder name)."""
    name = compat.program(words[0])
    if name == "popd" or name == "pushd" and any(re.fullmatch(r"[+-]\d+", w) for w in words[1:2]):
        return None
    rest = words[1:]
    while rest and re.fullmatch(r"-[LPe@n]+", rest[0]):
        rest = rest[1:]
    if rest[:1] == ["--"]:
        rest = rest[1:]
    return rest[:1]


def _within(folder: str, value: str, env: dict[str, list[str]]) -> list[str]:
    """`value` taken from `folder`, with the folder's variables expanded."""
    if not folder or value.startswith(UNKNOWN) or not _relative(value):
        return [value]
    return [UNKNOWN + value if f.startswith(UNKNOWN) else _under(f, value)
            for f in map(_settle, _expand(folder, env))]


_CHANGE_DIR = {"cd", "pushd", "popd"}
_MAX_CWDS = 16
_MAX_VALUES = 8


def _relative(path: str) -> bool:
    return not path.startswith(("/", "~")) and not re.match(r"^[A-Za-z]:[\\/]", path)


def _bounded(values: list[str], limit: int = _MAX_CWDS) -> tuple[list[str], bool]:
    """At most `limit` distinct possibilities, keeping the first (where the command
    started), and whether any had to be dropped."""
    values = list(dict.fromkeys(values))
    if len(values) <= limit:
        return values, False
    return [values[0], *values[-(limit - 1):]], True


def _assignments(words: list[str]) -> list[tuple[str, str]]:
    """The variables a command made only of assignments (or `export` of them) sets."""
    while words and words[0] in _KEYWORDS:
        words = words[1:]
    rest = words[1:] if words[:1] == ["export"] else words
    if not rest or not all(_ASSIGN.match(w) for w in rest):
        return []
    return [(w.partition("=")[0], w.partition("=")[2]) for w in rest]


def _expand(word: str, env: dict[str, list[str]]) -> list[str]:
    """`word` with each variable replaced by each value it may have. A variable whose value is
    not known here (set outside the command, or too many possibilities) makes the result
    UNKNOWN plus whatever literal path follows it, which can still be judged by name."""
    names = list(dict.fromkeys(m.group(1) or m.group(2) for m in _VAR.finditer(word)))
    if not names:
        return [word]
    unknown = [UNKNOWN + _VAR.split(word)[-1].lstrip("/")]
    if any(n not in env for n in names):
        return unknown
    combos: list[dict[str, str]] = [{}]
    for name in names:
        combos = [{**c, name: v} for c in combos for v in env[name] if v != UNKNOWN]
        if len(combos) > _MAX_VALUES:
            return unknown
    # Known values stay alongside an unknown one: an earlier `F=$TMPDIR` must not hide `F=CLAUDE.md`.
    partly_unknown = any(UNKNOWN in env[n] for n in names)
    return [_fill(word, c) for c in combos] + (unknown if partly_unknown else [])


# Programs where an option alone decides whether named files are written (`sed -i`, `sort -o`).
_OPTION_WRITERS = {"sed", "perl", "ruby", "awk", "gawk", "git", "curl", "wget", "tar", "unzip", "patch", "rsync",
                   "cp", "mv", "ln", "install", "dd", "sort", "tee"}


def _may_be_option(word: str, env: dict[str, list[str]]) -> bool:
    """Whether a word with a variable in it may turn out to be an option."""
    return "$" in word and any(v.startswith(("-", UNKNOWN)) for v in _expand(word, env))


def _code_positions(words: list[str]) -> set[int]:
    """Positions of inline code (`bash -c`, `python -c`, `perl -e`, `sed -e`), whose `$` is the
    code's own, not this shell's."""
    return {i + 1 for i, w in enumerate(words[:-1])
            if w in ("-c", "-e", "-E", "--eval", "-r") or re.fullmatch(r"-[a-zA-Z]*e", w)}


def _fill(word: str, values: dict[str, str]) -> str:
    return _VAR.sub(lambda m: values[m.group(1) or m.group(2)], word)


def _word_variants(words: list[str], env: dict[str, list[str]]) -> list[list[str]]:
    """The command's words under each combination of variable values; past the limit, a word
    with several possible values is treated as unknown."""
    options = [_expand(w, env) for w in words]
    combos: list[list[str]] = [[]]
    for choices in options:
        combos = [c + [o] for c in combos for o in choices]
        if len(combos) > _MAX_VALUES:
            return [[o[0] if len(o) == 1 else UNKNOWN + _VAR.split(w)[-1].lstrip("/") for w, o in zip(words, options)]]
    return combos


def _under(cwd: str, target: str) -> str:
    if not cwd or target.startswith(("/", "~", "$")) or re.match(r"^[A-Za-z]:[\\/]", target):
        return target
    return f"{cwd.rstrip('/')}/{target}"


def _segment_targets(seg: list[str], work_trees: Sequence[str] = ()) -> list[tuple[str, str]]:
    """What a command writes, each with the folder it is relative to ("" for the folder
    the command runs in)."""
    if not seg:
        return []
    # Skip a trailing fd number left over from "2>&1" style redirects.
    args = [a for a in seg[1:] if not a.startswith("-") and not a.isdigit()]
    name = compat.program(seg[0])
    if name == "git":
        return _git_targets(seg[1:], work_trees)
    if name in _COPY_COMMANDS:
        return [("", t) for t in _copy_targets(name, seg[1:])]
    if name == "tee":
        found = args
    elif name == "sed" and any(a.startswith("-i") for a in seg[1:]):
        found = args[1:]
    elif name in _DELETE_COMMANDS:
        found = [a + TREE for a in args]
    elif name == "dd":
        found = [a[3:] for a in seg[1:] if a.startswith("of=")]
    elif name in ("curl", "wget"):
        found = _download_targets(name, seg[1:])
    elif name in _INTERPRETERS:
        found = _interpreter_targets(name, seg[1:])
    else:
        found = []
    return [("", t) for t in found]


# Copy options that take the next word as their value.
_COPY_VALUES = {
    "cp": {"-t", "-S", "--target-directory", "--suffix"},
    "mv": {"-t", "-S", "--target-directory", "--suffix"},
    "ln": {"-t", "-S", "--target-directory", "--suffix"},
    "install": {"-t", "-S", "-m", "-o", "-g", "--target-directory", "--suffix", "--mode", "--owner", "--group"},
    "rsync": {"-e", "-f", "-T", "--rsh", "--filter", "--exclude", "--include", "--exclude-from", "--include-from",
              "--files-from", "--temp-dir", "--backup-dir", "--suffix", "--chmod", "--chown", "--log-file"},
}
# rsync options whose value is a file it writes.
_COPY_WRITES = {"--log-file", "--write-batch", "--only-write-batch"}


def _copy_targets(name: str, args: list[str]) -> list[str]:
    """What a copy, move or link writes: its destination, and each source's name inside it
    when that is a folder (`cp x/CLAUDE.md .`, `cp -t .claude x/settings.json`). A folder
    copied or moved into it replaces what is under that name."""
    values = _COPY_VALUES.get(name, set())
    operands: list[str] = []
    written: list[str] = []
    folder = None
    recursive = name in ("mv", "rsync")
    i = 0
    while i < len(args):
        word = args[i]
        if word == "--":
            operands += args[i + 1:]
            break
        if word.startswith("-") and word != "-":
            options, used = _options(args, i, values)
            for option, value in options:
                if option in ("-t", "--target-directory") and name != "rsync" and value:
                    folder = value
                recursive |= option in ("-r", "-R", "-a", "--recursive", "--archive")
                if option in _COPY_WRITES and name == "rsync" and value:
                    written.append(value)
            i += used
            continue
        if not word.isdigit():
            operands.append(word)
        i += 1
    if folder is None and len(operands) == 1 and name == "ln":
        folder = ""    # `ln -s x/CLAUDE.md` links CLAUDE.md here
    elif folder is None:
        if not operands:
            return written
        *sources, dest = operands
        if not sources:
            return [*written, dest]
        # Several sources, or a destination written as a folder, can only be a folder.
        certain = len(sources) > 1 or dest.endswith("/") or posixpath.basename(dest) in (".", "..")
        return [*written, dest, *(_inside(name, dest, s, recursive) + ("" if certain else INTO) for s in sources)]
    return [*written, *(_inside(name, folder, s, recursive) for s in operands)]


# BSD cp, as on macOS, copies what is in `src/` rather than the folder itself; GNU cp does not.
_BSD = sys.platform.startswith(("darwin", "freebsd", "openbsd", "netbsd"))


def _inside(program: str, folder: str, source: str, recursive: bool) -> str:
    """Where `source` lands when copied into `folder`. rsync copies what is in `src/`,
    not the folder itself."""
    contents = recursive and source.endswith("/") and (program == "rsync" or program == "cp" and _BSD)
    name = "." if contents else posixpath.basename(source.rstrip("/"))
    return (f"{folder.rstrip('/')}/{name}" if folder else name) + (TREE if recursive else "")


# Git options before the subcommand that take the next word as their value.
_GIT_VALUES = {"-C", "-c", "--git-dir", "--work-tree", "--namespace", "--super-prefix", "--config-env",
               "--attr-source"}


def _git_targets(args: list[str], work_trees: Sequence[str]) -> list[tuple[str, str]]:
    """Files a git checkout or restore writes, each with the folder it is relative to:
    `git -C .claude restore settings.json` writes .claude/settings.json. Given another work
    tree (`--work-tree`, GIT_WORK_TREE), a path may be relative to either folder."""
    folder = ""
    trees = list(work_trees)
    i = 0
    while i < len(args) and args[i].startswith("-"):
        name, eq, value = args[i].partition("=")
        if name in _GIT_VALUES and not eq:
            value = args[i + 1] if i + 1 < len(args) else ""
            i += 1
        i += 1
        if name == "-C" and value:
            folder = _join(folder, value)
        elif name == "--work-tree" and value:
            trees.append(_join(folder, value))
    return [(f, t + TREE) for t in _git_paths(args[i:]) for f in dict.fromkeys([folder, *trees])]


def _git_paths(args: list[str]) -> list[str]:
    sub = args[0] if args else ""
    if sub not in ("checkout", "restore"):
        return []
    rest = args[1:]
    options = rest[:rest.index("--")] if "--" in rest else rest
    if sub == "restore" and any(a in ("-S", "--staged") for a in options) and not any(
            a in ("-W", "--worktree") for a in options):
        return []  # the index only
    if "--" in rest:
        return rest[rest.index("--") + 1:]
    if sub == "checkout":
        # Without `--` a word may be a branch; `.` and `./…` can only be paths.
        return [a for a in rest if a == "." or a.startswith("./")]
    if sub == "restore":
        skip = {i + 1 for i, a in enumerate(rest) if a in ("-s", "--source")}
        return [a for i, a in enumerate(rest) if not a.startswith("-") and i not in skip]
    return []


def _download_targets(name: str, args: list[str]) -> list[str]:
    short, long = ("o", "--output") if name == "curl" else ("O", "--output-document")
    out = []
    for i, a in enumerate(args):
        # Short options bundle (`-sSLo file`), and the value may follow the letter (`-ofile`).
        bundle = re.fullmatch(rf"-[A-Za-z]*?{short}(.*)", a) if not a.startswith("--") else None
        if bundle and bundle.group(1):
            out.append(bundle.group(1))
        elif (bundle or a == long) and i + 1 < len(args):
            out.append(args[i + 1])
        elif a.startswith(long + "="):
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


_HEREDOC = re.compile(r"(?<!<)<<-?\s*(['\"]?)([A-Za-z_][A-Za-z0-9_]*)\1")


def heredocs(command: str) -> tuple[str, list[tuple[str, str]]]:
    """The command without its heredoc bodies, and each body with the line that feeds it.
    A body is data unless the command reading it is a shell or an interpreter."""
    lines = command.split("\n")
    kept: list[str] = []
    bodies: list[tuple[str, str]] = []
    i = 0
    while i < len(lines):
        line = lines[i]
        kept.append(line)
        i += 1
        for m in _HEREDOC.finditer(line):
            body: list[str] = []
            while i < len(lines) and lines[i].strip() != m.group(2):
                body.append(lines[i])
                i += 1
            i += 1
            bodies.append((line, "\n".join(body)))
    return "\n".join(kept), bodies


def heredoc_targets(bodies: list[tuple[str, str]]) -> tuple[list[str], bool]:
    """Write targets in heredoc bodies fed to a shell, and whether such a body changes
    AgentDetox."""
    targets: list[str] = []
    changes = False
    for line, body in bodies:
        for words, _, _, _, _ in _commands(split(line)):
            if "<<" not in words and "<<-" not in words:
                continue
            command = _unwrap(words)
            name = compat.program(command[0]) if command else ""
            # A script fed to an interpreter is too varied to judge from its text (it may only
            # mention CLAUDE.md); the check after the command sees what it wrote.
            if name in _SHELLS:
                targets += write_targets(split(body), 1)
                changes |= changes_agentdetox(split(body), 1)
    return targets, changes


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
