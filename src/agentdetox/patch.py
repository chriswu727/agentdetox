"""What a Codex apply_patch call does to each file it names.

The envelope is the one Codex's own tool reads:

    *** Begin Patch
    *** Add File: <path>          every following line starts with "+"
    *** Delete File: <path>
    *** Update File: <path>
    *** Move to: <path>           optional, straight after Update File
    @@ [a line to look for first] optional before the first hunk of a file
     context / -removed / +added
    *** End of File               optional: the hunk sits at the end of the file
    *** End Patch

Hunks are placed as Codex places them: each after the one before, looking for its context
and removed lines exactly, then ignoring trailing blanks, then leading ones too, then with
look-alike punctuation folded; a hunk with nothing to look for goes at the end of the file.

The bytes written are the tool's too, as its own apply_patch (codex-cli 0.167) was seen to
write them: a line the patch leaves alone or names as context stays as the file has it,
spelling and line ending both, even where the patch spells it differently; an added line
takes the file's first line ending (CRLF, LF or a lone CR; LF in a file with none); the last
line always ends in one. A new file is written with LF.

A patch that does not fit the file as it is now (Codex would reject it) or that uses
anything outside this grammar is not guessed at: the change carries a `problem`, and its
content after is the content before (for a move, of the file being moved) with the added
lines appended, so that both what the patch adds and what it would carry along are still
checked.
"""

from __future__ import annotations

import os
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path

BEGIN, END = "*** Begin Patch", "*** End Patch"
_ADD, _DELETE, _UPDATE, _MOVE, _EOF = "*** Add File: ", "*** Delete File: ", "*** Update File: ", "*** Move to: ", "*** End of File"


@dataclass
class FileChange:
    path: Path
    old: str | None       # the file's content now; None when there is no such file
    new: str | None       # its content after the patch; None when the patch removes it
    problem: str = ""     # why `new` is a guess and not what the patch would write


@dataclass
class _Hunk:
    context: str | None = None
    # Its lines in order, each with what it is: " " context, "-" removed, "+" added.
    lines: list[tuple[str, str]] = field(default_factory=list)
    at_end: bool = False

    @property
    def old(self) -> list[str]:
        return [text for kind, text in self.lines if kind != "+"]


def _read(path: Path) -> str | None:
    try:
        # Bytes, so that a file's own line endings stay as the tool would leave them.
        return path.read_bytes().decode("utf-8", errors="replace") if path.is_file() else None
    except OSError:
        return None


class PatchError(ValueError):
    """The text is in a patch envelope but names no file in any way this module reads."""


def _lines(text: str) -> list[str]:
    # As the tool splits them: on line feeds only. str.splitlines also breaks at form feeds
    # and Unicode separators, which would let one added line pass for two patch lines.
    return [line[:-1] if line.endswith("\r") else line for line in text.split("\n")]


def changes(patch: str, base: Path, read: Callable[[Path], str | None] = _read) -> list[FileChange]:
    """One FileChange per file the patch touches, in the order it first names them. A file
    named twice is changed twice; a moved file is removed at its old path and written at its
    new one."""
    lines = _lines(patch.strip())
    start = next((i for i, line in enumerate(lines) if line.strip() == BEGIN), None)
    if start is None:
        return []
    lines = lines[start + 1:]
    # The envelope closes at its last end marker; a shell wrapper's own closing line follows it.
    last = max((i for i, line in enumerate(lines) if line.strip() == END), default=None)
    if last is not None:
        lines = lines[:last]
    now: dict[Path, str | None] = {}          # content as the patch has left it so far
    first: dict[Path, str | None] = {}
    problems: dict[Path, str] = {}

    def resolve(text: str) -> Path:
        path = Path(text.strip())
        return Path(os.path.normpath(path if path.is_absolute() else base / path))

    def current(path: Path) -> str | None:
        if path not in now:
            now[path] = first[path] = read(path)
        return now[path]

    def fail(path: Path, why: str, added: list[str], source: str | None = None) -> None:
        """Keep what the patch adds in view when the rest of it cannot be modelled: the file
        is taken to end up holding all it holds now (or all `source` holds, for a move that
        would bring that along) and every added line."""
        current(path)
        before = source if source is not None else now[path]
        problems.setdefault(path, why)
        now[path] = (before or "") + ("\n" if before and not before.endswith("\n") else "") + "".join(
            line + "\n" for line in added)

    i = 0
    while i < len(lines):
        line = lines[i].strip()   # the tool trims the line that opens a file's section
        if line.startswith(_ADD):
            path = resolve(line[len(_ADD):])
            i += 1
            added = []
            while i < len(lines) and lines[i].startswith("+"):
                added.append(lines[i][1:])
                i += 1
            current(path)
            now[path] = "".join(text + "\n" for text in added)
        elif line.startswith(_DELETE):
            path = resolve(line[len(_DELETE):])
            current(path)
            now[path] = None
            i += 1
        elif line.startswith(_UPDATE):
            path = resolve(line[len(_UPDATE):])
            i += 1
            target = None
            if i < len(lines) and lines[i].strip().startswith(_MOVE):
                target = resolve(lines[i].strip()[len(_MOVE):])
                i += 1
            body = []
            while i < len(lines) and (lines[i] == "" or lines[i][0] in " +-" or lines[i] == "@@"
                                      or lines[i].startswith("@@ ") or lines[i].strip() == _EOF):
                body.append(lines[i])
                i += 1
            hunks, why = _hunks(body)
            before = current(path)
            after = None
            if not why and before is None:
                why = "it updates a file that does not exist"
            if not why:
                assert before is not None
                after, why = _apply(before, hunks)
            destination = target if target is not None else path
            if why:
                fail(destination, why, [text[1:] for text in body if text.startswith("+")],
                     before if destination != path else None)
                problems.setdefault(path, why)
            else:
                current(destination)
                now[destination] = after
                if destination != path:
                    now[path] = None
        else:
            # Outside the grammar: what follows cannot be attributed to a file with any
            # confidence, so every file the patch names anywhere is given all it adds.
            why = f"the patch has a line AgentDetox does not understand: {lines[i][:60]!r}"
            added = [text[1:] for text in lines if text.startswith("+")]
            named = [resolve(text.strip()[len(header):]) for text in lines for header in (_ADD, _DELETE, _UPDATE, _MOVE)
                     if text.strip().startswith(header)]
            if not named:
                raise PatchError(why)
            for path in dict.fromkeys(named):
                fail(path, why, added)
            break
    return [FileChange(path, first[path], after, problems.get(path, "")) for path, after in now.items()
            if after != first[path] or path in problems]


def _hunks(body: list[str]) -> tuple[list[_Hunk], str]:
    hunks: list[_Hunk] = []
    for line in body:
        if line == "@@" or line.startswith("@@ "):
            hunks.append(_Hunk(context=line[3:] if line.startswith("@@ ") else None))
            continue
        if line.strip() == _EOF:
            if not hunks:
                return [], "it marks the end of the file before any change"
            hunks[-1].at_end = True
            continue
        if not hunks:
            hunks.append(_Hunk())  # the first hunk of a file may come without @@
        hunk = hunks[-1]
        if line == "":
            hunk.lines.append((" ", ""))
        elif line[0] in " -+":
            hunk.lines.append((line[0], line[1:]))
        else:
            return [], f"a hunk has a line that is neither context, removal nor addition: {line[:60]!r}"
    if not hunks or any(not h.lines for h in hunks):
        return [], "it has an Update File section without a change"
    return hunks, ""


# What the tool folds before its last attempt to place a hunk: dashes, curly quotes and
# unusual spaces typed for their ASCII look-alikes.
_FOLDED = str.maketrans({
    **dict.fromkeys("\u2010\u2011\u2012\u2013\u2014\u2015\u2212", "-"),
    **dict.fromkeys("\u2018\u2019\u201a\u201b", "'"),
    **dict.fromkeys("\u201c\u201d\u201e\u201f", '"'),
    **dict.fromkeys("\u00a0\u2002\u2003\u2004\u2005\u2006\u2007\u2008\u2009\u200a\u202f\u205f\u3000", " "),
})


def _seek(lines: list[str], wanted: list[str], start: int, at_end: bool) -> int | None:
    """Where `wanted` occurs in `lines` at or after `start`: exactly, else ignoring trailing
    blanks, else ignoring leading blanks too, else with look-alike punctuation folded as
    well. A hunk marked as the file's end is tried there first."""
    if not wanted:
        return start
    if len(wanted) > len(lines):
        return None
    last = len(lines) - len(wanted)
    order = ([last] if at_end and last >= start else []) + list(range(start, last + 1))
    for same in (lambda a, b: a == b, lambda a, b: a.rstrip() == b.rstrip(), lambda a, b: a.strip() == b.strip(),
                 lambda a, b: a.strip().translate(_FOLDED) == b.strip().translate(_FOLDED)):
        for i in order:
            if all(same(lines[i + k], wanted[k]) for k in range(len(wanted))):
                return i
    return None


_ENDING = re.compile(r"\r\n|\n|\r")


def _apply(text: str, hunks: list[_Hunk]) -> tuple[str | None, str]:
    # Each line of the file with its own ending; "" for a last line that has none. An ending
    # of None marks a line the patch adds, which takes the file's.
    lines: list[tuple[str, str | None]] = []
    start = 0
    for ending in _ENDING.finditer(text):
        lines.append((text[start:ending.start()], ending.group()))
        start = ending.end()
    if start < len(text):
        lines.append((text[start:], ""))
    file_ending = lines[0][1] or "\n" if lines else "\n"
    content = [line for line, _ in lines]
    replacements: list[tuple[int, int, list[tuple[str, str | None]]]] = []
    position = 0
    for hunk in hunks:
        if hunk.context is not None:
            found = _seek(content, [hunk.context], position, False)
            if found is None:
                return None, f"the file has no line {hunk.context[:60]!r} for a hunk to start from"
            position = found + 1
        steps = hunk.lines
        if not hunk.old:
            replacements.append((len(lines), 0, [(added, None) for _, added in steps]))
            continue
        found = _seek(content, hunk.old, position, hunk.at_end)
        if found is None and hunk.old[-1] == "":
            # The hunk ends in an empty line the file does not have there (it stood for the
            # final newline). The tool then stops looking for that line but, when it was
            # context, still writes it, as a blank line of the patch's own; and it drops one
            # empty line from the end of what it writes, if there is one.
            last = max(i for i, (kind, _) in enumerate(steps) if kind != "+")
            steps = steps[:last] + ([("+", "")] if steps[last][0] == " " else []) + steps[last + 1:]
            kept = [i for i, (kind, _) in enumerate(steps) if kind != "-"]
            if kept and steps[kept[-1]][1] == "":
                steps = steps[:kept[-1]] + steps[kept[-1] + 1:]
            found = _seek(content, [line for kind, line in steps if kind != "+"], position, hunk.at_end)
        if found is None:
            return None, "a hunk's context and removed lines are not in the file as it is now"
        written: list[tuple[str, str | None]] = []
        at = found
        for kind, line in steps:
            if kind == "+":
                written.append((line, None))
            else:
                if kind == " ":
                    written.append(lines[at])   # the file's own line, not the patch's spelling of it
                at += 1
        replacements.append((found, at - found, written))
        position = at
    for index, count, new in sorted(replacements, key=lambda r: r[0], reverse=True):
        lines[index:index + count] = new
    return "".join(line + (ending or file_ending) for line, ending in lines), ""


def touched(patch: str, response: object, base: Path) -> list[Path]:
    """Every path a finished patch may have written, removed or moved: those its sections
    name, and those Codex's own result lists ("M AGENTS.md")."""
    paths: list[Path] = []

    def add(text: str) -> None:
        path = Path(text.strip())
        paths.append(Path(os.path.normpath(path if path.is_absolute() else base / path)))

    for line in _lines(patch):
        for header in (_ADD, _DELETE, _UPDATE, _MOVE):
            if line.strip().startswith(header):
                add(line.strip()[len(header):])
    if isinstance(response, str):
        for line in _lines(response):
            if len(line) > 2 and line[0] in "AMD" and line[1] == " ":
                add(line[2:])
    return list(dict.fromkeys(paths))
