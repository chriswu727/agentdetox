"""Which file a path names, whatever it is spelled like.

A path can be written many ways that reach one file: another case on a file system that
ignores case, another Unicode form of the same name, a link, or macOS's second name for
the data volume (`/System/Volumes/Data/Users/…`). Comparing spellings lets any of them
past a check made for the others. These helpers compare what the file system says the
file is: the device and file number of the folders above it.
"""

from __future__ import annotations

import os
import sys
import unicodedata
from pathlib import Path

from . import budget

# macOS and Windows file systems ignore case by default.
CASELESS = sys.platform in ("darwin", "win32")

Identity = tuple[int, int]


def identity(path: Path | str) -> Identity | None:
    """What the file system calls the file at `path` (a link is followed), or None when
    there is none or it cannot be looked at."""
    try:
        found = os.stat(path)
    except (OSError, ValueError):
        return None
    return found.st_dev, found.st_ino


def ancestry(path: Path | str) -> dict[Identity, str]:
    """For `path` and every folder above it that exists, by identity: `path` relative to
    it, in `path`'s own spelling ("" for `path` itself). Links in the part that exists are
    followed first, so the folders are the ones the file really sits in."""
    if "\0" in os.fspath(path):
        return {}  # no file has this name; Windows' realpath returns it as it is instead of failing
    try:
        parts = Path(os.path.realpath(path)).parts
    except (OSError, ValueError):
        return {}
    found: dict[Identity, str] = {}
    folder = ""
    for count, part in enumerate(parts, 1):
        budget.check()
        folder = os.path.join(folder, part)
        key = identity(folder)
        if key is not None:
            found[key] = "/".join(parts[count:])  # the deepest folder of an identity wins
    return found


def inside(path: Path | str, folder: Path | str) -> bool:
    """Whether `path` is `folder` or lies below it, whether or not `path` exists yet."""
    key = identity(folder)
    if key is not None and key in ancestry(path):
        return True
    return _spelled_inside(path, folder)


def same(a: Path | str, b: Path | str) -> bool:
    """Whether two paths name one existing file or folder, or are spelled alike."""
    first, second = identity(a), identity(b)
    if first is not None and second is not None:
        return first == second
    return _parts(a) == _parts(b)


def _parts(path: Path | str) -> tuple[str, ...]:
    try:
        parts = Path(os.path.realpath(path)).parts
    except (OSError, ValueError):
        parts = Path(os.path.abspath(str(path).replace("\0", ""))).parts
    if CASELESS:
        return tuple(unicodedata.normalize("NFC", part).casefold() for part in parts)
    return parts


def _spelled_inside(path: Path | str, folder: Path | str) -> bool:
    """The comparison for a folder that does not exist: by spelling, folding case and
    Unicode form where the file system does."""
    parts, base = _parts(path), _parts(folder)
    return len(parts) >= len(base) and parts[:len(base)] == base
