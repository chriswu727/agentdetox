"""File access that a swapped parent directory cannot redirect.

A path names whatever its folders point at when it is used. Between a review and the
write that follows it, or between two steps of one recovery, a folder can be replaced by a
link to somewhere else, and a path-based write then lands in a file nobody reviewed. Where
the system allows it (POSIX), the folder holding a file is opened once, one component at a
time and never through a link the user could replace, and every later read, write, rename
and delete goes through that open folder. Elsewhere (Windows) the same checks are made on
the path before and after, which narrows the gap without closing it; `PINNED` says which.

This protects against redirection. It is not a compare-and-swap: a program running as the
same user can still change the file inside the pinned folder between the last check and
the rename, and that write is then only in the quarantine copy if it came before the copy.
"""

from __future__ import annotations

import contextlib
import os
import stat
import sys
from collections.abc import Callable, Iterator
from pathlib import Path

from .findings import printable
from .integrity import StoreError

PINNED = (sys.platform != "win32" and os.open in os.supports_dir_fd and os.rename in os.supports_dir_fd
          and os.stat in os.supports_dir_fd and os.unlink in os.supports_dir_fd
          and hasattr(os, "O_NOFOLLOW") and hasattr(os, "O_DIRECTORY"))
TEMP_PREFIX = ".agentdetox-restore-"
MAX_LINK_HOPS = 16
_BINARY = getattr(os, "O_BINARY", 0)
_CLOEXEC = getattr(os, "O_CLOEXEC", 0)
_NOFOLLOW = getattr(os, "O_NOFOLLOW", 0)
_DIRECTORY = getattr(os, "O_DIRECTORY", 0)
# Enough to pass through a folder that may be entered but not listed (mode 0711).
_SEARCH = getattr(os, "O_PATH", None) or getattr(os, "O_SEARCH", None)
# Windows names for links: a symbolic link and a junction. Other reparse points (cloud
# placeholders, deduplicated files) are ordinary content.
_LINK_TAGS = {0xA000000C, 0xA0000003}


class UnsafePath(StoreError):
    """The path cannot be used without going through a link, or no longer names the
    folder that was opened for it. `kind` says which part: "path" (a folder on the way),
    "symlink" or "not-regular" (the file itself)."""

    def __init__(self, message: str, kind: str = "path") -> None:
        super().__init__(message)
        self.kind = kind


class TooLarge(StoreError):
    """The file holds more than the caller is prepared to read; it was not read into memory."""


def open_dir(name: str | Path, dir_fd: int | None = None, *, listable: bool = False) -> int:
    """Open a folder itself, never what a link in its place points at."""
    flags = os.O_RDONLY | _DIRECTORY | _NOFOLLOW | _CLOEXEC
    try:
        return os.open(name, flags, dir_fd=dir_fd)
    except PermissionError:
        if listable or _SEARCH is None:
            raise
        return os.open(name, _SEARCH | _DIRECTORY | _NOFOLLOW | _CLOEXEC, dir_fd=dir_fd)


def is_link(name: str | Path, dir_fd: int | None = None) -> bool:
    try:
        found = os.stat(name, dir_fd=dir_fd, follow_symlinks=False) if dir_fd is not None else os.lstat(name)
    except OSError:
        return False
    return stat.S_ISLNK(found.st_mode) or getattr(found, "st_reparse_tag", 0) in _LINK_TAGS


def _system_link(name: str, dir_fd: int) -> bool:
    """A link the current user cannot replace: root's, in a folder only root may change
    (/tmp on macOS, /home on some Linux systems). Following it cannot be steered."""
    if sys.platform == "win32" or os.geteuid() == 0:
        return False
    link = os.stat(name, dir_fd=dir_fd, follow_symlinks=False)
    folder = os.fstat(dir_fd)
    return link.st_uid == 0 and folder.st_uid == 0 and not folder.st_mode & 0o022


def open_path(folder: Path, *, create: bool = False, system_links: bool = True, listable: bool = False) -> int | None:
    """An open descriptor for `folder`, reached one component at a time. A component that
    is a link is refused unless it is a system link, whose target is then walked the same
    way. None when a component is missing and `create` is off."""
    absolute = Path(os.path.abspath(folder))
    pending = list(absolute.parts[1:])
    fd = open_dir(absolute.anchor)
    walked: list[str] = [absolute.anchor]
    hops = 0
    try:
        while pending:
            name = pending.pop(0)
            last = not pending
            try:
                following = open_dir(name, fd, listable=listable and last)
            except FileNotFoundError:
                if not create:
                    os.close(fd)
                    return None
                with contextlib.suppress(FileExistsError):
                    os.mkdir(name, dir_fd=fd)
                following = open_dir(name, fd, listable=listable and last)
            except OSError:
                if not is_link(name, fd):
                    raise
                shown = printable(str(Path(*walked, name)))
                if not (system_links and _system_link(name, fd)):
                    raise UnsafePath(f"{shown} is a symbolic link; AgentDetox does not read or write through a "
                                     "folder link that could be pointed elsewhere. Use the real path") from None
                hops += 1
                if hops > MAX_LINK_HOPS:
                    raise UnsafePath(f"{shown} has too many levels of symbolic links") from None
                target = Path(os.readlink(name, dir_fd=fd))
                if target.is_absolute():
                    restart = open_dir(target.anchor)
                    os.close(fd)
                    fd, walked = restart, [target.anchor]
                    pending = list(target.parts[1:]) + pending
                else:
                    # Continued from the folder that holds the link; ".." is opened, not computed.
                    pending = [part for part in target.parts if part != "."] + pending
                continue
            os.close(fd)
            fd = following
            walked.append(name)
        return fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def open_beneath(root_fd: int, parts: list[str], *, listable: bool = False) -> int:
    """The folder `parts` below an open root, with no link followed at any level."""
    fd = os.dup(root_fd)
    try:
        for index, name in enumerate(parts):
            try:
                following = open_dir(name, fd, listable=listable and index == len(parts) - 1)
            except OSError:
                if is_link(name, fd):
                    raise UnsafePath(f"{printable('/'.join(parts[:index + 1]))} is a symbolic link") from None
                raise
            os.close(fd)
            fd = following
        return fd
    except BaseException:
        with contextlib.suppress(OSError):
            os.close(fd)
        raise


def open_regular(name: str | Path, dir_fd: int | None = None) -> int:
    """Open a regular file for reading, refusing a link, a pipe or a device in its place."""
    # O_NONBLOCK: opening a pipe someone put there must not wait for a writer.
    flags = os.O_RDONLY | _NOFOLLOW | _CLOEXEC | _BINARY | getattr(os, "O_NONBLOCK", 0)
    if dir_fd is None and is_link(name):
        raise UnsafePath(f"{printable(str(name))} is a symbolic link", "symlink")
    try:
        fd = os.open(name, flags, dir_fd=dir_fd)
    except FileNotFoundError:
        raise
    except OSError:
        if is_link(name, dir_fd):
            raise UnsafePath(f"{printable(str(name))} is a symbolic link", "symlink") from None
        raise
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise UnsafePath(f"{printable(str(name))} is not a regular file", "not-regular")
    return fd


def write_new(name: str | Path, data: bytes, dir_fd: int | None = None, mode: int = 0o600) -> None:
    """Create `name` with `data`, flushed to disk. Never writes into something that is
    already there, a link included."""
    fd = os.open(name, os.O_WRONLY | os.O_CREAT | os.O_EXCL | _NOFOLLOW | _CLOEXEC | _BINARY, 0o600, dir_fd=dir_fd)
    try:
        with os.fdopen(fd, "wb") as file:
            file.write(data)
            file.flush()
            os.fsync(file.fileno())
            if sys.platform != "win32":
                os.fchmod(file.fileno(), mode & 0o777)
        if sys.platform == "win32":
            os.chmod(name, mode & 0o777)
    except BaseException:
        with contextlib.suppress(OSError):
            os.unlink(name, dir_fd=dir_fd)
        raise


def read_all(name: str | Path, dir_fd: int | None = None, limit: int | None = None) -> bytes:
    """The file's bytes. With `limit`, never more than limit + 1 bytes are requested: a
    file over the limit, or one that grows past it while being read, raises TooLarge
    instead of filling memory."""
    with os.fdopen(open_regular(name, dir_fd), "rb") as file:
        if limit is None:
            return file.read()
        data = b"" if os.fstat(file.fileno()).st_size > limit else file.read(limit + 1)
        if len(data) > limit or os.fstat(file.fileno()).st_size > limit:
            raise TooLarge(f"{printable(str(name))} is larger than the {limit:,} bytes this operation reads; "
                           "it was left as it is")
        return data


def _linked_ancestor(path: Path) -> Path | None:
    return next((p for p in Path(os.path.abspath(path)).parents if is_link(p)), None)


class Pin:
    """One file, addressed through the open folder that holds it. With `limit`, every read
    through the pin, the first and each later check, refuses a file larger than that."""

    def __init__(self, path: Path, fd: int | None, reopen: Callable[[bool], int | None],
                 limit: int | None = None) -> None:
        self.path = path
        self.name = path.name
        self.limit = limit
        self._fd = fd
        self._reopen = reopen

    def _at(self) -> tuple[str | Path, int | None]:
        return (self.name, self._fd) if PINNED else (self.path, None)

    def _missing_folder(self) -> bool:
        return PINNED and self._fd is None

    def is_link(self) -> bool:
        return not self._missing_folder() and is_link(*self._at())

    def read(self) -> bytes | None:
        """The file's bytes, or None when it (or its folder) is not there."""
        if self._missing_folder():
            return None
        try:
            return read_all(*self._at(), self.limit)
        except FileNotFoundError:
            return None
        except TooLarge:
            raise TooLarge(f"{printable(str(self.path))} is larger than the {self.limit:,} bytes this operation "
                           "reads; it was left as it is") from None

    def mode(self) -> int:
        name, fd = self._at()
        return stat.S_IMODE(os.stat(name, dir_fd=fd, follow_symlinks=False).st_mode if fd is not None
                            else os.lstat(name).st_mode)

    def chmod(self, mode: int) -> None:
        if sys.platform != "win32" and PINNED:
            fd = open_regular(self.name, self._fd)
            try:
                os.fchmod(fd, mode)
            finally:
                os.close(fd)
        else:
            self.verify()
            os.chmod(self.path, mode)

    def ensure_folder(self) -> None:
        if self._missing_folder():
            self._fd = self._reopen(True)
        elif not PINNED:
            self.path.parent.mkdir(parents=True, exist_ok=True)
            self.verify()

    def stage(self, data: bytes, mode: int) -> str:
        """Write the replacement beside the file and return its name."""
        self.ensure_folder()
        temp = TEMP_PREFIX + os.urandom(8).hex()
        write_new(temp if PINNED else self.path.with_name(temp), data, self._fd, mode)
        return temp

    def commit(self, temp: str) -> None:
        if PINNED:
            os.replace(temp, self.name, src_dir_fd=self._fd, dst_dir_fd=self._fd)
        else:
            self.verify()
            os.replace(self.path.with_name(temp), self.path)

    def discard(self, temp: str) -> None:
        with contextlib.suppress(OSError):
            os.unlink(temp if PINNED else self.path.with_name(temp), dir_fd=self._fd)

    def unlink(self) -> None:
        if not PINNED:
            self.verify()
        os.unlink(self.name if PINNED else self.path, dir_fd=self._fd)

    def verify(self) -> None:
        """Refuse once the path no longer names the folder this pin holds: what was read or
        written through the pin is then not what the path shows."""
        if not PINNED:
            link = _linked_ancestor(self.path)
            if link is not None:
                raise UnsafePath(f"{printable(str(link))} is a symbolic link or junction; AgentDetox does not read or write "
                                 "through a folder link. Use the real path")
            return
        if self._fd is None:
            return
        try:
            now = self._reopen(False)
        except (OSError, StoreError):
            now = None
        try:
            if now is None or not os.path.samestat(os.fstat(now), os.fstat(self._fd)):
                raise UnsafePath(f"The folder holding {printable(str(self.path))} was moved or replaced while AgentDetox worked "
                                 "on it. Nothing was written at the path's new location; inspect the file, the "
                                 "folder's earlier location and the backup")
        finally:
            if now is not None:
                os.close(now)

    def close(self) -> None:
        if self._fd is not None:
            os.close(self._fd)
            self._fd = None


@contextlib.contextmanager
def pinned(path: Path, limit: int | None = None) -> Iterator[Pin]:
    """Pin the folder that holds `path`. Links the user could replace are refused in every
    parent; the file itself is never followed if it is a link."""
    path = Path(os.path.abspath(path))
    if PINNED:
        def reopen(create: bool) -> int | None:
            return open_path(path.parent, create=create)

        pin = Pin(path, reopen(False), reopen, limit)
    else:
        pin = Pin(path, None, lambda create: None, limit)
        pin.verify()
    try:
        yield pin
    finally:
        pin.close()


@contextlib.contextmanager
def pinned_beneath(root_fd: int, root: Path, parts: list[str], limit: int | None = None) -> Iterator[Pin]:
    """Pin a file below an already opened root; no link is followed below the root."""
    def reopen(create: bool) -> int | None:
        return open_beneath(root_fd, parts[:-1])

    pin = Pin(root.joinpath(*parts), reopen(False), reopen, limit)
    try:
        yield pin
    finally:
        pin.close()
