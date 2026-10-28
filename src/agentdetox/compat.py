"""What differs between POSIX and Windows: file locks, program names, hook quoting.

Callers read `compat.WINDOWS` at call time rather than importing it, so tests can
exercise the Windows branches on any machine.
"""

from __future__ import annotations

import contextlib
import os
import re
import shlex

try:
    import fcntl
except ImportError:
    fcntl = None
    import msvcrt

WINDOWS = os.name == "nt"


def try_lock(fd: int) -> bool:
    """Take an exclusive lock on an open file without waiting; False if another
    descriptor holds it, in this process or another."""
    if fcntl is not None:
        try:
            fcntl.flock(fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True
    os.lseek(fd, 0, os.SEEK_SET)
    try:
        msvcrt.locking(fd, msvcrt.LK_NBLCK, 1)
    except OSError:
        return False
    return True


def release(fd: int) -> None:
    """Unlock and close. Windows frees a lock left on a closed handle only when the
    system gets round to it, so the next process could still find it held."""
    if fcntl is None:
        with contextlib.suppress(OSError):
            os.lseek(fd, 0, os.SEEK_SET)
            msvcrt.locking(fd, msvcrt.LK_UNLCK, 1)
    os.close(fd)


def program(token: str) -> str:
    """The command name in a shell token: `/x/agentdetox`, `C:\\x\\AgentDetox.exe` and
    `agentdetox` all give "agentdetox". Case is dropped because macOS and Windows file
    systems ignore it, so `AGENTDETOX` runs the same program."""
    name = re.split(r"[\\/]", token)[-1].lower()
    return name[:-4] if name.endswith(".exe") else name


def native_path(path: str) -> str:
    """A path from a shell command, as Python must spell it: Git Bash on Windows writes
    C:\\x as /c/x, which Python would take as a relative path."""
    if WINDOWS and (drive := re.match(r"/([A-Za-z])(?=/|$)", path)):
        return f"{drive[1]}:{path[2:] or '/'}"
    return path


def quote_executable(path: str) -> str:
    # Hook commands go through a shell: POSIX sh on macOS and Linux, cmd.exe or Git
    # Bash on Windows, where only double quotes mean the same thing in both.
    return f'"{path}"' if WINDOWS else shlex.quote(path)


def hook_executable(command: str) -> str:
    """The program a hook command runs, undoing quote_executable."""
    if WINDOWS:
        return shlex.split(command, posix=False)[0].strip('"')
    return shlex.split(command)[0]
