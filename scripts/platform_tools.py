"""Executable discovery for development and acceptance runners."""

import os
import shutil
from pathlib import Path


def git_bash() -> str:
    """Use Git for Windows, never the unrelated WSL bash.exe launcher."""
    if os.name != 'nt':
        return shutil.which('bash') or 'bash'
    candidates = [Path(os.environ['CLAUDE_CODE_GIT_BASH_PATH'])] if os.environ.get('CLAUDE_CODE_GIT_BASH_PATH') else []
    if git := shutil.which('git'):
        candidates.append(Path(git).resolve().parent.parent / 'bin/bash.exe')
    for directory in ('ProgramFiles', 'LOCALAPPDATA'):
        if root := os.environ.get(directory):
            candidates.append(Path(root) / ('Programs/Git/bin/bash.exe' if directory == 'LOCALAPPDATA' else 'Git/bin/bash.exe'))
    for candidate in candidates:
        if candidate.is_file():
            return str(candidate)
    raise FileNotFoundError('Install Git for Windows or set CLAUDE_CODE_GIT_BASH_PATH to its bash.exe')
