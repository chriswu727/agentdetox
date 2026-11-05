"""Explicit removal of added lines, preserving unselected bytes and later edits."""

from __future__ import annotations

import difflib
import re
from dataclasses import dataclass

from .integrity import StoreError

MAX_BYTES = 1_000_000
MAX_LINES = 10_000


@dataclass
class Plan:
    added: dict[int, bytes]
    selected: list[int]
    current_lines: list[int]
    content: bytes


def text_lines(data: bytes) -> list[bytes]:
    if len(data) > MAX_BYTES:
        raise StoreError('Selective cleanup supports files up to 1 MB; inspect this file manually')
    try:
        data.decode('utf-8')
    except UnicodeDecodeError:
        raise StoreError('Selective cleanup requires UTF-8 text; no file was changed') from None
    if b'\0' in data:
        raise StoreError('Selective cleanup does not support binary content')
    # Split on LF only: bytes.splitlines also treats lone CR as a line boundary.
    lines = data.split(b'\n')
    lines = [line + b'\n' for line in lines[:-1]] + ([lines[-1]] if lines[-1] else [])
    if len(lines) > MAX_LINES:
        raise StoreError('Selective cleanup supports at most 10000 lines; inspect this file manually')
    return lines


def selection(value: str, limit: int) -> list[int]:
    chosen: set[int] = set()
    for part in value.split(','):
        if not re.fullmatch(r'[1-9][0-9]*(?:-[1-9][0-9]*)?', part):
            raise ValueError('Use added line numbers such as --lines 3,5-7')
        ends = [int(n) for n in part.split('-')]
        first, last = ends[0], ends[-1]
        if not 1 <= first <= last <= limit:
            raise ValueError(f'Line selection must be within 1-{limit}, in ascending ranges')
        chosen.update(range(first, last + 1))
    return sorted(chosen)


def plan(before: bytes, after: bytes, current: bytes, lines: str | None = None) -> Plan:
    old, recorded, now = (text_lines(data) for data in (before, after, current))
    added = {j + 1: recorded[j]
             for tag, _, _, start, end in difflib.SequenceMatcher(None, old, recorded, autojunk=False).get_opcodes()
             if tag in ('insert', 'replace') for j in range(start, end)}
    selected = selection(lines, len(recorded)) if lines is not None else []
    if any(n not in added for n in selected):
        raise ValueError('Select only lines added or replaced by this change; existing lines cannot be removed')
    mapping = {i + 1: j + 1 for block in difflib.SequenceMatcher(None, recorded, now, autojunk=False).get_matching_blocks()
               for i, j in zip(range(block.a, block.a + block.size), range(block.b, block.b + block.size))}
    if any(n not in mapping for n in selected):
        raise StoreError('Selected lines were edited or removed later; inspect the current file and latest change')
    if current != after:
        for n in selected:
            # An exact match is insufficient when repeated lines allow several possible alignments.
            if recorded.count(recorded[n - 1]) != 1 or now.count(recorded[n - 1]) != 1:
                raise StoreError('Selected lines have ambiguous repeated matches; inspect the current file manually')
    removed = {mapping[n] for n in selected}
    content = b''.join(line for n, line in enumerate(now, 1) if n not in removed)
    return Plan(added, selected, sorted(removed), content)
