"""A terminal review loop over the same version-checked actions as the CLI."""

from __future__ import annotations

import sys
from pathlib import Path

from . import review
from .integrity import StoreError


def run(*, global_scope: bool = False, **filters) -> int:
    if not sys.stdin.isatty():
        raise ValueError('--interactive needs a terminal; use review C<ID> and explicit action commands in scripts')
    if global_scope and filters.get('project'):
        raise ValueError('Choose global scope or a project')
    if not global_scope:
        filters['project'] = filters.get('project') or Path.cwd()
    page_number = filters.pop('page_number', 1)
    while True:
        data = review.page(**filters, page_number=page_number)
        print(review.render_page(data))
        choice = _read('Select a number, n next, p previous, or q quit: ')
        if choice == 'q':
            return 0
        if choice == 'n':
            page_number = min(page_number + 1, max(data['pages'], 1))
        elif choice == 'p':
            page_number = max(page_number - 1, 1)
        elif choice.isdigit() and 1 <= int(choice) <= len(data['rows']):
            row = data['rows'][int(choice) - 1]
            if data['group_by'] == 'file':
                print('Reviewing this file. Use q to return to the file list.')
                run(global_scope=global_scope, **{**filters, 'file': Path(row['path']), 'group_by': 'change'})
            else:
                _change(f"C{row['id']}")
            page_number = min(page_number, max(review.page(**filters)['pages'], 1))
        else:
            print('Choose an entry number, n, p or q.')


def _read(prompt: str) -> str:
    try:
        return input(prompt).strip().lower()
    except (EOFError, KeyboardInterrupt):
        return 'q'


def _change(change_id: str) -> None:
    try:
        print(review.detail(change_id))
        while True:
            choice = _read('a accept this version, d dismiss a finding, r preview recovery, b back: ')
            if choice in ('b', 'q'):
                return
            if choice == 'a':
                if _read(f'Accept only {change_id}? [y/N]: ') == 'y':
                    review.accept(change_id)
                    print(f'Accepted {change_id}.')
                    return
            elif choice == 'd':
                finding = _read('Finding id (F<ID>), or b back: ')
                if finding in ('b', 'q'):
                    continue
                review.dismiss(finding, change_id)
                print(f'Dismissed {finding.upper()}.')
                return
            elif choice == 'r':
                print(review.restore(change_id))
                if _read(f'Restore the version before {change_id}? [y/N]: ') == 'y':
                    print(review.restore(change_id, apply=True))
                    return
            else:
                print('Choose a, d, r or b.')
    except (ValueError, OSError, StoreError) as error:
        print(f'Action was not completed: {error}', file=sys.stderr)
