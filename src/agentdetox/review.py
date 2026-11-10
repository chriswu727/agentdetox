"""Review exact observed versions without granting permanent source trust."""

from __future__ import annotations

import contextlib
import difflib
import hashlib
import json
import os
import re
import time
import uuid
from collections import Counter
from pathlib import Path

from . import allowlist, cleanup, events, ledger, storage
from .agentscan import scan_text
from .context import classify, claude_memory_dir, display_path, is_hook_script, short_path
from .findings import finding_id, printable
from .integrity import (
    StoreError,
    baseline_entries,
    object_text,
    quarantine_copy,
    restore_object,
    store_dir,
    store_lock,
    store_object,
)
from .persistence import guarded_sections


def number(value: str, prefix: str = 'C') -> int:
    if not re.fullmatch(prefix + r'[1-9][0-9]*', value.upper()):
        raise ValueError(f'Expected a {prefix} id, such as {prefix}42')
    return int(value[1:])


def get(change_id: str) -> dict:
    with storage.connection() as db:
        row = db.execute('SELECT * FROM changes WHERE id=?', (number(change_id),)).fetchone() if db else None
        if row is None:
            raise ValueError(f'Unknown change {change_id}')
        return dict(row)


def _digest(path: Path) -> str | None:
    if path.is_symlink():
        raise StoreError(f'Symbolic links are not supported for review actions: {path}')
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def _pinned_digest(pin) -> str | None:
    """The hash of the file a safefs pin holds, read through its opened folder."""
    if pin.is_link():
        raise StoreError(f'Symbolic links are not supported for review actions: {pin.path}')
    data = pin.read()
    return hashlib.sha256(data).hexdigest() if data is not None else None


def _check_current(row: dict, settings: bool = False, pin=None) -> Path:
    path = Path(row['path'])
    digest = _pinned_digest(pin) if pin is not None else _digest(path)
    if digest != row['after_hash'] and not (settings and _same_settings(path, row['after_hash'])):
        raise StoreError(f'{path} changed after C{row["id"]}; inspect the latest file before taking action')
    return path


def _same_settings(path: Path, digest: str | None) -> bool:
    """A config file whose security-relevant sections are still those of `digest`. Agents
    rewrite their own config at every start (counters, caches), which must not make a
    reviewed version impossible to accept."""
    if path.suffix not in ('.json', '.toml') or digest is None or not path.is_file():
        return False
    return guarded_sections(path, path.read_text(encoding='utf-8', errors='replace')) == \
        guarded_sections(path, object_text(digest))


def list_changes(since: str | None = None, all_changes: bool = False) -> list[dict]:
    args = []
    where = '' if all_changes or since else " WHERE review_state='pending'"
    if since:
        if not re.fullmatch(r'[1-9][0-9]*d', since):
            raise ValueError('Use a duration such as --since 7d')
        where = ' WHERE ts>=?'
        args.append(time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - int(since[:-1]) * 86400)))
    with storage.connection() as db:
        if db is None:
            return []
        return [dict(r) for r in db.execute('SELECT * FROM changes' + where + ' ORDER BY id DESC LIMIT 200', args)]


def render_list(rows: list[dict], summary: bool = False) -> str:
    if not rows:
        return 'No changes in this period.' if summary else 'Nothing needs attention. Use `agentdetox review --since 7d` for recent changes.'
    counts = Counter(row['review_state'] for row in rows)
    lines = [f"{len(rows)} changes shown: " + ', '.join(f'{n} {state}' for state, n in sorted(counts.items())),
             'Recent context changes:' if summary else 'Changes needing attention:']
    for row in rows:
        data = json.loads(row['data'])
        operation = 'deleted' if row['after_hash'] is None else 'added' if row['before_hash'] is None else 'modified'
        lines.append(f"C{row['id']}  {row['review_state']:<10} {operation:<8} {short_path(row['path'])}")
        lines.append(f"    {data.get('actor') or data.get('origin', 'unknown')} · {row['ts']}")
    lines.append('Open a change: agentdetox review C<ID> (showing up to 200 changes).')
    return '\n'.join(lines)


def page(*, since: str | None = None, all_changes: bool = False, project: Path | None = None,
         file: Path | None = None, search: str = '', page_number: int = 1, page_size: int = 20,
         group_by: str = 'file') -> dict:
    if page_number < 1 or not 1 <= page_size <= 200:
        raise ValueError('Page must be positive; page size must be between 1 and 200')
    if group_by not in ('file', 'change'):
        raise ValueError('Group by file or change')
    clauses: list[str] = []
    args: list = []
    if not all_changes and not since:
        clauses.append("c.review_state='pending'")
    if since:
        if not re.fullmatch(r'[1-9][0-9]*d', since):
            raise ValueError('Use a duration such as --since 7d')
        clauses.append('c.ts>=?')
        args.append(time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - int(since[:-1]) * 86400)))
    if project:
        project = Path(os.path.abspath(project.expanduser()))
        roots = (project, claude_memory_dir(project))
        clauses.append('(' + ' OR '.join('substr(c.path, 1, ?)=?' for _ in roots) + ')')
        for root in roots:
            prefix = str(root) + os.sep
            args.extend((len(prefix), prefix))
    if file:
        target = file.expanduser()
        if not target.is_absolute():
            target = (project or Path.cwd()) / target
        clauses.append('c.path=?')
        args.append(os.path.abspath(target))
    if search:
        pattern = '%' + search.replace('\\', '\\\\').replace('%', '\\%').replace('_', '\\_') + '%'
        clauses.append("(c.path LIKE ? ESCAPE '\\' OR EXISTS "
                       "(SELECT 1 FROM findings f WHERE f.change_id=c.id AND f.reason LIKE ? ESCAPE '\\'))")
        args.extend((pattern, pattern))
    where = ' WHERE ' + ' AND '.join(clauses) if clauses else ''
    result: dict = dict(rows=[], page=page_number, page_size=page_size, pages=0, group_by=group_by,
                        total_changes=0, total_files=0, states={}, operations={}, project=str(project) if project else None)
    with storage.connection() as db:
        if db is None:
            return result
        if not db.in_transaction:
            db.execute('BEGIN')
        counts = db.execute('SELECT count(*), count(DISTINCT path) FROM changes c' + where, args).fetchone()
        result['total_changes'], result['total_files'] = counts
        result['states'] = {r[0]: r[1] for r in db.execute(
            'SELECT review_state, count(*) FROM changes c' + where + ' GROUP BY review_state', args)}
        operation = "CASE WHEN after_hash IS NULL THEN 'deleted' WHEN before_hash IS NULL THEN 'added' ELSE 'modified' END"
        result['operations'] = {r[0]: r[1] for r in db.execute(
            'SELECT ' + operation + ', count(*) FROM changes c' + where + ' GROUP BY 1', args)}
        total = result['total_files'] if group_by == 'file' else result['total_changes']
        result['pages'] = (total + page_size - 1) // page_size
        if group_by == 'file':
            query = '''SELECT c.path, count(*) AS change_count, max(c.id) AS id, max(c.ts) AS ts,
                sum(CASE WHEN c.review_state='pending' THEN 1 ELSE 0 END) AS pending_count
                FROM changes c''' + where + ' GROUP BY c.path ORDER BY max(c.id) DESC LIMIT ? OFFSET ?'
        else:
            query = 'SELECT c.* FROM changes c' + where + ' ORDER BY c.id DESC LIMIT ? OFFSET ?'
        result['rows'] = [dict(r) for r in db.execute(query, [*args, page_size, (page_number - 1) * page_size])]
        for row in result['rows']:
            row.update(_summary(db, row['id']))
    return result


_WRITERS = {'you': 'the agent, with your words', 'agent': 'the agent', 'external': 'outside the agent',
            'restored': 'restored by AgentDetox'}
_SEVERITY_RANK = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"


def _summary(db, change_id: int) -> dict:
    """What a change was, in a few words: who wrote it, its size, and its most serious open finding."""
    change = db.execute('SELECT * FROM changes WHERE id=?', (change_id,)).fetchone()
    data = json.loads(change['data'])
    origin = data.get('origin', '')
    if data.get('method') == 'selective-removal':
        writer = 'selected lines removed by AgentDetox'
    elif origin == 'copied' and data.get('source'):
        writer = f"copied by the agent from {data['source']}"
    elif origin == 'external' and data.get('method') == 'before-after':
        writer = 'during a shell command, writer unknown'
    else:
        writer = _WRITERS.get(origin, origin)
    added: int | None
    removed: int | None
    try:
        before, after = _object_text(change['before_hash']), _object_text(change['after_hash'])
        added, removed = _line_changes(before.splitlines(), after.splitlines())
    except StoreError:
        added = removed = None
    top = db.execute(f"SELECT severity, reason FROM findings WHERE change_id=? AND status='pending' "
                     f"ORDER BY {_SEVERITY_RANK}, id LIMIT 1", (change_id,)).fetchone()
    operation = ('deleted' if change['after_hash'] is None else 'added' if change['before_hash'] is None
                 else 'changed')
    return {'writer': writer, 'operation': operation, 'added': added, 'removed': removed,
            'finding': {'severity': top['severity'], 'reason': top['reason']} if top else None}


_DIFF_BUDGET = 4_000_000


def _line_changes(old: list[str], new: list[str]) -> tuple[int | None, int | None]:
    """How many lines a change added and removed; (None, None) when working it out would
    take too long. Comparing is quadratic in repeated lines, so the unchanged start and end
    are set aside first and what remains is compared only within a budget."""
    limit = min(len(old), len(new))
    head = 0
    while head < limit and old[head] == new[head]:
        head += 1
    tail = 0
    while tail < limit - head and old[-1 - tail] == new[-1 - tail]:
        tail += 1
    old, new = old[head:len(old) - tail], new[head:len(new) - tail]
    if len(old) * len(new) > _DIFF_BUDGET:
        return None, None
    opcodes = difflib.SequenceMatcher(None, old, new, autojunk=False).get_opcodes()
    return (sum(j2 - j1 for op, _, _, j1, j2 in opcodes if op in ('insert', 'replace')),
            sum(i2 - i1 for op, i1, i2, _, _ in opcodes if op in ('delete', 'replace')))


def _describe(row: dict) -> str:
    size = f" +{row['added']} −{row['removed']} lines" if row['added'] is not None else ''
    return f"C{row['id']} · {printable(row['writer'])} · {row['operation']}{size} · {row['ts'].replace('T', ' ')[:16]}"


def render_page(data: dict) -> str:
    scope = f" in {short_path(data['project'])}" if data['project'] else ''
    change_word = 'change' if data['total_changes'] == 1 else 'changes'
    file_word = 'file' if data['total_files'] == 1 else 'files'
    lines = [f"{data['total_changes']} {change_word} across {data['total_files']} {file_word}{scope}."]
    if not data['total_changes']:
        return lines[0] + '\nNothing matches. Use --since 7d to include recent quiet changes.'
    lines.append(', '.join(f'{n} {state}' for state, n in sorted(data['states'].items())) + '. ' +
                 ', '.join(f'{n} {operation}' for operation, n in sorted(data['operations'].items())) + '.')
    lines.append(f"Page {data['page']} of {data['pages']} · grouped by {data['group_by']}")
    for index, row in enumerate(data['rows'], 1):
        if data['group_by'] == 'file':
            change_word = 'change' if row['change_count'] == 1 else 'changes'
            lines.append(f"{index}. {display_path(row['path'])}  ({row['change_count']} {change_word}, "
                         f"{row['pending_count']} pending)")
            lines.append(f"   latest: {_describe(row)}")
        else:
            lines.append(f"{index}. [{row['review_state']}] {display_path(row['path'])}")
            lines.append(f"   {_describe(row)}")
        if row['finding']:
            lines.append(f"   {row['finding']['severity'].upper()}: {printable(row['finding']['reason'])}")
    if not data['rows']:
        lines.append('No entries on this page. Choose an earlier page.')
    if data['page'] < data['pages']:
        lines.append(f"Next page: repeat with --page {data['page'] + 1}.")
    lines.append('Open: agentdetox review C<ID>. Browse and act: add --interactive.')
    return '\n'.join(lines)


def detail(change_id: str) -> str:
    row = get(change_id)
    data = json.loads(row['data'])
    before = _object_text(row['before_hash'])
    after = _object_text(row['after_hash'])
    lines = [f"C{row['id']} · {short_path(row['path'])} · {row['review_state']}",
             f"Observed writer: {data.get('actor') or data.get('origin', 'unknown')}",
             f"Session: {data.get('session') or 'unknown'}; tool: {data.get('tool') or 'unknown'}",
             'Content attribution is evidence-based inference, not proof of authorship.']
    evidence = sorted({(s.get('attribution', 'unknown'), s.get('source', '')) for s in data.get('spans', [])})
    lines += [f'  {printable(str(what))}' + (f': {printable(str(source))}' if source else '') for what, source in evidence]
    if not evidence:
        lines.append(f"  {data.get('attribution', 'unknown')} ({data.get('method', 'legacy')})")
    lines += [printable(line) for line in
              difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile='before', tofile='after', lineterm='')]
    with storage.connection() as db:
        findings = db.execute('SELECT * FROM findings WHERE change_id=? ORDER BY id', (row['id'],)).fetchall()
    lines += [f"F{f['id']} [{f['severity']}, {f['status']}] {printable(f['reason'])}" for f in findings]
    try:
        _check_current(row)
    except StoreError:
        lines.append('STALE: the file no longer matches this change. Accept and whole-version restore refuse newer work; '
                     'selective cleanup requires unchanged, unambiguous selected lines.')
    recovery_label = 'Preview undo of this recovery' if data.get('origin') == 'restored' else 'Preview recovery'
    lines += [f'Accept only this version: agentdetox review accept C{row["id"]}',
              f'{recovery_label}: agentdetox restore C{row["id"]}',
              f'Inspect added lines for selective cleanup: agentdetox clean C{row["id"]}',
              'Dismiss one finding: agentdetox review dismiss F<ID>. This grants no permanent exception.']
    if data.get('cleanup'):
        action = data['cleanup']
        source = f"C{action['change']}" if action.get('change') is not None else action.get('library', 'a library file')
        lines.append(f"Selective cleanup of {source}, recorded lines "
                     + ','.join(map(str, action['lines'])) + '. Unselected content was preserved.')
    return '\n'.join(lines)


def accept(change_id: str) -> None:
    with store_lock(), storage.connection(write=True) as db:
        row = get(change_id)
        path = _check_current(row, settings=True)
        db.execute('UPDATE files SET accepted_hash=?, accepted_change=? WHERE path=?',
                   (row['after_hash'], row['id'], row['path']))
        db.execute("UPDATE changes SET review_state='accepted' WHERE id=?", (row['id'],))
        db.execute("UPDATE findings SET status='accepted' WHERE change_id=?", (row['id'],))
        if _digest(path) != row['after_hash'] and not _same_settings(path, row['after_hash']):
            raise StoreError('File changed while accepting; no approval was saved')
        events.record("review_accepted", change=change_id, path=row["path"])


def dismiss(finding_id: str, change_id: str | None = None) -> None:
    with storage.connection(write=True) as db:
        row = db.execute("SELECT change_id FROM findings WHERE id=? AND status='pending'", (number(finding_id, 'F'),)).fetchone()
        if row is None:
            raise ValueError(f'Unknown or already handled finding {finding_id}')
        if change_id is not None and row[0] != number(change_id):
            raise ValueError(f'{finding_id} belongs to a different change; no finding was dismissed')
        db.execute("UPDATE findings SET status='dismissed' WHERE id=?", (number(finding_id, 'F'),))
        pending = db.execute("SELECT 1 FROM findings WHERE change_id=? AND status='pending'", (row[0],)).fetchone()
        events.record("review_dismissed", finding=finding_id)
        if not pending:
            db.execute("UPDATE changes SET review_state='dismissed' WHERE id=?", (row[0],))


def accepted_versions() -> dict[str, str | None]:
    with storage.connection() as db:
        return {r['path']: r['accepted_hash'] for r in db.execute('SELECT path, accepted_hash FROM files WHERE accepted_change IS NOT NULL')} if db else {}


def pending_recovery_paths() -> set[str]:
    with storage.connection() as db:
        if db is None:
            return set()
        rows = db.execute("""SELECT DISTINCT c.path FROM changes c JOIN findings f ON f.change_id=c.id
            WHERE json_extract(c.data, '$.origin')='restored' AND f.status='pending' AND f.severity='high'""")
        return {row['path'] for row in rows}


def restore(change_id: str, apply: bool = False) -> str:
    from . import safefs

    with store_lock():
        row = get(change_id)
        with safefs.pinned(Path(row['path'])) as pin:
            path = _check_current(row, pin=pin)
            residual, warning = _residual(path, row['before_hash'])
            if not apply:
                return detail(change_id) + f'\nRestore the version before this change: agentdetox restore {change_id} --apply\nThe current version will be backed up; file permissions will be preserved. Recovery does not certify that a version is safe.' + warning
            mode = json.loads(row['data']).get('before_mode')
            if mode is None:
                mode = baseline_entries().get(str(path), {}).get('mode', 0o600)
            backup = _recover(path, row['before_hash'], row['after_hash'], mode, residual, row['id'], pin=pin)
            return f'Restored {short_path(str(path))}. Backup: {backup or "file was absent"}.' + warning


def clean(change_id: str, lines: str | None = None, *, apply: bool = False,
          expected_hash: str | None = None) -> dict:
    from . import safefs

    row = get(change_id)
    path = Path(row['path'])
    kinds = {cf.kind for root in path.parents if (cf := classify(path, project=root)) is not None}
    if not kinds or 'config' in kinds or is_hook_script(path):
        raise ValueError('Selective cleanup supports memory, instructions and skills, not executable config; '
                         'use restore or edit configuration with its own tool')
    kind = next(k for k in ('memory', 'instructions', 'skill') if k in kinds)
    if row['after_hash'] is None:
        raise ValueError('A deleted-file change has no added lines to clean; use restore')
    limit = cleanup.MAX_BYTES
    with safefs.pinned(path, limit) as pin:
        return clean_version(pin, kind, lambda _: (_object_bytes(row['before_hash'], limit),
                                                   _object_bytes(row['after_hash'], limit)),
                             f'C{row["id"]}', {'change': row['id']}, lines, apply=apply, expected_hash=expected_hash)


def clean_version(pin, kind: str, versions, label: str, source: dict, lines: str | None = None, *,
                  apply: bool = False, expected_hash: str | None = None, recheck=None) -> dict:
    """Preview or apply the removal of selected lines of one recorded version from the file
    `pin` holds. `versions`, given the file's bytes now, returns the version before the
    recorded one and the recorded one; `label` names it in messages and `source` in the record. Reading, planning and rule scans run without the
    store lock; applying takes it, checks the file (and `recheck`, the caller's own state)
    again, and only then starts the journalled recovery. The pin carries cleanup's size
    limit, so no read of the file, then or later in the recovery, takes in more than that."""
    path = pin.path
    if pin.is_link():
        raise StoreError(f'Symbolic links are not supported for review actions: {path}')
    current = pin.read()
    if current is None:
        raise StoreError('The file no longer exists; no cleanup was applied')
    digest = hashlib.sha256(current).hexdigest()
    if apply and (not lines or not expected_hash):
        raise ValueError('Preview with --lines first, then use the printed --expected-hash and --apply command')
    if expected_hash is not None and expected_hash != digest:
        raise StoreError('File changed after the cleanup preview; preview it again before applying')
    before, after = versions(current)
    plan = cleanup.plan(before, after, current, lines)
    target = plan.content.decode('utf-8')
    residual, warning = _residual_text(path, target, kind)
    result = dict(change=label, path=str(path), current_hash=digest,
                  added=[{'line': n, 'text': _cleanup_line(text)}
                         for n, text in plan.added.items()],
                  selected=plan.selected, current_lines=plan.current_lines,
                  diff='\n'.join(printable(line) for line in difflib.unified_diff(
                      [_cleanup_line(line) for line in cleanup.text_lines(current)],
                      [_cleanup_line(line) for line in cleanup.text_lines(plan.content)],
                      fromfile='current', tofile='after cleanup', lineterm='')),
                  warning=warning, applied=False, backup=None)
    if not apply:
        return result
    original_flags = {finding_id(f) for f in scan_text(str(path), str(path), current.decode('utf-8'), kind)}
    remaining_flags = {finding_id(f) for f in scan_text(str(path), str(path), target, kind)}
    with store_lock():
        if _pinned_digest(pin) != digest:
            raise StoreError('File changed after the cleanup preview; preview it again before applying')
        if recheck is not None:
            recheck()
        with storage.connection(write=True):
            # A store used only for library scans has no metadata yet, and content copies
            # without metadata read as a damaged store.
            pass
        backup = _recover(path, store_object(plan.content), digest, pin.mode(), residual, None,
                          cleanup_data={**source, 'lines': plan.selected,
                                        'resolved_flags': sorted(original_flags - remaining_flags)}, pin=pin)
    result.update(applied=True, backup=str(backup) if backup else None)
    return result


def _cleanup_line(line: bytes) -> str:
    return line.decode('utf-8').removesuffix('\r\n').removesuffix('\n')


def render_cleanup(data: dict) -> str:
    library = data.get('library')
    lines = [f"Selective cleanup of {data['change']} · {short_path(data['path'])}"]
    if data['applied']:
        lines += [f"Removed selected lines. Backup: {data['backup']}.",
                  'Unselected content was preserved. Review any remaining findings with `agentdetox '
                  + (f"library review {data['change']}`." if library else 'review`.')]
    elif not data['selected']:
        lines += ['Lines of the inspected version, which the file still is:' if library else
                  'Added or replaced lines in this recorded version (not current-file line numbers):']
        lines += [f"{item['line']:>5}  {printable(item['text'])}" for item in data['added']]
        lines += [f"Choose only unwanted lines: agentdetox clean {data['change']} --lines 3,5-7"
                  if data['added'] else 'This change has no added lines to clean.']
    else:
        chosen = ','.join(map(str, data['selected']))
        lines += [data['diff'],
                  f"Apply this preview: agentdetox clean {data['change']} --lines {chosen} "
                  f"--expected-hash {data['current_hash']} --apply"]
    lines.append('Cleanup removes selected lines; it does not restore replaced text or certify safety.')
    return '\n'.join(lines) + data['warning']


def restore_trusted(path: Path) -> str:
    """Put back the last trusted version of `path` (its snapshot checkpoint), through the same
    journalled, stale-checked recovery as `restore`."""
    from . import safefs

    with store_lock():
        entry = baseline_entries().get(str(path))
        if entry is None:
            raise KeyError(f'{path} is not in the snapshot')
        with safefs.pinned(path) as pin:
            if pin.is_link():
                raise StoreError(f'Cannot restore a symbolic link: {path}')
            current = _pinned_digest(pin)
            mode = entry.get('mode', 0o600)
            if current == entry['sha256']:
                if os.name != 'nt' and pin.mode() != mode & 0o777:
                    pin.chmod(mode & 0o777)
                    return f'Put back the permissions of {short_path(str(path))}; its content is the last trusted version.'
                return f'{short_path(str(path))} is already the last trusted version.'
            residual, warning = _residual(path, entry['sha256'])
            backup = _recover(path, entry['sha256'], current, mode, residual, None, pin=pin)
            return (f'Restored {short_path(str(path))}'
                    + (f' (previous version quarantined at {backup})' if backup else '') + '.' + warning)


def _residual(path: Path, target_hash: str | None) -> tuple[list, str]:
    """Rule findings that the version being restored still has, and the warning saying so."""
    target = _object_text(target_hash)
    return _residual_text(path, target)


def _residual_text(path: Path, target: str, kind: str | None = None) -> tuple[list, str]:
    if kind is None:
        cf = classify(path, project=path.parent)
        kind = cf.kind if cf else 'config' if path.suffix in ('.json', '.toml') else 'memory'
    residual = [f for f in allowlist.unsuppressed(scan_text(str(path), str(path), target, kind))
                if f.severity in ('medium', 'high')]
    warning = ('\nWARNING: the recovery version still has rule findings: ' +
               printable('; '.join(sorted({f.message for f in residual}))) + '. Restoring it does not clear these findings.') if residual else ''
    return residual, warning


def _recover(path: Path, target_hash: str | None, current_hash: str | None, mode: int, residual: list,
             change_id: int | None, *, cleanup_data: dict | None = None, pin=None) -> Path | None:
    """Replace `path`, now `current_hash`, with the stored `target_hash` version: journalled,
    refused if the file changes meanwhile, the current version kept in quarantine, and the
    result recorded in the same transaction. Every read and write of the file goes through
    one pinned folder (`pin`, or one opened here). Call with the store lock held."""
    from . import safefs

    operation = uuid.uuid4().hex
    backup_path = store_dir() / 'quarantine' / operation / 'content'
    with storage.connection(write=True) as db:
        db.execute('INSERT INTO operations(id, path, before_hash, after_hash, stage, backup) VALUES (?, ?, ?, ?, ?, ?)',
                   (operation, str(path), current_hash, target_hash, 'preparing', str(backup_path)))
    backup = None
    data: bytes | None = None
    source = None
    if cleanup_data:
        source = f"C{cleanup_data['change']}" if cleanup_data.get('change') is not None else cleanup_data['library']
    try:
        with contextlib.ExitStack() as stack:
            if pin is None:
                pin = stack.enter_context(safefs.pinned(path))
            original = pin.read()
            if (hashlib.sha256(original).hexdigest() if original is not None else None) != current_hash:
                raise StoreError('The file changed since it was checked; review it again')
            if original is not None:
                store_object(original)  # the recovery's own record must be reviewable and undoable
            if target_hash is not None:
                backup = restore_object(path, target_hash, mode, current_hash, backup_path.parent, pin)
            elif original is not None:
                backup = quarantine_copy(operation, original, path)
                if pin.is_link() or pin.read() != original:
                    raise StoreError('File changed during recovery; original was left in place')
                pin.unlink()
                pin.verify()
            with storage.connection(write=True) as db:
                data = pin.read()
                if (hashlib.sha256(data).hexdigest() if data is not None else None) != target_hash:
                    raise StoreError('File changed during recovery; inspect it and the backup')
                fields = {'method': 'selective-removal', 'cleanup': cleanup_data, 'before_mode': mode} if cleanup_data else {}
                entry = ledger.record(path, 'restored', current_hash, data, findings=residual, **fields)
                if entry is None:
                    raise StoreError('Could not record recovery')
                if change_id is not None:
                    db.execute("UPDATE changes SET review_state='restored' WHERE id=?", (change_id,))
                    db.execute("UPDATE findings SET status='restored' WHERE change_id=?", (change_id,))
                if cleanup_data:
                    if cleanup_data.get('change') is not None:
                        for flag in cleanup_data['resolved_flags']:
                            db.execute("UPDATE findings SET status='restored' WHERE change_id=? AND flag_id=? AND status='pending'",
                                       (cleanup_data['change'], flag))
                        pending = db.execute("SELECT 1 FROM findings WHERE change_id=? AND status='pending'",
                                             (cleanup_data['change'],)).fetchone()
                        if not pending:
                            db.execute("UPDATE changes SET review_state='restored' WHERE id=? AND review_state='pending'",
                                       (cleanup_data['change'],))
                    storage.append_event(db, {'ts': entry.ts, 'event': 'cleanup_applied', 'path': str(path),
                                              'change': source, 'lines': cleanup_data['lines'],
                                              'recovery': f'C{entry.id}'})
                checkpoint = db.execute('SELECT checkpoint FROM files WHERE path=?', (str(path),)).fetchone()
                if target_hash is None:
                    db.execute('UPDATE files SET checkpoint=NULL WHERE path=?', (str(path),))
                elif not cleanup_data and checkpoint and checkpoint[0] and not any(f.severity == 'high' for f in residual):
                    value = json.loads(checkpoint[0])
                    assert data is not None
                    value['sha256'] = store_object(data)
                    value['mode'] = mode
                    from .persistence import guarded_sections
                    value['sections'] = guarded_sections(path, data.decode('utf-8', errors='replace')) if value['kind'] == 'config' else {}
                    db.execute('UPDATE files SET checkpoint=? WHERE path=?', (json.dumps(value), str(path)))
                db.execute("UPDATE operations SET stage='completed', backup=? WHERE id=?", (str(backup) if backup else None, operation))
    except (OSError, StoreError) as e:
        with storage.connection(write=True) as db:
            db.execute("UPDATE operations SET stage='failed', backup=?, error=? WHERE id=?",
                       (str(backup_path), str(e), operation))
        raise
    return backup


def handled_findings() -> set[tuple[str, str | None, str]]:
    with storage.connection() as db:
        if db is None:
            return set()
        return {(r['path'], r['after_hash'], r['flag_id']) for r in db.execute(
            "SELECT c.path, c.after_hash, f.flag_id FROM findings f JOIN changes c ON c.id=f.change_id "
            "WHERE f.status IN ('dismissed', 'accepted')")}


def prune(older_than: str, apply: bool = False) -> dict:
    if not re.fullmatch(r'[1-9][0-9]*d', older_than):
        raise ValueError('Use a duration such as 90d')
    cutoff = time.strftime('%Y-%m-%dT%H:%M:%S', time.localtime(time.time() - int(older_than[:-1]) * 86400))
    with storage.connection(write=apply) as db:
        if db is None:
            return {'changes': 0, 'events': 0, 'applied': apply}
        query = """SELECT id FROM changes WHERE ts<? AND review_state IN ('recorded', 'dismissed', 'restored')
            AND id NOT IN (SELECT accepted_change FROM files WHERE accepted_change IS NOT NULL)
            AND id NOT IN (SELECT max(id) FROM changes GROUP BY path)
            AND id NOT IN (SELECT change_id FROM findings WHERE status='pending')"""
        count = db.execute('SELECT count(*) FROM (' + query + ')', (cutoff,)).fetchone()[0]
        event_query = "ts<? AND NOT (event='hook_error' AND resolved=0)"
        event_count = db.execute('SELECT count(*) FROM events WHERE ' + event_query, (cutoff,)).fetchone()[0]
        if apply:
            db.execute('DELETE FROM findings WHERE change_id IN (' + query + ')', (cutoff,))
            db.execute('DELETE FROM changes WHERE id IN (' + query + ')', (cutoff,))
            db.execute('DELETE FROM events WHERE ' + event_query, (cutoff,))
        return {'changes': count, 'events': event_count, 'applied': apply}


def _object_text(digest: str | None) -> str:
    return _object_bytes(digest).decode('utf-8', errors='replace')


def _object_bytes(digest: str | None, limit: int | None = None) -> bytes:
    if digest is None:
        return b''
    path = store_dir() / 'objects' / digest
    if not path.is_file():
        raise StoreError(f'Missing content object {digest}; cannot show a reliable diff')
    if limit is not None and path.stat().st_size > limit:
        raise StoreError('Selective cleanup supports files up to 1 MB; inspect this file manually')
    data = path.read_bytes()
    if hashlib.sha256(data).hexdigest() != digest:
        raise StoreError(f'Corrupt content object {digest}; cannot show a reliable diff')
    return data


def acknowledge_recovery(operation_id: str) -> None:
    with storage.connection(write=True) as db:
        row = db.execute('SELECT * FROM operations WHERE id=?', (operation_id,)).fetchone()
        if row is None:
            raise ValueError('Unknown recovery operation')
        current = _digest(Path(row['path']))
        if current not in (row['before_hash'], row['after_hash']):
            raise StoreError('File matches neither side of this recovery; inspect and resolve it before acknowledging')
        db.execute("UPDATE operations SET stage='acknowledged' WHERE id=?", (operation_id,))
        events.record('recovery_acknowledged', operation=operation_id, current=current)
