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
from pathlib import Path

from . import allowlist, cleanup, events, judge, ledger, storage
from .agentscan import scan_stored, scan_text
from .context import classify, claude_memory_dir, display_path, is_hook_script, short_path
from .findings import finding_id, printable
from .hidden import normalize
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
    if not re.fullmatch(prefix + r'[1-9][0-9]{0,17}', value.upper()):
        raise ValueError(f'Expected a {prefix} id, such as {prefix}42')
    return int(value[1:])


def get(change_id: str) -> dict:
    with storage.connection() as db:
        row = db.execute('SELECT * FROM changes WHERE id=?', (number(change_id),)).fetchone() if db else None
        if row is None:
            raise ValueError(f'Unknown change {change_id}. `agentdetox review` lists the changes that need '
                             'attention, `agentdetox review --all` every recorded one')
        return dict(row)


INSPECTION = ledger.INSPECTION


def inspected(row: dict) -> bool:
    """Whether a record is of a version found as it was, not of a change: it has no earlier
    version, and every line of it can be chosen for cleanup."""
    return json.loads(row['data']).get('method') == INSPECTION


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
                        total_changes=0, total_files=0, states={}, operations={}, project=str(project) if project else None,
                        filtered=bool(since or all_changes or project or file or search))
    with storage.connection() as db:
        if db is None:
            return result
        if not db.in_transaction:
            db.execute('BEGIN')
        counts = db.execute('SELECT count(*), count(DISTINCT path) FROM changes c' + where, args).fetchone()
        result['total_changes'], result['total_files'] = counts
        result['states'] = {r[0]: r[1] for r in db.execute(
            'SELECT review_state, count(*) FROM changes c' + where + ' GROUP BY review_state', args)}
        operation = ("CASE WHEN after_hash IS NULL THEN 'deleted' WHEN before_hash IS NULL THEN 'added' "
                     f"WHEN json_extract(c.data, '$.method')='{INSPECTION}' THEN 'inspected' ELSE 'modified' END")
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
        sizes = []
        for row in result['rows']:
            summary, versions = _summary(db, row['id'])
            row.update(summary)
            sizes.append(versions)
    # Comparing two versions can take seconds. It is done with the database closed: a reader
    # that held it open this long made a hook's write wait, and then fail.
    for row, versions in zip(result['rows'], sizes):
        if versions is not None:
            row['added'], row['removed'] = _size(*versions)
    return result


_WRITERS = {'you': 'the agent, with your words', 'agent': 'the agent', 'external': 'outside the agent',
            'restored': 'restored by AgentDetox'}
_SEVERITY_RANK = "CASE severity WHEN 'high' THEN 0 WHEN 'medium' THEN 1 ELSE 2 END"


def _summary(db, change_id: int) -> tuple[dict, tuple[str | None, str | None] | None]:
    """What a change was, in a few words: who wrote it and its most serious open finding.
    Its size is left out; the versions to compare for it are returned beside, or None when
    it has no size to show."""
    change = db.execute('SELECT * FROM changes WHERE id=?', (change_id,)).fetchone()
    data = json.loads(change['data'])
    origin = data.get('origin', '')
    if data.get('method') == 'selective-removal':
        writer = 'selected lines removed by AgentDetox'
    elif data.get('method') == INSPECTION:
        writer = 'found as it was, earlier history unknown'
    elif origin == 'copied' and data.get('source'):
        writer = f"copied by the agent from {data['source']}"
    elif origin == 'external' and data.get('method') == 'before-after':
        writer = 'during a shell command, writer unknown'
    else:
        writer = _WRITERS.get(origin, origin)
    top = db.execute(f"SELECT severity, reason FROM findings WHERE change_id=? AND status='pending' "
                     f"ORDER BY {_SEVERITY_RANK}, id LIMIT 1", (change_id,)).fetchone()
    operation = ('deleted' if change['after_hash'] is None else 'added' if change['before_hash'] is None
                 else 'inspected' if data.get('method') == INSPECTION else 'changed')
    versions = None if data.get('method') == INSPECTION else (change['before_hash'], change['after_hash'])
    return {'writer': writer, 'operation': operation, 'added': None, 'removed': None,
            'finding': {'severity': top['severity'], 'reason': top['reason']} if top else None}, versions


def _size(before_hash: str | None, after_hash: str | None) -> tuple[int | None, int | None]:
    """Lines a change added and removed; (None, None) when a version is missing or comparing
    them would take too long."""
    try:
        before, after = _object_text(before_hash), _object_text(after_hash)
    except StoreError:
        return None, None
    return _line_changes(before.splitlines(), after.splitlines())


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
        if not data.get('filtered'):
            return 'Nothing needs review. `agentdetox review --since 7d` also lists recent changes that need none.'
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


def detail(change_id: str, restoring: bool = False) -> str:
    row = get(change_id)
    data = json.loads(row['data'])
    before = _object_text(row['before_hash'])
    after = _object_text(row['after_hash'])
    found = data.get('method') == INSPECTION
    lines = [f"C{row['id']} · {short_path(row['path'])} · {row['review_state']}",
             f"{'Found by' if found else 'Observed writer'}: {data.get('actor') or data.get('origin', 'unknown')}",
             f"Session: {data.get('session') or 'unknown'}; tool: {data.get('tool') or 'unknown'}",
             'Content attribution is evidence-based inference, not proof of authorship.']
    evidence = sorted({(s.get('attribution', 'unknown'), s.get('source', '')) for s in data.get('spans', [])})
    lines += [f'  {printable(str(what))}' + (f': {printable(str(source))}' if source else '') for what, source in evidence]
    if not evidence:
        lines.append(f"  {data.get('attribution', 'unknown')} ({data.get('method', 'legacy')})")
    where: dict[str, int] = {}
    model = _model_lines(after, row['id'])
    if found:
        lines.append('This records a version found as it was, not a change: AgentDetox has no earlier version of '
                     'the file, so there is no diff and nothing to restore.')
        # With no diff to show them, the flagged lines themselves.
        where = _flagged_lines(Path(row['path']), after)
        text = after.split('\n')
        lines += [f"{n:>5}  {printable(text[n - 1])}"
                  for n in sorted(set(where.values()) | {n for numbers in model.values() for n in numbers})]
    where = {**{flag: numbers[0] for flag, numbers in model.items()}, **where}
    lines += [printable(line) for line in
              difflib.unified_diff(before.splitlines(), after.splitlines(), fromfile='before', tofile='after', lineterm='')]
    with storage.connection() as db:
        findings = db.execute('SELECT * FROM findings WHERE change_id=? ORDER BY id', (row['id'],)).fetchall()
    lines += [f"F{f['id']} [{f['severity']}, {f['status']}] "
              + (f"line {where[f['flag_id']]}: " if f['flag_id'] in where else '') + printable(f['reason']) for f in findings]
    try:
        _check_current(row)
    except StoreError:
        lines.append('STALE: the file no longer matches this change. Accept and whole-version restore refuse newer work; '
                     'selective cleanup requires unchanged, unambiguous selected lines.')
    recovery_label = ('Preview undo of this recovery' if data.get('origin') == 'restored' else
                      'Preview removal of the file, which this change added' if row['before_hash'] is None else
                      'Preview recovery')
    lines.append(f'Accept only this version: agentdetox review accept C{row["id"]}')
    if data.get('method') == INSPECTION:
        lines.append(f'List its lines for selective cleanup: agentdetox clean C{row["id"]}')
    else:
        lines += ([] if restoring else [f'{recovery_label}: agentdetox restore C{row["id"]}']) + [
            f'Inspect added lines for selective cleanup: agentdetox clean C{row["id"]}']
    lines.append('Dismiss one finding: agentdetox review dismiss F<ID>. This grants no permanent exception.')
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


def finding_lines(text: str, findings: list) -> dict[str, int]:
    """The line of the inspected version each finding is on, where the flagged line can be
    found again: the number `agentdetox clean` takes."""
    lines = [" ".join(normalize(line).split()) for line in text.split("\n")]
    where: dict[str, int] = {}
    for finding in findings:
        # A model reads a text whole; the line it pointed at, if any, is the finding's evidence.
        named = finding.evidence if finding.detector == "judge" else finding.anchor
        wanted = next((" ".join(normalize(part).split()) for part in named.split("\n") if part.strip()), "")
        if not wanted:
            continue
        hits = [i for i, line in enumerate(lines, 1) if wanted in line]
        if len(hits) == 1:
            where[finding_id(finding)] = hits[0]
    return where


def _model_lines(text: str, change: int | None) -> dict[str, list[int]]:
    """Finding id to the lines of `text` a model pointed at, for the findings of a change
    that a model made and that can still be placed."""
    if change is None:
        return {}
    with storage.connection() as db:
        ids = [r['flag_id'] for r in db.execute('SELECT flag_id FROM findings WHERE change_id=?', (change,))] if db else []
    lines = [" ".join(normalize(line).split()) for line in text.split("\n")]
    where: dict[str, list[int]] = {}
    for flag_id in ids:
        said = judge.remembered(flag_id)
        for quoted in said.lines if said else ():
            wanted = " ".join(normalize(quoted).split())
            hits = [i for i, line in enumerate(lines, 1) if wanted and wanted in line]
            if len(hits) == 1:
                where.setdefault(flag_id, []).append(hits[0])
    return where


def _flagged_lines(path: Path, text: str, kind: str | None = None) -> dict[str, int]:
    """Finding id to line number, for the findings of `text` that can be placed on one line."""
    if kind is None:
        kinds = {cf.kind for root in path.parents if (cf := classify(path, project=root)) is not None}
        kind = next((k for k in ('memory', 'instructions', 'skill', 'config') if k in kinds), 'memory')
    found = [f for f in allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), text, kind))
             if f.severity in ('medium', 'high')]
    return finding_lines(text, found)


def restore(change_id: str, apply: bool = False) -> str:
    from . import safefs

    with store_lock():
        row = get(change_id)
        if inspected(row):
            raise ValueError(f'C{row["id"]} records a version found as it was, not a change: there is no earlier '
                             f'version to restore. Remove unwanted lines with `agentdetox clean C{row["id"]}`')
        with safefs.pinned(Path(row['path'])) as pin:
            path = _check_current(row, pin=pin)
            residual, warning = _residual(path, row['before_hash'])
            # There was no file before a change that added it: going back means removing it.
            removes = row['before_hash'] is None
            if not apply:
                data = json.loads(row['data'])
                undoes = ('This record is a cleanup: undoing it puts back the lines it removed'
                          if data.get('method') == 'selective-removal' else
                          'This record is a recovery: undoing it puts back the version it replaced')
                action = (f'This file did not exist before this change, so restoring REMOVES it: agentdetox restore {change_id} --apply\n'
                          f'To keep the file and take out chosen lines instead: agentdetox clean {change_id}\n'
                          'The current version will be backed up. ' if removes else
                          f'{undoes}. Apply it: agentdetox restore {change_id} --apply\n'
                          'The current version will be backed up; file permissions will be preserved. '
                          if data.get('origin') == 'restored' else
                          f'Restore the version before this change: agentdetox restore {change_id} --apply\n'
                          'The current version will be backed up; file permissions will be preserved. ')
                return (detail(change_id, restoring=True) + '\n' + action + 'Recovery does not certify that a version '
                        'is safe.' + warning)
            mode = json.loads(row['data']).get('before_mode')
            if mode is None:
                mode = baseline_entries().get(str(path), {}).get('mode')
            if mode is None:
                # No recorded permissions for that version: the file keeps the ones it has now,
                # as the preview says. A script that was executable stays executable.
                mode = _current_mode(pin)
            backup = _recover(path, row['before_hash'], row['after_hash'], mode, residual, row['id'], pin=pin)
            done = (f'Removed {short_path(str(path))}, which did not exist before C{row["id"]}.' if removes
                    else f'Restored {short_path(str(path))}.')
            return f'{done} Backup: {backup or "file was absent"}.' + warning


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
    # An inspected version has no version before it: all of its lines are open to cleanup.
    before = None if inspected(row) else row['before_hash']
    with safefs.pinned(path, limit) as pin:
        result = clean_version(pin, kind, lambda _: (_object_bytes(before, limit),
                                                     _object_bytes(row['after_hash'], limit)),
                               f'C{row["id"]}', {'change': row['id']}, lines, apply=apply, expected_hash=expected_hash)
    result['inspected'] = inspected(row)
    return result


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
        raise StoreError(_cleaned_already(path, digest, source, label)
                         or 'File changed after the cleanup preview; preview it again before applying')
    before, after = versions(current)
    try:
        plan = cleanup.plan(before, after, current, lines)
    except (StoreError, ValueError) as error:
        done = _cleaned_already(path, digest, source, label)
        if done is None:
            raise
        raise StoreError(done) from error
    target = plan.content.decode('utf-8')
    residual, warning = _residual_text(path, target, kind, cleanup=True)
    flagged: list[int] = []
    if not plan.selected:
        # Nothing chosen yet: say which of the listed lines are flagged, and warn of nothing.
        warning = ''
        text = after.decode('utf-8')
        pointed = {n for numbers in _model_lines(text, source.get('change')).values() for n in numbers}
        flagged = sorted((set(_flagged_lines(path, text, kind).values()) | pointed) & set(plan.added))
    result = dict(change=label, path=str(path), current_hash=digest, flagged=flagged,
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
    original_flags = {finding_id(f) for f in scan_stored(scan_text, str(path), str(path), current.decode('utf-8'), kind)}
    remaining_flags = {finding_id(f) for f in scan_stored(scan_text, str(path), str(path), target, kind)}
    with store_lock():
        if _pinned_digest(pin) != digest:
            raise StoreError('File changed after the cleanup preview; preview it again before applying')
        if recheck is not None:
            recheck()
        with storage.connection(write=True):
            # A store used only for library scans has no metadata yet, and content copies
            # without metadata read as a damaged store.
            pass
        made: dict = {}
        backup = _recover(path, store_object(plan.content), digest, pin.mode(), residual, None,
                          cleanup_data={**source, 'lines': plan.selected,
                                        'resolved_flags': sorted(original_flags - remaining_flags)}, pin=pin,
                          recorded=made)
    result.update(applied=True, backup=str(backup) if backup else None, reload=RELOAD,
                  recovery=f"C{made['id']}" if 'id' in made else None)
    return result


def _cleaned_already(path: Path, digest: str, source: dict, label: str) -> str | None:
    """What to say when the file is the one a recorded cleanup of `source` left: applying or
    previewing that cleanup again then fails for that reason, not for an edit made later."""
    try:
        with storage.connection() as db:
            row = db.execute('SELECT id, data FROM changes WHERE path=? AND after_hash=? ORDER BY id DESC LIMIT 1',
                             (str(path), digest)).fetchone() if db else None
    except StoreError:
        return None
    if row is None:
        return None
    data = json.loads(row['data'])
    action = data.get('cleanup') or {}
    if data.get('method') != 'selective-removal' or any(action.get(k) != v for k, v in source.items()):
        return None
    lines = action.get('lines') or []
    many = len(lines) != 1
    return (f"{label} was already cleaned: line{'s' if many else ''} {','.join(map(str, lines))} "
            f"{'were' if many else 'was'} removed and recorded as C{row['id']}. Nothing was changed now. "
            f"To undo that cleanup: agentdetox restore C{row['id']} --apply")


# A cleanup changes the file, not what a running agent has already read from it.
RELOAD = ('An agent session that loaded this file before the cleanup still holds the removed text: start a new '
          'session in that client before relying on the cleanup.')


def _cleanup_line(line: bytes) -> str:
    return line.decode('utf-8').removesuffix('\r\n').removesuffix('\n')


def render_cleanup(data: dict) -> str:
    library = data.get('library')
    lines = [f"Selective cleanup of {data['change']} · {short_path(data['path'])}"]
    if data['applied']:
        lines += [f"Removed selected lines. Backup: {data['backup']}."]
        if data.get('recovery'):
            lines.append(f"Recorded as {data['recovery']}. To undo this cleanup: agentdetox restore "
                         f"{data['recovery']} --apply (without --apply it shows what that would do).")
        lines += [RELOAD,
                  'Unselected content was preserved. Review any remaining findings with `agentdetox '
                  + (f"library review {data['change']}`." if library else 'review`.')]
    elif not data['selected']:
        lines += ['Lines of the inspected version, which the file still is:' if library else
                  'Lines of the inspected version (not current-file line numbers):' if data.get('inspected') else
                  'Added or replaced lines in this recorded version (not current-file line numbers):']
        lines += [f"{item['line']:>5}  {printable(item['text'])}" for item in data['added']]
        flagged = ','.join(map(str, data.get('flagged') or []))
        lines += ['This change has no added lines to clean.'] if not data['added'] else [
            f"Flagged: line {flagged}. Preview removing only that: agentdetox clean {data['change']} --lines {flagged}"
            if flagged else
            "Choose only unwanted lines by the numbers above, singly or as ranges: "
            f"agentdetox clean {data['change']} --lines <numbers>"]
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


def _residual_text(path: Path, target: str, kind: str | None = None, cleanup: bool = False) -> tuple[list, str]:
    if kind is None:
        cf = classify(path, project=path.parent)
        kind = cf.kind if cf else 'config' if path.suffix in ('.json', '.toml') else 'memory'
    residual = [f for f in allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), target, kind))
                if f.severity in ('medium', 'high')]
    said = printable('; '.join(sorted({f.message for f in residual})))
    warning = '' if not residual else (
        f'\nWARNING: with these lines removed the file still has rule findings: {said}.' if cleanup else
        f'\nWARNING: the recovery version still has rule findings: {said}. Restoring it does not clear these findings.')
    return residual, warning


def _recover(path: Path, target_hash: str | None, current_hash: str | None, mode: int, residual: list,
             change_id: int | None, *, cleanup_data: dict | None = None, pin=None,
             recorded: dict | None = None) -> Path | None:
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
            pin.sweep()     # what a recovery stopped half-way left beside the file
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
                if recorded is not None:
                    recorded['id'] = entry.id
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
            # Where the backup is if one was written; `operation_backup` says whether it was.
            db.execute("UPDATE operations SET stage='failed', backup=?, error=? WHERE id=?",
                       (str(backup_path), str(e), operation))
        raise
    return backup


def _current_mode(pin) -> int:
    try:
        return pin.mode()
    except OSError:
        return 0o600


def operation_backup(operation) -> str:
    """Where an unfinished recovery's backup is, said only if it is there: the path is
    recorded before the copy is made, and a recovery stopped earlier wrote none."""
    backup = operation['backup'] or str(store_dir() / 'quarantine' / operation['id'] / 'content')
    if Path(backup).exists():
        return f'backup: {backup}'
    return 'no backup was written, so the file was not replaced'


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
