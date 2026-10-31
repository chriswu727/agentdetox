"""Observe context versions across a shell tool without claiming process-level authorship."""

from __future__ import annotations

import hashlib
import os
import stat
import time
from pathlib import Path

from . import allowlist, events, ledger, storage
from .agentscan import scan_text
from .context import ContextFile, discover_session
from .engine import _added_text
from .findings import Finding, finding_id
from .integrity import StoreError, _config_changes, object_text, store_lock, store_object
from .persistence import guarded_sections

MAX_AGE = 24 * 3600


def _key(agent: str, session: str, tool_id: str) -> str:
    if not tool_id:
        raise ValueError('Shell observation requires a tool_use_id from the agent')
    return hashlib.sha256('\0'.join((agent, session, tool_id)).encode()).hexdigest()


def start(agent: str, session: str, tool_id: str, project: Path) -> None:
    run_id = _key(agent, session, tool_id)
    with store_lock(), storage.connection(write=True) as db:
        db.execute('DELETE FROM tool_runs WHERE created<?', (time.time() - MAX_AGE,))
        existing = db.execute('SELECT 1 FROM tool_runs WHERE id=?', (run_id,)).fetchone()
        if existing:
            return
        db.execute('INSERT INTO tool_runs VALUES (?, ?, ?, ?, ?)',
                   (run_id, agent, session, str(project), time.time()))
        for cf in discover_session(project, agent):
            with cf.path.open('rb') as file:
                data = file.read()
                mode = stat.S_IMODE(os.fstat(file.fileno()).st_mode)
            if cf.path.is_symlink():
                raise StoreError(f'Context became a symbolic link: {cf.path}')
            digest = store_object(data)
            db.execute('INSERT INTO tool_versions VALUES (?, ?, ?, ?, ?, ?)',
                       (run_id, str(cf.path), digest, cf.kind, cf.scope, mode))


def finish(agent: str, session: str, tool_id: str, project: Path, *, failed: bool = False) -> str:
    run_id = _key(agent, session, tool_id)
    changes = []
    with store_lock(), storage.connection(write=True) as db:
        run = db.execute('SELECT * FROM tool_runs WHERE id=?', (run_id,)).fetchone()
        if run is None:
            raise StoreError('Shell observation has no start state; inspect doctor and the context history')
        # Bash may change cwd; compare the scope captured before execution.
        project = Path(run['project'])
        before = {r['path']: dict(r) for r in db.execute('SELECT * FROM tool_versions WHERE run_id=?', (run_id,))}
        current = {str(cf.path): cf for cf in discover_session(project, agent)}
        for name in sorted(before.keys() | current.keys()):
            path = Path(name)
            if path.is_symlink():
                raise StoreError(f'Context became a symbolic link: {path}')
            previous = before.get(name)
            cf = current.get(name)
            if cf is None:
                assert previous is not None
                cf = ContextFile(agent, previous['kind'], previous['scope'], path)
            data = path.read_bytes() if name in current else None
            after_hash = hashlib.sha256(data).hexdigest() if data is not None else None
            before_hash = previous['digest'] if previous else None
            if before_hash == after_hash:
                continue
            latest = ledger.entries(name, limit=1)
            if latest and latest[0].after == after_hash:
                continue
            old = object_text(before_hash) if before_hash else ''
            text = data.decode('utf-8', errors='replace') if data is not None else ''
            if cf.kind == 'config' and previous and data is not None:
                if guarded_sections(path, old) == guarded_sections(path, text):
                    continue
            findings = _findings(cf, old, text, previous is not None, data is None)
            entry = ledger.record(path, 'external', latest[0].after if latest else before_hash, data,
                                  findings=findings, agent=agent, session=session, tool='Bash', method='before-after',
                                  before_mode=previous['mode'] if previous else None,
                                  attribution=f'observed across shell tool {tool_id}; writing process unknown')
            if entry is None:
                raise StoreError('Could not record shell observation')
            observation = Finding(name, name, 'context-change', 'low',
                                  'Context changed during a shell tool; writing process unknown',
                                  anchor=f'{name}\n{tool_id}\n{after_hash}')
            ledger.add_finding(entry.id, finding_id(observation), observation.severity, observation.message)
            changes.append(f'C{entry.id}')
        db.execute('DELETE FROM tool_runs WHERE id=?', (run_id,))
        if changes:
            events.record('shell_context_changed', agent=agent, project=str(project), session=session,
                          tool_use_id=tool_id, failed=failed, changes=changes)
    if not changes:
        return ''
    shown = ', '.join(changes[:5]) + (' ...' if len(changes) > 5 else '')
    return (f'AgentDetox: {len(changes)} context file(s) changed during this shell tool ({shown}). '
            f'Review: agentdetox review {changes[0]}. Writing process is unknown; this does not prove malicious intent.')


def _findings(cf: ContextFile, old: str, text: str, existed: bool, deleted: bool) -> list[Finding]:
    name = str(cf.path)
    findings = []
    if cf.kind == 'config' and existed:
        findings += _config_changes(name, cf.path, text, guarded_sections(cf.path, old))
    if not deleted:
        findings += scan_text(name, name, text if cf.kind == 'config' else _added_text(old, text), cf.kind)
    return allowlist.unsuppressed(findings)
