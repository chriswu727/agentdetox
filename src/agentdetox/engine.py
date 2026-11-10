"""What AgentDetox finds in a change to an agent's persistent context, whatever the agent.

Adapters turn each agent's events into a Write or a shell command; the checks here
report what is wrong with it as Signals; policy.py decides what to do about them. Nothing
here knows which agent is asking or what the user's settings are.
"""

from __future__ import annotations

import difflib
import functools
import hashlib
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist, events, ledger, shell, storage
from .agentscan import scan_text
from .allowlist import Flag, contradiction_flag, copy_flag, finding_flag, source_id
from .consistency import (
    NLI,
    Contradiction,
    Statement,
    find_contradictions,
    statements,
    store_statements,
)
from .context import ContextFile, classify, discover, named_like_context, related_files, short_path
from .findings import Finding, printable
from .integrity import StoreError, baseline_entries, object_text, snapshot, store_dir, store_lock
from .persistence import guard_changes, guarded_sections
from .provenance import (
    CopyFinding,
    Transcript,
    attribute_lines,
    copied_from_untrusted,
    origin_of,
    read_transcript,
    typed_by_user,
)

# What a signal is about. The last three are also the names of the user's settings.
PLANTED = "planted"          # a clear-cut planted instruction
USER_WRITTEN = "user-written"  # the same, in text the user typed or pasted themselves
OWN_STATE = "own-state"      # a change to AgentDetox's own settings, allowlist or snapshots
GUARDRAILS = "guardrails"    # an agent changing its own hooks, MCP servers or permissions
SHELL_WRITE = "shell-write"  # a shell command writing agent context past the write check
SUSPICIOUS, COPIED, CONTRADICTION = "suspicious", "copied", "contradiction"


@dataclass
class Write:
    """A planned change to one file: its whole text before and after."""
    path: Path
    old: str
    new: str


@dataclass
class Signal:
    check: str
    reason: str
    flags: list[Flag] = field(default_factory=list)


def check_write(write: Write, project: Path, run: set[str], transcript: str | None = None) -> list[Signal]:
    """What is wrong with a planned write. `run` names the configurable checks to do
    now. A clear-cut finding stops the rest: the write is blocked anyway."""
    path, old, new = write.path, write.old, write.new
    if is_own_state(path):
        return [Signal(OWN_STATE, f"AgentDetox: this write changes AgentDetox's own settings, allowlist or "
                                  f"snapshots ({short_path(str(path))}).")]
    cf = classify(path, project=project)
    if cf is None:
        return []

    @functools.cache
    def recent() -> Transcript | None:
        return read_transcript(transcript) if transcript and Path(transcript).is_file() else None

    if cf.kind == "config":
        findings = allowlist.unsuppressed(scan_text(str(path), str(path), new, "config"))
        if _worst(findings) == "high":
            return [_planted(cf, findings, recent())]
        if (guarded_sections(path, old) if old.strip() else {}) != guarded_sections(path, new):
            changes = printable("; ".join(guard_changes(path, old, new))) or "changes the hooks, MCP servers or permissions"
            return [Signal(GUARDRAILS, f"AgentDetox: this write to {short_path(str(path))} {changes}. An agent "
                                       "changing its own hooks, MCP servers or permissions is how an injected "
                                       "instruction makes itself permanent.")]
        return []
    added = _added_text(old, new)
    findings = allowlist.unsuppressed(scan_text(str(path), str(path), added, cf.kind))
    if _worst(findings) == "high":
        return [_planted(cf, findings, recent())]
    signals = []
    medium = [f for f in findings if f.severity == "medium"]
    if medium and SUSPICIOUS in run:
        signals.append(Signal(SUSPICIOUS, _reason(cf, medium, "flagged"), [finding_flag(f) for f in medium]))
    copied = _copied(cf, added, recent()) if COPIED in run else None
    if copied:
        source = f"{copied.tool} output ({copied.origin[:100]})" if copied.origin else f"{copied.tool} output"
        signals.append(Signal(
            COPIED,
            f"AgentDetox: {copied.fraction:.0%} of a passage in this {cf.kind} write is copied from {source} the agent "
            f'just read ("{copied.excerpt[:80]}..."), and the user did not ask to remember it. Text planted in web '
            "pages, emails and files reaches agent memory this way. Allowing its id trusts that source from now on.",
            [copy_flag(copied)]))
    conflicts = contradictions(cf, old, new, project) if CONTRADICTION in run else []
    if conflicts:
        signals.append(Signal(CONTRADICTION, _conflict_reason(cf, conflicts),
                              [contradiction_flag(c) for c in conflicts]))
    return signals


def check_command(command: str, project: Path, cwd: Path | None = None) -> list[Signal]:
    """What is wrong with a shell command the agent is about to run in `cwd` (by default
    the project root)."""
    cwd = cwd or project
    command_only, bodies = shell.heredocs(command)
    tokens = shell.split(command_only)
    fed, fed_changes = shell.heredoc_targets(bodies)
    targets = shell.write_targets(tokens) + fed
    targets = [t.removesuffix(shell.INTO) for t in targets if not t.endswith(shell.INTO)
               or not t.startswith(shell.UNKNOWN) and shell.resolve(t.removesuffix(shell.INTO), cwd).parent.is_dir()]
    trees = {t.removesuffix(shell.TREE) for t in targets if t.endswith(shell.TREE)}
    targets = [t.removesuffix(shell.TREE) for t in targets]
    # A target in a folder only known at run time is judged by its name alone.
    context = [t for t in targets if named_like_context(t[len(shell.UNKNOWN):]) if t.startswith(shell.UNKNOWN)]
    targets = [t for t in targets if not t.startswith(shell.UNKNOWN)]
    context += [t for t in targets if any(classify(p, project=project) for p in shell.resolve_all(t, cwd))]
    folders = [p for t in targets if t in trees for p in shell.resolve_all(t, cwd) if p.is_dir()]
    if folders:
        inside = [os.path.realpath(cf.path) for cf in discover(project=project)]
        context += [str(f) for f in folders
                    if any(Path(p).is_relative_to(os.path.realpath(f)) for p in inside)]
    if context:
        analyzed = command
        findings = []
        literal = shell.literal_printf(command)
        if literal:
            target, body, executable = literal
            cf = classify(shell.resolve(target, cwd), project=project)
            if cf and cf.kind in {'memory', 'instructions'}:
                findings = scan_text(str(cf.path), str(cf.path), body, cf.kind)
                analyzed = executable
        findings += scan_text("shell", "shell", analyzed, "shell")
        findings = allowlist.unsuppressed(findings)
        if _worst(findings) == "high":
            return [Signal(PLANTED, "AgentDetox: shell command writes to agent context and "
                                    + printable("; ".join(sorted({f.message for f in findings}))) + ".",
                           [finding_flag(f) for f in findings if f.severity == "high"])]
    if (any(is_own_state(p) for t in targets if not t.startswith(shell.UNKNOWN) for p in shell.resolve_all(t, cwd))
            or shell.changes_agentdetox(tokens) or fed_changes):
        return [Signal(OWN_STATE, "AgentDetox: this command changes AgentDetox's own settings, allowlist or snapshots.")]
    if context:
        return [Signal(SHELL_WRITE, "AgentDetox: this shell command writes to or deletes the agent's memory, rules or "
                                    "config, bypassing the write check. Approve only if you expected it.")]
    return []


def after_write(paths: list[Path], project: Path, record_contradictions: bool, transcript: str | None = None,
                agent: str = "", session: str = "", tool: str = "") -> None:
    """Re-trust context files the agent just wrote through its own tools, which the write
    check saw, so the snapshot only lags behind writes that bypassed them, and record each
    change in the ledger with where it came from. A clear-cut finding the user wrote
    themselves does not stop this: the write ran, so they approved it when asked."""

    @functools.cache
    def recent() -> Transcript | None:
        return read_transcript(transcript) if transcript and Path(transcript).is_file() else None

    for path in paths:
        cf = classify(path, project=project)
        if cf is None or not path.is_file():
            continue
        for _ in range(3):
            with store_lock():
                before = previous_version(str(path))
                old = object_text(before) if before else ""
                data = path.read_bytes()
            text = data.decode("utf-8", errors="replace")
            digest = hashlib.sha256(data).hexdigest()
            full_findings = allowlist.unsuppressed(scan_text(str(path), str(path), text, cf.kind))
            high = [f for f in full_findings if f.severity == "high"]
            t = recent()
            # A file that keeps a clear-cut finding the user did not write stays untrusted; the
            # agent's edit to it is still recorded.
            trusted = not high or bool(t and t.human and all(typed_by_user(f, t.human) for f in high))
            if digest != before:
                added = _added_text(old, text)
                origin, source, requested = origin_of(added, t)
                spans = attribute_lines(old, text, t)
                findings = (full_findings if cf.kind == "config" else
                            allowlist.unsuppressed(scan_text(str(path), str(path), added, cf.kind)))
                copied = _copied(cf, added, t)
            with store_lock(), storage.connection(write=True):
                # Evidence is computed without the global lock; neither its base version nor
                # the checked bytes may change before checkpoint and history commit together.
                if (previous_version(str(path)) != before or not path.is_file()
                        or hashlib.sha256(path.read_bytes()).hexdigest() != digest):
                    continue
                if trusted:
                    snapshot([cf], roots=[], expected={str(cf.path): digest})
                if digest != before:
                    entry = ledger.record(path, origin, before, data, agent=agent, session=session, tool=tool,
                                          source=source, requested=requested, findings=findings, spans=spans)
                    if copied and entry:
                        flag = copy_flag(copied)
                        ledger.add_finding(entry.id, flag.id, "medium", flag.what + " (text-match inference)")
                break
        else:
            raise StoreError(f"{path} changed repeatedly while recording; check it again before trusting it")
        if trusted and record_contradictions:
            record_in_background(cf, old, project, content=data)


def before_write(paths: list[Path], project: Path) -> None:
    """Record a change made outside the agent that is about to be built on: a file the
    agent is going to edit no longer matches the last version AgentDetox knows, because
    something else changed it during the session (an install script, say). Without this the
    agent's edit would be credited with that change. Config files churn on their own and
    are compared at session start instead."""
    for path in paths:
        cf = classify(path, project=project)
        if cf is None or cf.kind == "config" or not path.is_file():
            continue
        for _ in range(3):
            with store_lock():
                known = previous_version(str(path))
                data = path.read_bytes()
            if known is None or hashlib.sha256(data).hexdigest() == known:
                break
            text = data.decode('utf-8', errors='replace').replace('\r\n', '\n').replace('\r', '\n')
            findings = allowlist.unsuppressed(scan_text(str(path), str(path), text, cf.kind))
            with store_lock():
                if previous_version(str(path)) != known:
                    continue
                ledger.record(path, "external", known, data, flagged=_worst(findings) == "high", findings=findings)
                break
        else:
            raise StoreError(f'{path} history changed repeatedly while recording the external version')


def previous_version(path: str) -> str | None:
    """The newest version AgentDetox knows of `path`: the trusted snapshot, or a later
    change the ledger recorded without trusting it."""
    with storage.connection() as db:
        if db is not None:
            # Updated in write order by every recorded change and snapshot, so no clock
            # comparison is needed (local timestamps go backwards with the clock).
            row = db.execute('SELECT observed_hash FROM files WHERE path=?', (path,)).fetchone()
            return row[0] if row else None
        snap = baseline_entries().get(path)
    history = ledger.entries(path, limit=1)
    if history and (snap is None or history[-1].ts >= snap.get("taken", "")):
        return history[-1].after
    return snap["sha256"] if snap else None


def is_own_state(path: Path) -> bool:
    # Settings, allowlist and snapshots: an injected instruction that could edit these
    # could switch the checks off, allow itself, or make a poisoned file the baseline.
    return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(store_dir()))


def _planted(cf: ContextFile, findings: list[Finding], t: Transcript | None) -> Signal:
    high = [f for f in findings if f.severity == "high"]
    flags = [finding_flag(f) for f in high]
    if t and all(typed_by_user(f, t.human) for f in high):
        return Signal(USER_WRITTEN, _reason(cf, findings, "flagged") + " The flagged text is from your own message; "
                                    "approve only if you trust where you got it.", flags)
    return Signal(PLANTED, _reason(cf, findings), flags)


def _copied(cf: ContextFile, added: str, t: Transcript | None) -> CopyFinding | None:
    if cf.kind not in ("memory", "instructions", "skill") or t is None:
        return None
    allowed = allowlist.entries()
    sources = [s for s in t.sources if source_id(s.tool, s.origin) not in allowed]
    return copied_from_untrusted(added, t, sources=sources)


def _added_text(old: str, new: str) -> str:
    after = new.splitlines()
    return "\n\n".join(
        "\n".join(after[start:end])
        for tag, _, _, start, end in difflib.SequenceMatcher(None, old.splitlines(), after).get_opcodes()
        if tag in ("insert", "replace")
    )


def _worst(findings: list[Finding]) -> str | None:
    sevs = {f.severity for f in findings}
    return "high" if "high" in sevs else "medium" if "medium" in sevs else "low" if sevs else None


def _reason(cf: ContextFile, findings: list[Finding], verb: str = "blocked") -> str:
    labels = printable("; ".join(sorted({f.message for f in findings if f.severity in ("medium", "high")})))
    return (f"AgentDetox {verb} a write to the agent's {cf.kind} file {short_path(str(cf.path))}: {labels}. "
            "Content like this, once saved, is obeyed in every later session.")


# Contradictions -----------------------------------------------------------------------

def comparison(cf: ContextFile, old_text: str, new_text: str,
               project: Path) -> tuple[list[Statement], list[Statement]] | None:
    """The statements a write adds and the ones they are compared with."""
    if cf.kind not in ("memory", "instructions"):
        return None
    # Diff by statement, not by line: editing one sentence of a line must not make the
    # line's other, unchanged sentences count as new claims.
    old_texts = {s.text for s in statements(old_text, str(cf.path))}
    after = statements(new_text, str(cf.path))
    new_stmts = [s for s in after if s.text not in old_texts]
    if not new_stmts:
        return None
    added_texts = {s.text for s in new_stmts}
    # Statements still in the target file after the edit count as existing; ones the
    # edit removed do not, so replacing an old fact with a new one is an update.
    existing = [s for s in after if s.text not in added_texts]
    existing += store_statements(related_files(cf, project), skip={str(cf.path)})
    return new_stmts, existing


def contradictions(cf: ContextFile, old_text: str, new_text: str, project: Path, nli=None) -> list[Contradiction]:
    found = comparison(cf, old_text, new_text, project)
    if found is None:
        return []
    allowed = allowlist.entries()
    return [c for c in find_contradictions(*found, nli or _nli) if contradiction_flag(c).id not in allowed]


def record_in_background(cf: ContextFile, old: str, project: Path, *, content: bytes | None = None) -> None:
    """Queue the observed version; candidate selection and inference run in the worker."""
    if cf.kind not in ("memory", "instructions") or not _nli_installed():
        return
    content = cf.path.read_bytes() if content is None else content
    # Stored text uses universal newlines; queued bytes retain their exact version hash.
    text = content.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
    if not content.strip() or text == old.replace("\r\n", "\n").replace("\r", "\n"):
        return
    from . import daemon

    daemon.submit({"path": str(cf.path), "project": str(project), "old": old, "content_hex": content.hex()})


def record_contradictions(path: Path, project: Path, old: str, nli=None, *, content: bytes | None = None) -> int:
    """Log contradictions between a written file and what was there before (run by the
    model server)."""
    cf = classify(path, project=project)
    if cf is None or (content is None and not path.is_file()):
        return 0
    content = path.read_bytes() if content is None else content
    digest = hashlib.sha256(content).hexdigest()
    conflicts = contradictions(cf, old, content.decode("utf-8", errors="replace"), project, nli)
    for c in conflicts:
        events.record("contradiction", id=contradiction_flag(c).id, path=str(path), new=c.new.text[:300],
                      existing=c.existing.text[:300], existing_source=c.existing.source,
                      probability=round(c.probability, 3))
    if conflicts:
        with storage.connection(write=True) as db:
            row = db.execute('SELECT id FROM changes WHERE path=? AND after_hash=? ORDER BY id DESC LIMIT 1',
                             (str(path), digest)).fetchone()
            if row:
                for conflict in conflicts:
                    flag = contradiction_flag(conflict)
                    ledger.add_finding(row[0], flag.id, "medium", flag.what)
    return len(conflicts)


def _conflict_reason(cf: ContextFile, conflicts: list[Contradiction]) -> str:
    lines = "; ".join(f'"{printable(c.new.text[:100])}" contradicts "{printable(c.existing.text[:100])}" '
                      f'({short_path(c.existing.source)})'
                      for c in conflicts[:3])
    return (f"AgentDetox: this {cf.kind} write conflicts with what the agent already knows: {lines}. "
            "A fabricated fact often looks like this. If it is a real update, edit the old entry instead.")


def _nli_installed() -> bool:
    # AGENTDETOX_NLI=0 must also keep tests and benchmarks from starting a server.
    return os.environ.get("AGENTDETOX_NLI") != "0" and NLI.installed()


_NLI_INSTANCE: list = []


def _nli():
    """The model for checks that must answer now (ask mode, session start): the model
    server's, so only its first use pays the load. None when the extra or model is
    missing. A process that set _NLI_INSTANCE (a benchmark) uses its own model."""
    from . import daemon

    if not _NLI_INSTANCE:
        nli = NLI()
        _NLI_INSTANCE.append(None if not nli.available() else _ServerNLI() if daemon.SERVER else nli)
    return _NLI_INSTANCE[0]


class _ServerNLI:
    def contradiction(self, pairs: list[tuple[str, str]]) -> list[float]:
        from . import daemon

        probs = daemon.contradiction(pairs)
        if probs is None:  # no server could be reached: load the model here, as before
            probs = NLI().contradiction(pairs)
        return probs
