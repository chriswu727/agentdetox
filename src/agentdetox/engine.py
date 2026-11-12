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
from concurrent.futures import ThreadPoolExecutor
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist, budget, events, judge, ledger, paths, shell, storage
from .agentscan import scan_stored, scan_text
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
from .integrity import (
    StoreError,
    baseline_entries,
    is_self_hook,
    object_text,
    snapshot,
    snapshot_text,
    store_dir,
    store_lock,
)
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
DELETION = "deletion"        # an edit tool removing a memory, rules or skill file
UNREAD = "unread"            # a write to agent context whose content could not be worked out
SUSPICIOUS, COPIED, CONTRADICTION, JUDGE = "suspicious", "copied", "contradiction", "judge"


@dataclass
class Write:
    """A planned change to one file: its whole text before and after."""
    path: Path
    old: str
    new: str | None      # None: the file is removed
    # Why `new` is a guess (a patch that does not fit the file, an input not understood).
    unknown: str = ""


@dataclass
class Signal:
    check: str
    reason: str
    flags: list[Flag] = field(default_factory=list)


def _transcript(path: str | None) -> Transcript | None:
    """The session's recent turns, or None when there is no transcript or it cannot be read.
    Without one a flagged write counts as planted, never as the user's own words."""
    try:
        if not path or not Path(path).is_file():
            return None
        return read_transcript(path)
    except Exception as error:  # noqa: BLE001 - its content is whatever the agent read
        events.record("hook_error", stage="transcript", error=type(error).__name__)
        return None


def check_write(write: Write, project: Path, run: set[str], transcript: str | None = None) -> list[Signal]:
    """What is wrong with a planned write. `run` names the configurable checks to do
    now. A clear-cut finding stops the rest: the write is blocked anyway."""
    path, old = write.path, write.old
    if write.new is None and path.is_dir() and not path.is_symlink():
        return _folder_removal(path, project)
    if is_own_state(path):
        return [Signal(OWN_STATE, f"AgentDetox: this write changes AgentDetox's own settings, allowlist or "
                                  f"snapshots ({short_path(str(path))}).")]
    cf = classify(path, project=project)
    if cf is None:
        return []
    if write.new is None:
        return _removal(cf, old)
    new = write.new

    @functools.cache
    def recent() -> Transcript | None:
        return _transcript(transcript)

    if cf.kind == "config":
        findings = allowlist.unsuppressed(scan_text(str(path), str(path), new, "config"))
        if _worst(findings) == "high":
            return [_planted(cf, findings, recent())]
        if write.unknown:
            return [Signal(GUARDRAILS, f"AgentDetox: could not work out what this write does to "
                                       f"{short_path(str(path))} ({printable(write.unknown)}), so it is treated as a "
                                       "change to the agent's hooks, MCP servers or permissions.")]
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
    if JUDGE in run and added.strip():
        signals += _judged(cf, added)
    if write.unknown:
        signals.append(Signal(UNREAD, f"AgentDetox: only the text this write adds to the agent's {cf.kind} file "
                                      f"{short_path(str(path))} was checked, not the result: {printable(write.unknown)}."))
    return signals


def _judged(cf: ContextFile, added: str) -> list[Signal]:
    """What a model makes of the text a write adds, when it would stop it. Asked last, so
    that it can only add to what the rules and the text's origin already say."""
    found, _ = judged([(cf, added)], "medium")
    if not found:
        return []
    cut = f" Only its first {judge.LIMIT} characters were read." if len(added) > judge.LIMIT else ""
    line = f' It points at: "{printable(found[0].evidence[:120])}".' if found[0].evidence else ""
    return [Signal(JUDGE, f"AgentDetox: a model read the text this write adds to the agent's {cf.kind} file "
                          f"{short_path(str(cf.path))} and flagged it: {found[0].message.removeprefix(MODEL_FLAGGED)}."
                          f"{line}{cut} Content like this, once saved, is obeyed in every later session.",
                   [finding_flag(found[0])])]


MODEL_FLAGGED = "a model flagged it: "
JUDGED_AT_ONCE = 8      # texts a session start hands to the model; the rest wait for the next


def judged(texts: list[tuple[ContextFile, str]], severity: str, *, limit: int | None = None,
           timeout: float = judge.TIMEOUT) -> tuple[list[Finding], set[str]]:
    """Findings for the texts a model flags, and the paths of those it gave no opinion on:
    a call that failed, or a text past `limit`. A finding's evidence is the first line the
    model pointed at, if it pointed at any. The model is asked about several at once.
    A text allowed before is not sent; one flagged before is flagged still, unasked, since
    asking again might get another answer and trying again must change nothing."""
    order = {"instructions": 0, "skill": 1, "memory": 2}
    waiting: list[tuple[ContextFile, str, Finding]] = []
    found: list[Finding] = []
    undecided: set[str] = set()
    for cf, text in sorted(texts, key=lambda pair: order.get(pair[0].kind, 3)):
        if not text.strip():
            continue
        finding = Finding(str(cf.path), str(cf.path), "judge", severity, "a model read this text as one that would "
                          "turn the agent against you", anchor=text)
        if not allowlist.unsuppressed([finding]):
            continue
        before = judge.remembered(finding_flag(finding).id)
        if before is not None:
            found.append(_flagged(finding, before))
        elif limit is not None and len(waiting) >= limit:
            undecided.add(str(cf.path))
        else:
            waiting.append((cf, text, finding))
    if not waiting:
        return found, undecided
    with ThreadPoolExecutor(min(JUDGED_AT_ONCE, len(waiting))) as pool:
        said = list(pool.map(lambda job: judge.opinion(job[1], job[0].kind, timeout), waiting))
    # Recorded here, one at a time: the store is not written from several threads.
    for (cf, _, finding), opinion in zip(waiting, said):
        if opinion.flag is None:
            events.record("hook_error", stage="judge", error=opinion.error[:300])
            undecided.add(str(cf.path))
        elif opinion.flag:
            judge.remember(finding_flag(finding).id, opinion)
            found.append(_flagged(finding, opinion))
    return found, undecided


def _flagged(finding: Finding, said: judge.Opinion) -> Finding:
    finding.message = MODEL_FLAGGED + said.about
    finding.evidence = said.lines[0] if said.lines else ""
    return finding


def _inside(folder: Path, project: Path) -> list[ContextFile]:
    """The context files in `folder`: looked up among the files an agent loads and the ones
    AgentDetox has a version of, not found by walking a folder of any size."""
    real = os.path.realpath(folder)
    inside = {str(cf.path): cf for cf in discover(project=project)
              if Path(os.path.realpath(cf.path)).is_relative_to(real)}
    for name in storage.known_under(str(folder)):   # files in subfolders are known once recorded
        if name not in inside and os.path.isfile(name):
            cf = classify(Path(name), project=project)
            if cf is not None:
                inside[name] = cf
    return list(inside.values())


def removal_targets(path: Path, project: Path) -> list[Path]:
    """The files a removal of `path` takes with it that are worth keeping a version of."""
    if path.is_dir() and not path.is_symlink():
        return [cf.path for cf in _inside(path, project)]
    return [path]


def _folder_removal(folder: Path, project: Path) -> list[Signal]:
    """What is wrong with an edit tool removing a folder, judged by the context files in it."""
    if is_own_state(folder) or holds_own_state(folder):
        return [Signal(OWN_STATE, f"AgentDetox: this removes {short_path(str(folder))}, which holds AgentDetox's own "
                                  "settings, allowlist or snapshots.")]
    signals: list[Signal] = []
    for cf in _inside(folder, project):
        try:
            old = cf.path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            old = ""
        for signal in _removal(cf, old):
            if signal.check not in {s.check for s in signals}:
                signals.append(signal)
    return signals


def _removal(cf: ContextFile, old: str) -> list[Signal]:
    """What is wrong with an edit tool removing a context file. Config that sets hooks, MCP
    servers or permissions is guarded as any change to them is; a hook script counts whole."""
    where = short_path(str(cf.path))
    if not os.path.lexists(cf.path):
        return []
    if cf.kind == "config":
        sections = guarded_sections(cf.path, old) if old.strip() else {}
        if not sections:
            return []
        own = " It registers AgentDetox's own hooks." if any(is_self_hook(v) for v in sections.values()) else ""
        return [Signal(GUARDRAILS, f"AgentDetox: this removes {where}, and with it the hooks, MCP servers or "
                                   f"permissions it sets.{own} An agent changing its own hooks, MCP servers or "
                                   "permissions is how an injected instruction makes itself permanent.")]
    return [Signal(DELETION, f"AgentDetox: this removes the agent's {cf.kind} file {where}.")]


def check_command(command: str, project: Path, cwd: Path | None = None) -> list[Signal]:
    """What is wrong with a shell command the agent is about to run in `cwd` (by default
    the project root). Raises budget.OverBudget when reading it takes too long: a command
    built to be slow to read (thousands of folders entered, each looked up on disk) must not
    outlast the client's patience with the hook and so go unread."""
    with budget.limit():
        return _check_command(command, project, cwd)


def _check_command(command: str, project: Path, cwd: Path | None = None) -> list[Signal]:
    cwd = cwd or project
    if "\0" in command:
        # No shell word holds a NUL. Depending on how the command reaches the shell, it ends
        # at the first one or the NULs are dropped; either reading may be what runs.
        found: dict[str, Signal] = {}
        for reading in dict.fromkeys((command.split("\0", 1)[0], command.replace("\0", ""))):
            for signal in _check_command(reading, project, cwd):
                found.setdefault(signal.check, signal)
        return list(found.values())
    command_only, bodies = shell.heredocs(command)
    tokens = shell.split(command_only)
    fed, fed_changes = shell.heredoc_targets(bodies)
    targets = shell.write_targets(tokens) + fed
    targets = [t.removesuffix(shell.INTO) for t in targets if not t.endswith(shell.INTO)
               or not t.startswith(shell.UNKNOWN) and _is_dir(shell.resolve(t.removesuffix(shell.INTO), cwd).parent)]
    trees = {t.removesuffix(shell.TREE) for t in targets if t.endswith(shell.TREE)}
    targets = [t.removesuffix(shell.TREE) for t in targets]
    # A target in a folder only known at run time is judged by its name alone.
    context = [t for t in targets if named_like_context(t[len(shell.UNKNOWN):]) if t.startswith(shell.UNKNOWN)]
    targets = [t for t in targets if not t.startswith(shell.UNKNOWN)]
    context += [t for t in targets if any(classify(p, project=project) for p in shell.resolve_all(t, cwd))]
    folders = [p for t in targets if t in trees for p in shell.resolve_all(t, cwd) if _is_dir(p)]
    if folders:
        inside = [os.path.realpath(cf.path) for cf in discover(project=project)]
        context += [str(f) for f in folders
                    if any(Path(p).is_relative_to(os.path.realpath(f)) for p in inside)]
    if context:
        analyzed = command
        findings = []
        literal = shell.literal_printf(command) or shell.literal_heredoc(command)
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
            or any(holds_own_state(f) for f in folders)
            or shell.changes_agentdetox(tokens) or fed_changes):
        return [Signal(OWN_STATE, "AgentDetox: this command changes AgentDetox's own settings, allowlist or snapshots.")]
    if context:
        written = Signal(SHELL_WRITE, "AgentDetox: this shell command writes to or deletes the agent's memory, rules "
                                      "or config, bypassing the write check.")
        guarded = _guarded_targets(targets, project, cwd)
        if guarded:
            # What the command leaves in the file cannot be read from it, so this is judged as
            # an edit tool removing the file would be: it sets the agent's own guardrails.
            return [Signal(GUARDRAILS, f"AgentDetox: this shell command writes to or deletes {guarded}, which sets "
                                       "the agent's hooks, MCP servers or permissions. An agent changing those is "
                                       "how an injected instruction makes itself permanent."), written]
        return [written]
    if shell.unreadable(command_only) and (shell.names_context(command_only)
                                            or "agentdetox" in command_only.lower()):
        # Nothing was found, but the command could not be read to its end either.
        return [Signal(SHELL_WRITE, "AgentDetox: this shell command could not be read to its end (an unclosed quote "
                                    "or substitution) and names the agent's memory, rules or config, or AgentDetox.")]
    return []


def after_write(paths: list[Path], project: Path, record_contradictions: bool, transcript: str | None = None,
                agent: str = "", session: str = "", tool: str = "") -> None:
    """Re-trust context files the agent just wrote through its own tools, which the write
    check saw, so the snapshot only lags behind writes that bypassed them, and record each
    change in the ledger with where it came from. A clear-cut finding the user wrote
    themselves does not stop this: the write ran, so they approved it when asked."""

    @functools.cache
    def recent() -> Transcript | None:
        return _transcript(transcript)

    for path in paths:
        cf = classify(path, project=project)
        if cf is None:
            if not os.path.lexists(path):
                # A removed folder: every context file AgentDetox knew in it went with it.
                known = [Path(name) for name in storage.known_under(str(path))]
                if known:
                    _record_removals(known, agent, session, tool)
            continue
        if not path.is_file():
            _record_removals([path], agent, session, tool)
            continue
        for _ in range(3):
            with store_lock():
                before = previous_version(str(path))
                old = object_text(before) if before else ""
                data = path.read_bytes()
            text = data.decode("utf-8", errors="replace")
            digest = hashlib.sha256(data).hexdigest()
            full_findings = allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), text, cf.kind))
            high = [f for f in full_findings if f.severity == "high"]
            t = recent()
            # A file that keeps a clear-cut finding the user did not write stays untrusted; the
            # agent's edit to it is still recorded.
            trusted = not high or bool(t and t.human and all(typed_by_user(f, t.human) for f in high))
            if trusted and cf.kind == "config" and old.strip():
                # What the agent built on already set up something else than the snapshot does:
                # a change made outside the agent that nobody has been told about. The snapshot
                # stays where it is, so the next session still reports it.
                checked = snapshot_text(str(path))
                trusted = checked is None or guarded_sections(path, checked) == guarded_sections(path, old)
            if digest != before:
                added = _added_text(old, text)
                origin, source, requested = origin_of(added, t)
                spans = attribute_lines(old, text, t)
                findings = (full_findings if cf.kind == "config" else
                            allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), added, cf.kind)))
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


def _record_removals(paths: list[Path], agent: str, session: str, tool: str) -> None:
    """Record that the agent's own tool removed context files AgentDetox knew a version of
    (a patch that deletes or moves one, a deleted folder), all in one transaction. Their
    checkpoints stay, so each removal can be undone and the next session still reports it."""
    with store_lock(), storage.connection(write=True):
        for path in paths:
            known = previous_version(str(path))
            if known is None or os.path.lexists(path):
                continue
            ledger.record(path, "agent", known, None, agent=agent, session=session, tool=tool,
                          attribution="removed through the agent's own tool")


def changed_findings(cf: ContextFile, before: str, text: str) -> list[Finding]:
    """What the rules find in a change from `before` to `text`: in the added lines of a
    memory, rules or skill file, and in what a config file's change sets up."""
    from .integrity import _config_changes

    name = str(cf.path)
    if cf.kind == "config":
        found = _config_changes(name, cf.path, text, guarded_sections(cf.path, before) if before.strip() else {})
        found += scan_stored(scan_text, name, name, text, cf.kind)
    else:
        found = scan_stored(scan_text, name, name, _added_text(before, text), cf.kind)
    return allowlist.unsuppressed(found)


def before_removal(paths: list[Path], project: Path, agent: str = "") -> None:
    """Keep the version of each context file an edit tool is about to remove, so that
    putting the file back gives what was there and not an older checkpoint. A version
    that differs from the last one known is recorded as the change made outside the agent
    that it is; a file never seen before is recorded as found, with no history invented
    for it. Neither is trusted by this: nothing is checkpointed."""
    for path in paths:
        cf = classify(path, project=project)
        if cf is None or not path.is_file() or path.is_symlink():
            continue
        for _ in range(3):
            with store_lock():
                known = previous_version(str(path))
                data = path.read_bytes()
            digest = hashlib.sha256(data).hexdigest()
            if known == digest:
                break
            text = data.decode("utf-8", errors="replace").replace("\r\n", "\n").replace("\r", "\n")
            if known is None:
                findings = [f for f in allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), text, cf.kind))
                            if f.severity in ("medium", "high")]
            else:
                findings = changed_findings(cf, object_text(known), text)
            with store_lock():
                if previous_version(str(path)) != known:
                    continue
                if known is None:
                    ledger.record(path, "inspected", digest, data, findings=findings, method=ledger.INSPECTION,
                                  actor=agent or "agent tool",
                                  attribution="present when a tool asked to remove it; earlier history unknown")
                else:
                    ledger.record(path, "external", known, data, flagged=_worst(findings) == "high", findings=findings)
                break
        else:
            raise StoreError(f'{path} changed repeatedly while its version before removal was recorded')


def before_write(paths: list[Path], project: Path) -> None:
    """Record a change made outside the agent that is about to be built on: a file the
    agent is going to edit no longer matches the last version AgentDetox knows, because
    something else changed it during the session (an install script, say). Without this the
    agent's edit would be credited with that change. Config files churn on their own
    (counters, caches), so for them only a change to what they guard counts: a hook, an MCP
    server or a permission added outside the agent is not the agent's either."""
    for path in paths:
        cf = classify(path, project=project)
        if cf is None or not path.is_file():
            continue
        for _ in range(3):
            with store_lock():
                known = previous_version(str(path))
                data = path.read_bytes()
            if known is None or hashlib.sha256(data).hexdigest() == known:
                break
            text = data.decode('utf-8', errors='replace').replace('\r\n', '\n').replace('\r', '\n')
            if cf.kind == "config":
                earlier = object_text(known)
                if guarded_sections(path, earlier) == guarded_sections(path, text):
                    break
                findings = changed_findings(cf, earlier, text)
            else:
                findings = allowlist.unsuppressed(scan_stored(scan_text, str(path), str(path), text, cf.kind))
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
    # By what the file is, not how the path is spelled: another case, another name for the
    # volume or a link reach the same store.
    return paths.inside(path, store_dir())


# Config files that hold nothing but what is guarded: one of these being created is a
# guardrail change whatever is put in it.
_ONLY_GUARDED = {"hooks.json", ".mcp.json", "mcp.json"}


def _guarded_targets(targets: list[str], project: Path, cwd: Path) -> str:
    """The config files among a command's targets that set hooks, MCP servers or
    permissions now, or could hold nothing else; "" when there are none."""
    found = []
    for target in targets:
        if target.startswith(shell.UNKNOWN):
            continue
        for path in shell.resolve_all(target, cwd):
            try:
                cf = classify(path, project=project)
                if cf is None or cf.kind != "config":
                    continue
                if path.is_file():
                    sections = guarded_sections(cf.path, path.read_text(encoding="utf-8", errors="replace"))
                    if not sections:
                        continue
                elif path.name not in _ONLY_GUARDED:
                    continue
            except (OSError, ValueError):
                continue
            found.append(short_path(str(cf.path)))
    return ", ".join(dict.fromkeys(found))


def _is_dir(path: Path) -> bool:
    """A path the file system refuses to look at (too long, a NUL in it) is no folder."""
    try:
        return path.is_dir()
    except (OSError, ValueError):
        return False


def holds_own_state(folder: Path) -> bool:
    """Whether removing or moving `folder` takes AgentDetox's store with it."""
    return paths.inside(store_dir(), folder)


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
