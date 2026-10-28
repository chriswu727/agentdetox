"""What AgentDetox finds in a change to an agent's persistent context, whatever the agent.

Adapters turn each agent's events into a Write or a shell command; the checks here
report what is wrong with it as Signals; policy.py decides what to do about them. Nothing
here knows which agent is asking or what the user's settings are.
"""

from __future__ import annotations

import difflib
import os
from dataclasses import dataclass, field
from pathlib import Path

from . import allowlist, daemon, events, shell
from .agentscan import read_text, scan_text
from .allowlist import Flag, contradiction_flag, copy_flag, finding_flag, source_id
from .consistency import (NLI, Contradiction, Statement, candidate_pairs, find_contradictions, statements,
                          store_statements)
from .context import ContextFile, classify, related_files, short_path
from .findings import Finding
from .integrity import snapshot, snapshot_text, store_dir
from .persistence import guarded_sections
from .provenance import CopyFinding, copied_from_untrusted, read_transcript

# What a signal is about. The last three are also the names of the user's settings.
PLANTED = "planted"          # a clear-cut planted instruction
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
    if cf.kind == "config":
        findings = allowlist.unsuppressed(scan_text(str(path), str(path), new, "config"))
        if _worst(findings) == "high":
            return [_planted(cf, findings)]
        if guarded_sections(path, old) != guarded_sections(path, new):
            return [Signal(GUARDRAILS, f"AgentDetox: this changes the hooks, MCP servers or permissions in {path}. "
                                       "Agents changing their own guardrails is how CurXecute-style attacks persist.")]
        return []
    added = _added_text(old, new)
    findings = allowlist.unsuppressed(scan_text(str(path), str(path), added, cf.kind))
    if _worst(findings) == "high":
        return [_planted(cf, findings)]
    signals = []
    medium = [f for f in findings if f.severity == "medium"]
    if medium and SUSPICIOUS in run:
        signals.append(Signal(SUSPICIOUS, _reason(cf, medium, "flagged"), [finding_flag(f) for f in medium]))
    copied = _copied(cf, added, transcript) if COPIED in run else None
    if copied:
        source = f"{copied.tool} output ({copied.origin[:100]})" if copied.origin else f"{copied.tool} output"
        signals.append(Signal(
            COPIED,
            f"AgentDetox: {copied.fraction:.0%} of this {cf.kind} write is copied from {source} the agent "
            f'just read ("{copied.excerpt[:80]}..."), and the user did not ask to remember it. Text planted in web '
            "pages, emails and files reaches agent memory this way. Allowing its id trusts that source from now on.",
            [copy_flag(copied)]))
    conflicts = contradictions(cf, old, new, project) if CONTRADICTION in run else []
    if conflicts:
        signals.append(Signal(CONTRADICTION, _conflict_reason(cf, conflicts),
                              [contradiction_flag(c) for c in conflicts]))
    return signals


def check_command(command: str, project: Path) -> list[Signal]:
    """What is wrong with a shell command the agent is about to run."""
    tokens = shell.split(command)
    targets = shell.write_targets(tokens)
    context = [t for t in targets if classify(shell.resolve(t, project), project=project)]
    if context:
        findings = allowlist.unsuppressed(scan_text("shell", "shell", command, "memory"))
        if _worst(findings) == "high":
            return [Signal(PLANTED, "AgentDetox: shell command writes to agent context and "
                                    + "; ".join(sorted({f.message for f in findings})) + ".",
                           [finding_flag(f) for f in findings if f.severity == "high"])]
    if any(is_own_state(shell.resolve(t, project)) for t in targets) or shell.changes_agentdetox(tokens):
        return [Signal(OWN_STATE, "AgentDetox: this command changes AgentDetox's own settings, allowlist or snapshots.")]
    if context:
        return [Signal(SHELL_WRITE, "AgentDetox: this shell command writes to or deletes the agent's memory, rules or "
                                    "config, bypassing the write check. Approve only if you expected it.")]
    return []


def after_write(paths: list[Path], project: Path, record_contradictions: bool) -> None:
    """Re-trust context files the agent just wrote through its own tools, which the write
    check saw, so the snapshot only lags behind writes that bypassed them."""
    for path in paths:
        cf = classify(path, project=project)
        if cf is None or not path.is_file():
            continue
        if _worst(allowlist.unsuppressed(scan_text(str(path), str(path), read_text(path), cf.kind))) != "high":
            old = snapshot_text(str(path)) or ""
            snapshot([cf], roots=[])
            if record_contradictions:
                record_in_background(cf, old, project)


def is_own_state(path: Path) -> bool:
    # Settings, allowlist and snapshots: an injected instruction that could edit these
    # could switch the checks off, allow itself, or make a poisoned file the baseline.
    return Path(os.path.realpath(path)).is_relative_to(os.path.realpath(store_dir()))


def _planted(cf: ContextFile, findings: list[Finding]) -> Signal:
    return Signal(PLANTED, _reason(cf, findings), [finding_flag(f) for f in findings if f.severity == "high"])


def _copied(cf: ContextFile, added: str, transcript: str | None) -> CopyFinding | None:
    if cf.kind not in ("memory", "instructions", "skill") or not transcript or not Path(transcript).is_file():
        return None
    t = read_transcript(transcript)
    allowed = allowlist.entries()
    t.sources = [s for s in t.sources if source_id(s.tool, s.origin) not in allowed]
    return copied_from_untrusted(added, t)


def _added_text(old: str, new: str) -> str:
    return "\n".join(
        line[1:] for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0)
        if line.startswith("+") and not line.startswith("+++")
    )


def _worst(findings: list[Finding]) -> str | None:
    sevs = {f.severity for f in findings}
    return "high" if "high" in sevs else "medium" if "medium" in sevs else "low" if sevs else None


def _reason(cf: ContextFile, findings: list[Finding], verb: str = "blocked") -> str:
    labels = "; ".join(sorted({f.message for f in findings if f.severity in ("medium", "high")}))
    return (f"AgentDetox {verb} a write to the agent's {cf.kind} file {cf.path}: {labels}. "
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


def record_in_background(cf: ContextFile, old: str, project: Path) -> None:
    """Hand the slow NLI check to the model server, so recording costs the hook nothing.
    Writes with nothing to compare (most of them) never reach it."""
    if not _nli_installed():
        return
    found = comparison(cf, old, read_text(cf.path), project)
    if found is None or not candidate_pairs(*found):
        return
    daemon.submit({"path": str(cf.path), "project": str(project), "old": old})


def record_contradictions(path: Path, project: Path, old: str, nli=None) -> int:
    """Log contradictions between a written file and what was there before (run by the
    model server)."""
    cf = classify(path, project=project)
    if cf is None or not path.is_file():
        return 0
    conflicts = contradictions(cf, old, read_text(path), project, nli)
    for c in conflicts:
        events.record("contradiction", id=contradiction_flag(c).id, path=str(path), new=c.new.text[:300],
                      existing=c.existing.text[:300], existing_source=c.existing.source,
                      probability=round(c.probability, 3))
    return len(conflicts)


def _conflict_reason(cf: ContextFile, conflicts: list[Contradiction]) -> str:
    lines = "; ".join(f'"{c.new.text[:100]}" contradicts "{c.existing.text[:100]}" ({short_path(c.existing.source)})'
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
    if not _NLI_INSTANCE:
        nli = NLI()
        _NLI_INSTANCE.append(None if not nli.available() else _ServerNLI() if daemon.SERVER else nli)
    return _NLI_INSTANCE[0]


class _ServerNLI:
    def contradiction(self, pairs: list[tuple[str, str]]) -> list[float]:
        probs = daemon.contradiction(pairs)
        if probs is None:  # no server could be reached: load the model here, as before
            probs = NLI().contradiction(pairs)
        return probs
