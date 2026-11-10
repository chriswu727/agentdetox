"""Scan an agent's persistent context files for planted instructions."""

from __future__ import annotations

from pathlib import Path

from .consistency import find_contradictions, statements, store_statements
from .context import ContextFile, related_files
from .corpus import Doc
from .findings import Finding, line_at, pair_anchor, snippet
from .hidden import normalize, outside_code, prose_view, scan_doc
from .persistence import config_commands, own_env_keys, text_findings, text_matches


def read_text(path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def scan_text(doc_id: str, source: str, text: str, kind: str) -> list[Finding]:
    """Findings for one piece of context text. `kind` is a ContextFile kind."""
    if kind == "config":
        return _scan_config(doc_id, source, text)
    prose = kind in {"memory", "instructions"}
    # A skill is sentences and commands both: what its sentences forbid is read as forbidden,
    # what its code blocks hold is read as what would run.
    skill = kind == "skill"
    findings = scan_doc(Doc(doc_id, text, source), prose=prose, wrapped=prose, guidance=skill)
    norm = normalize(text)
    def anchor(start, end):
        return line_at(norm, start)

    if prose:
        norm, anchor = prose_view(text)
    for severity, label, pos, end in text_matches(norm, prose=prose, guidance=outside_code(norm) if skill else None):
        findings.append(Finding(doc_id, source, "persistence", severity, label, snippet(norm, pos),
                                anchor=anchor(pos, end)))
    return findings


def _scan_config(doc_id: str, source: str, text: str) -> list[Finding]:
    findings = []
    for where, command in config_commands(Path(source), text):
        for severity, label, _ in text_findings(command):
            findings.append(Finding(doc_id, source, "config-command", severity, f"{label} ({where})", command[:200],
                                    anchor=command))
    for name in own_env_keys(Path(source), text):
        findings.append(Finding(doc_id, source, "config-command", "high",
                                "sets AgentDetox's own settings through the agent's environment", name, anchor=name))
    return findings


def consistency_findings(files: list[ContextFile], project: Path | None, nli) -> list[Finding]:
    """Contradictions between files in each memory scope (one project's memory plus the
    instructions that apply to it). Each conflicting pair is reported once."""
    seen: set[frozenset] = set()
    out: list[Finding] = []
    for cf in files:
        if cf.kind not in ("memory", "instructions"):
            continue
        own = statements(read_text(cf.path), str(cf.path))
        if not own:
            continue
        others = store_statements(related_files(cf, project), skip={str(cf.path)})
        # Sentences of one note were written together; within a file the model only adds noise.
        for c in find_contradictions(own, others, nli):
            key = frozenset((c.new.text, c.existing.text))
            if key in seen:
                continue
            seen.add(key)
            out.append(Finding(str(cf.path), str(cf.path), "contradiction", "medium",
                               f'contradicts "{c.existing.text[:120]}" ({c.existing.source}:{c.existing.line}), '
                               f"p={c.probability:.2f}", c.new.text[:200],
                               anchor=pair_anchor(c.new.text, c.existing.text)))
    return out


def scan_context(files: list[ContextFile]) -> list[Finding]:
    findings: list[Finding] = []
    for cf in files:
        text = read_text(cf.path)
        findings.extend(scan_text(str(cf.path), str(cf.path), text, cf.kind))
    return findings
