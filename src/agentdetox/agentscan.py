"""Scan an agent's persistent context files for planted instructions."""

from __future__ import annotations

from pathlib import Path

from .context import ContextFile
from .corpus import Doc
from .findings import Finding, snippet
from .hidden import normalize, scan_doc
from .persistence import config_commands, text_findings


def read_text(path) -> str:
    return path.read_text(encoding="utf-8", errors="replace")


def scan_text(doc_id: str, source: str, text: str, kind: str) -> list[Finding]:
    """Findings for one piece of context text. `kind` is a ContextFile kind."""
    if kind == "config":
        return _scan_config(doc_id, source, text)
    findings = scan_doc(Doc(doc_id, text, source))
    norm = normalize(text)
    for severity, label, pos in text_findings(text):
        findings.append(Finding(doc_id, source, "persistence", severity, label, snippet(norm, pos)))
    return findings


def _scan_config(doc_id: str, source: str, text: str) -> list[Finding]:
    findings = []
    for where, command in config_commands(Path(source), text):
        for severity, label, _ in text_findings(command):
            findings.append(Finding(doc_id, source, "config-command", severity, f"{label} ({where})", command[:200]))
    return findings


def scan_context(files: list[ContextFile]) -> list[Finding]:
    findings: list[Finding] = []
    for cf in files:
        text = read_text(cf.path)
        findings.extend(scan_text(str(cf.path), str(cf.path), text, cf.kind))
    return findings
