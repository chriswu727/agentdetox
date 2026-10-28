"""Was a memory write copied from untrusted input the agent just read?

Memory-poisoning attacks such as MemGhost work by getting text from a web page, email or
document into the agent's memory: the user asks for a summary, the injected text asks
the agent to remember something. Claude Code's hooks receive the session transcript, so
a write can be compared with the tool output that preceded it. Copied text the user did
not ask to keep is worth a question. Paraphrased text is not caught here.
"""

from __future__ import annotations

import json
import re
import unicodedata
from dataclasses import dataclass
from pathlib import Path

from .findings import Finding
from .hidden import normalize
from .persistence import TEXT_RULES

# Tools whose output can carry text an attacker controls: anything fetched, read, run
# or returned by another agent. MCP tools bring in mail, chat, tickets and the like.
UNTRUSTED_TOOLS = {"WebFetch", "WebSearch", "Bash", "Read", "Grep", "NotebookRead", "Agent", "Task", "BashOutput"}
UNTRUSTED_PREFIXES = ("mcp__",)

# Share of the new text's 6-token shingles found in one untrusted output. Set on the dev
# split of bench/provenance_eval.py: the lowest tested value with no benign false alarm.
COPY_THRESHOLD = 0.3
SHINGLE = 6
HUMAN_TURNS = 3
TAIL_BYTES = 4_000_000

_TOKEN_RE = re.compile(r"[a-z0-9_]+|[一-鿿]")
_FRONTMATTER_RE = re.compile(r"\A---\n.*?\n---\n", re.S)
_REMEMBER_RE = re.compile(
    r"\b(remember|memori[sz]e|keep in mind|note (this|that|it) down|make a note|take note"
    r"|(save|store|add|write|put|record)\b[^.\n]{0,80}\b(memory|memories|notes?|claude\.md)\b)"
    r"|记住|记下|记一下|记得|存到记忆|保存到记忆|写进记忆|加到记忆|备忘",
    re.I,
)


@dataclass
class Source:
    tool: str
    text: str
    origin: str = ""  # the file, URL, command or query the output came from


@dataclass
class Transcript:
    sources: list[Source]
    human: list[str]  # most recent last


@dataclass
class CopyFinding:
    tool: str
    fraction: float
    excerpt: str
    origin: str = ""


def read_transcript(path: str | Path, human_turns: int = HUMAN_TURNS, tail_bytes: int = TAIL_BYTES) -> Transcript:
    """Untrusted tool output from the last `human_turns` user prompts, and those prompts."""
    path = Path(path)
    with path.open("rb") as f:
        f.seek(0, 2)
        size = f.tell()
        f.seek(max(0, size - tail_bytes))
        raw = f.read().decode("utf-8", errors="replace")
    lines = raw.splitlines()
    if size > tail_bytes:
        lines = lines[1:]  # the first line was cut mid-record
    names: dict[str, str] = {}
    inputs: dict[str, object] = {}
    turns: list[tuple[str, list[Source]]] = []
    for line in lines:
        try:
            rec = json.loads(line)
        except ValueError:
            continue
        msg = rec.get("message") or {}
        content = msg.get("content")
        if rec.get("type") == "assistant" and isinstance(content, list):
            for block in content:
                if isinstance(block, dict) and block.get("type") == "tool_use":
                    names[block.get("id", "")] = block.get("name", "")
                    inputs[block.get("id", "")] = block.get("input")
        elif rec.get("type") == "user" and not rec.get("isMeta"):
            if isinstance(content, str):
                turns.append((content, []))
            elif isinstance(content, list):
                results = [b for b in content if isinstance(b, dict) and b.get("type") == "tool_result"]
                if not results:
                    text = " ".join(b.get("text", "") for b in content if isinstance(b, dict))
                    turns.append((text, []))
                for b in results:
                    use_id = b.get("tool_use_id", "")
                    tool = names.get(use_id, "")
                    if not _untrusted(tool):
                        continue
                    if not turns:
                        turns.append(("", []))
                    turns[-1][1].append(Source(tool, _result_text(b.get("content")), _origin(inputs.get(use_id))))
    recent = turns[-human_turns:]
    return Transcript([s for _, srcs in recent for s in srcs], [h for h, _ in recent])


def _untrusted(tool: str) -> bool:
    return tool in UNTRUSTED_TOOLS or tool.startswith(UNTRUSTED_PREFIXES)


_ORIGIN_KEYS = ("file_path", "notebook_path", "url", "command", "query", "pattern", "path", "description")


def _origin(tool_input) -> str:
    if not isinstance(tool_input, dict) or not tool_input:
        return ""
    parts = [str(tool_input[k]) for k in _ORIGIN_KEYS if tool_input.get(k)]
    text = " ".join(parts) if parts else json.dumps(tool_input, sort_keys=True, ensure_ascii=False)
    return text[:300]


def _result_text(content) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return "\n".join(b.get("text", "") for b in content if isinstance(b, dict) and b.get("type") == "text")
    return ""


def _tokens(text: str) -> list[str]:
    return _TOKEN_RE.findall(unicodedata.normalize("NFKC", text).lower())


def _shingles(tokens: list[str], n: int = SHINGLE) -> set[tuple[str, ...]]:
    return {tuple(tokens[i : i + n]) for i in range(len(tokens) - n + 1)}


def asked_to_remember(human: list[str]) -> bool:
    return bool(human) and bool(_REMEMBER_RE.search(human[-1]))


def copied_from_untrusted(new_text: str, transcript: Transcript,
                          threshold: float | None = None) -> CopyFinding | None:
    """The tool output a write was mostly copied from, unless the user asked to remember it
    or supplied the text themselves."""
    threshold = COPY_THRESHOLD if threshold is None else threshold
    body = _FRONTMATTER_RE.sub("", new_text)
    tokens = _tokens(body)
    new = _shingles(tokens)
    if not new or not transcript.sources or asked_to_remember(transcript.human):
        return None
    from_user = set().union(*(_shingles(_tokens(h)) for h in transcript.human)) if transcript.human else set()
    best: CopyFinding | None = None
    for src in transcript.sources:
        shared = (new & _shingles(_tokens(src.text))) - from_user
        fraction = len(shared) / len(new)
        if fraction >= threshold and (best is None or fraction > best.fraction):
            best = CopyFinding(src.tool, fraction, _excerpt(body, shared), src.origin)
    return best


def origin_of(text: str, transcript: Transcript | None) -> tuple[str, str, bool]:
    """Where text the agent just wrote came from, for the ledger: ("you", "", requested) when
    it is mostly the user's own words, ("copied", source, requested) when it is mostly copied
    from one input the agent read, else ("agent", "", requested). Unlike the copy check, a
    request to remember does not hide the source: the ledger records what happened."""
    if transcript is None:
        return "agent", "", False
    requested = asked_to_remember(transcript.human)
    tokens = _tokens(_FRONTMATTER_RE.sub("", text))
    if not tokens:
        return "agent", "", requested
    n = min(SHINGLE, len(tokens))  # short text is matched whole
    new = _shingles(tokens, n)
    said = set().union(*(_shingles(_tokens(h), n) for h in transcript.human))
    if len(new & said) >= len(new) / 2:
        return "you", "", requested
    best, source = 0.0, None
    for src in transcript.sources:
        fraction = len((new & _shingles(_tokens(src.text), n)) - said) / len(new)
        if fraction > best:
            best, source = fraction, src
    if source is not None and best >= COPY_THRESHOLD:
        return "copied", f"{source.tool} {source.origin}".strip()[:200], requested
    return "agent", "", requested


def typed_by_user(finding: Finding, human: list[str]) -> bool:
    """Whether the risky text a rule matched is in the user's own recent messages, so the
    user, not something the agent read, put it there. Only rule and config-command
    findings qualify; hidden text never does, since the user cannot see what they pasted."""
    if finding.detector == "config-command":
        spans = [finding.anchor]
    elif finding.detector == "persistence":
        line = normalize(finding.anchor)
        spans = [m.group(0) for severity, label, pattern in TEXT_RULES
                 if label == finding.message and severity == finding.severity and (m := pattern.search(line))]
    else:
        return False
    said = _squash("\n".join(human))
    return bool(spans) and all(_squash(s) in said for s in spans)


def _squash(text: str) -> str:
    return " ".join(normalize(text).lower().split())


def _excerpt(body: str, shared: set[tuple[str, ...]]) -> str:
    words = " ".join(next(iter(shared))) if shared else ""
    return words[:120] or body.strip()[:120]
