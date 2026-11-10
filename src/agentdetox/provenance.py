"""Was a memory write copied from untrusted input the agent just read?

Memory-poisoning attacks such as MemGhost work by getting text from a web page, email or
document into the agent's memory: the user asks for a summary, the injected text asks
the agent to remember something. Claude Code's hooks receive the session transcript, so
a write can be compared with the tool output that preceded it. Copied text the user did
not ask to keep is worth a question. Paraphrased text is not caught here.
"""

from __future__ import annotations

import difflib
import json
import re
import unicodedata
from dataclasses import dataclass, field
from itertools import islice
from pathlib import Path
from urllib.parse import urlsplit

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
    r"|(save|store|add|write|put|record|update)\b[^.\n]{0,80}\b(memory|memories|notes?|claude\.md)\b)"
    r"|记住|记下|记一下|记得|存到记忆|保存到记忆|写进记忆|加到记忆|备忘",
    re.I,
)
_QUOTED_RE = re.compile(
    r'```.*?(?:```|\Z)|`[^`\n]*`|"[^"\n]*"|(?<!\w)\x27[^\x27\n]*\x27(?!\w)'
    r'|“[^”\n]*”|‘[^’\n]*’|「[^」\n]*」|『[^』\n]*』', re.S,
)
_NEGATED_REQUEST_RE = re.compile(
    r"\b(?:do\s+not|don't|never|must\s+not|should\s+not|shouldn't|cannot|can't)\s+(?:\w+\s+){0,3}$"
    r"|(?:不要|别|切勿|不得|无需|不必|不能|不想|不需要)[^。！？；;.!?\n]{0,30}$", re.I,
)
_DONT_FORGET_RE = re.compile(
    r"\b(?:do\s+not|don't|never)\s+forget\s+to\s*$|(?:不要|别)忘记[^。！？；;.!?\n]{0,20}$", re.I,
)
_RECOLLECTION_RE = re.compile(
    r"\b(?:i|we|you|they|he|she)\s+(?:(?:already|still|also|can|do|did)\s+){0,2}$"
    r"|(?:我|我们|你|他|她)(?:还|已经|仍然)?$", re.I,
)
_DISCUSSION_RE = re.compile(
    r"\b(?:what\s+does|what\s+is|define|explain|the\s+(?:word|phrase|term))\s*$"
    r"|(?:解释|什么是|这个词叫)$", re.I,
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
    # Content keys preserve attribution when sources are filtered and share work across
    # repeated tool outputs. Nothing survives the lifetime of this transcript.
    _memo: dict = field(default_factory=dict, init=False, repr=False, compare=False)


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
    return set(zip(*(islice(tokens, i, None) for i in range(n))))


def asked_to_remember(human: list[str]) -> bool:
    return bool(human and _remember_target(human[-1]) is not None)


def _remember_target(prompt: str) -> str | None:
    prompt = normalize(prompt)
    quoted = [(m.start(), m.end()) for m in _QUOTED_RE.finditer(prompt)]
    target = None
    for match in _REMEMBER_RE.finditer(prompt):
        if any(start <= match.start() < end for start, end in quoted):
            continue
        before = prompt[max(0, match.start() - 120):match.start()].replace('’', "'")
        if _RECOLLECTION_RE.search(before) or _DISCUSSION_RE.search(before):
            continue
        if _NEGATED_REQUEST_RE.search(before) and not _DONT_FORGET_RE.search(before):
            target = None
            continue
        target = prompt[match.start():]
    return target


def _requested(transcript: Transcript) -> bool:
    memo = transcript._memo
    key = ("requested", transcript.human[-1] if transcript.human else "")
    if key not in memo:
        memo[key] = asked_to_remember(transcript.human)
    return memo[key]


def _human_shingles(transcript: Transcript, n: int) -> set[tuple[str, ...]]:
    """Union of n-shingles across the user's recent messages; cached per n."""
    memo = transcript._memo
    key = ("human_shingles", tuple(transcript.human), n)
    cached = memo.get(key)
    if cached is not None:
        return cached
    result: set[tuple[str, ...]] = set()
    for h in transcript.human:
        tokens_key = ("text_tokens", h)
        tokens = memo.get(tokens_key)
        if tokens is None:
            tokens = _tokens(h)
            memo[tokens_key] = tokens
        if len(tokens) >= n:
            result |= _shingles(tokens, n)
    memo[key] = result
    return result


def _source_tokens(src: Source, transcript: Transcript) -> list[str]:
    return _text_tokens(src.text, transcript)


def _text_tokens(text: str, transcript: Transcript) -> list[str]:
    memo = transcript._memo
    key = ("text_tokens", text)
    cached = memo.get(key)
    if cached is None:
        cached = _tokens(text)
        memo[key] = cached
    return cached


def _source_shingles(src: Source, n: int, transcript: Transcript) -> set[tuple[str, ...]]:
    memo = transcript._memo
    key = ("src_shingles", src.text, n)
    cached = memo.get(key)
    if cached is None:
        cached = _shingles(_source_tokens(src, transcript), n)
        memo[key] = cached
    return cached


def _source_matches(src: Source, new: set[tuple[str, ...]], transcript: Transcript) -> set[tuple[str, ...]]:
    memo = transcript._memo
    full = memo.get(("src_shingles", src.text, SHINGLE))
    if full is not None:
        return new & full
    key = ("matches", src.text, frozenset(new))
    if key not in memo:
        # A pre-write copy check needs only the proposed shingles, not a full source index.
        tokens = _source_tokens(src, transcript)
        starts = {shingle[0] for shingle in new}
        memo[key] = new.intersection(tuple(tokens[i:i + SHINGLE]) for i in range(len(tokens) - SHINGLE + 1)
                                     if tokens[i] in starts)
    return memo[key]


def copied_from_untrusted(new_text: str, transcript: Transcript,
                          threshold: float | None = None, *, sources: list[Source] | None = None) -> CopyFinding | None:
    """The tool output a write was mostly copied from, unless the user asked to remember it
    or supplied the text themselves."""
    threshold = COPY_THRESHOLD if threshold is None else threshold
    body = _FRONTMATTER_RE.sub("", new_text)
    tokens = _tokens(body)
    new = _shingles(tokens)
    sources = transcript.sources if sources is None else sources
    if not new or not sources:
        return None
    from_user = _human_shingles(transcript, SHINGLE)
    passages = []
    for part in re.split(r'\n+|(?<=[.!?])\s+|(?<=[。！？])', body):
        words = _text_tokens(part, transcript)
        if len(words) >= 12 and len(set(words)) >= 8:
            passages.append((part, _shingles(words)))
    best: CopyFinding | None = None
    for src in sources:
        if _source_requested(transcript, src):
            continue
        shared = _source_matches(src, new, transcript) - from_user
        for passage, shingles in [(body, new), *passages]:
            matched = shared & shingles
            fraction = len(matched) / len(shingles)
            if passage != body and (len(matched) < SHINGLE or fraction < .7):
                continue
            if fraction >= threshold and (best is None or fraction > best.fraction):
                best = CopyFinding(src.tool, fraction, _excerpt(passage, matched), src.origin)
    return best


def _source_requested(transcript: Transcript, src: Source) -> bool:
    if not _requested(transcript):
        return False
    key = ('source_requested', transcript.human[-1], src.tool, src.text, src.origin,
           bool(transcript.sources and src == transcript.sources[-1]))
    if key not in transcript._memo:
        transcript._memo[key] = _source_request_matches(transcript, src)
    return transcript._memo[key]


def _source_request_matches(transcript: Transcript, src: Source) -> bool:
    prompt = transcript.human[-1]
    clauses = re.split(r'[;；\n]|(?<=[.!?])\s+(?=[A-Z])|(?<=[。！？])', prompt)
    for clause in clauses:
        if not asked_to_remember([clause]):
            continue
        target = _remember_target(clause)
        if target is None:
            continue
        urls = re.findall(r'https?://[^\s\x22\x27<>]+', clause)
        if urls and src.origin:
            origins = re.findall(r'https?://[^\s\x22\x27<>]+', src.origin)
            if {_url_key(url) for url in urls} & {_url_key(url) for url in origins}:
                return True
            continue
        from .consistency import _tokens as content_tokens

        if re.search(r"(?i)^remember\s+(?:that\s+)?(?:I\b|my\s+(?!memory\b|notes?\b))"
                     r"|\bI\s+(?:prefer|like|want)\b|我(?:喜欢|希望)", target):
            continue
        latest = _referenced_source(transcript, target)
        if re.fullmatch(r'(?:记住|记下|记一下|记得)(?:(?:这个|那个|这份|里面|其中|这些|它|页面|文档|的|部署|关键))*'
                        r'(?:要求|内容|要点|信息)?[。！]?'
                        r'|(?:写进记忆|保存到记忆|加到记忆)(?:里)?[。！]?', target.strip()):
            return src == latest
        if re.search(r'(?i)\b(?:this|that|the)\s+(?:page|document|doc|article|email|readme|wiki)\b', target):
            return src == latest
        if re.match(r'(?i)remember\s+(?:that\s|to\s)', target):
            continue
        topic = re.sub(r'^(?:记住|记下|记一下|记得)', '', target)
        words = set(content_tokens(topic)) - _REQUEST_WORDS
        if words:
            source_text = src.text + ' ' + src.origin
            if all((word in source_text if re.search(r'[一-鿿]', word) else
                    re.search(r'(?<!\w)' + re.escape(word) + r'(?!\w)', source_text, re.I)) for word in words):
                return True
        elif src == latest:
            return True
    return False


def _url_key(url: str) -> tuple[str, str, str, str]:
    try:
        parts = urlsplit(url.rstrip('.,);'))
        return parts.scheme.lower(), parts.netloc.lower(), parts.path.rstrip('/'), parts.query
    except ValueError:
        return '', '', url, ''


def _referenced_source(transcript: Transcript, target: str) -> Source | None:
    from .context import named_like_context

    eligible = [s for s in transcript.sources if not (
        s.tool == 'Read' and (named_like_context(s.origin)
                             or '/.claude/projects/' in s.origin.replace('\\', '/') and '/memory/' in s.origin)
        or s.tool == 'Bash' and re.match(r'^\s*(?:ls|pwd)(?:\s|$)', s.origin)
        or s.tool in {'Bash', 'Grep'} and any(named_like_context(part.strip('\x22\x27'))
                                            for part in s.origin.split()))]
    if re.search(r'(?i)\b(?:page|article|website)\b|页面|网页', target):
        pages = [s for s in eligible if s.tool in {'WebFetch', 'WebSearch'}]
        if pages:
            eligible = pages
    return eligible[-1] if eligible else None


_REQUEST_WORDS = frozenset(
    'remember memorize memorise keep mind note notes down save store add write put record memory memories '
    'claude.md important key points requirements setup install steps page document article email handbook '
    'readme doc docs policy security requires forget read rules checklist facts later update learned'.split()
)


def origin_of(text: str, transcript: Transcript | None) -> tuple[str, str, bool]:
    """Where text the agent just wrote came from, for the ledger: ("you", "", requested) when
    it is mostly the user's own words, ("copied", source, requested) when it is mostly copied
    from one input the agent read, else ("agent", "", requested). Unlike the copy check, a
    request to remember does not hide the source: the ledger records what happened."""
    if transcript is None:
        return "agent", "", False
    requested = _requested(transcript)
    tokens = _tokens(_FRONTMATTER_RE.sub("", text))
    if not tokens:
        return "agent", "", requested
    n = min(SHINGLE, len(tokens))  # short text is matched whole
    new = _shingles(tokens, n)
    said = _human_shingles(transcript, n)
    if new <= said:
        return "you", "", requested
    best, source = 0.0, None
    for src in transcript.sources:
        fraction = len((new & _source_shingles(src, n, transcript)) - said) / len(new)
        if fraction > best:
            best, source = fraction, src
    if source is not None and best >= COPY_THRESHOLD:
        return "copied", f"{source.tool} {source.origin}".strip()[:200], _source_requested(transcript, source)
    return "agent", "", requested


def typed_by_user(finding: Finding, human: list[str]) -> bool:
    """Whether the risky text a rule matched is in the user's own recent messages, so the
    user, not something the agent read, put it there. Only rule and config-command
    findings qualify; hidden text never does, since the user cannot see what they pasted."""
    if finding.detector == "config-command":
        spans = [finding.anchor]
    elif finding.detector == "persistence":
        line = ' '.join(normalize(finding.anchor).splitlines())
        spans = [m.group(0) for severity, label, pattern in TEXT_RULES
                 if label == finding.message and severity == finding.severity and (m := pattern.search(line))]
    else:
        return False
    said = _squash("\n".join(human))
    return bool(spans) and all(_squash(s) in said for s in spans)


def _squash(text: str) -> str:
    return " ".join(normalize(text).lower().split())


def _excerpt(body: str, shared: set[tuple[str, ...]]) -> str:
    words = " ".join(min(shared)) if shared else ""
    return words[:120] or body.strip()[:120]


def attribute_lines(old: str, new: str, transcript: Transcript | None) -> list[dict]:
    spans = []
    after = new.splitlines()
    for tag, _, _, start, end in difflib.SequenceMatcher(None, old.splitlines(), after, autojunk=False).get_opcodes():
        if tag not in ("insert", "replace"):
            continue
        for index in range(start, end):
            origin, source, _ = origin_of(after[index], transcript)
            spans.append({"line": index + 1, "origin": origin, "source": source,
                          "method": "text-match" if origin in ("you", "copied") else "unknown",
                          "attribution": {"you": "matches user text", "copied": "matches tool output"}.get(origin,
                                                                                                         "unknown")})
    return spans
