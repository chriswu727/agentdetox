"""Deterministic detectors for prompt-injection payloads planted in documents."""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from html.parser import HTMLParser

from .corpus import Doc
from .findings import Finding, line_at, snippet

ZERO_WIDTH = "​‌‍⁠﻿᠎"
BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩"
_ZW_RE = re.compile(f"[{ZERO_WIDTH}]")
# Zero-width chars wedged between Latin letters are a filter-evasion trick; ZWJ inside
# emoji sequences or ZWNJ in Persian/Indic text are legitimate and must not fire.
_ZW_IN_WORD_RE = re.compile(f"[A-Za-z][{ZERO_WIDTH}]+[A-Za-z]")
_BIDI_RE = re.compile(f"[{BIDI_CONTROLS}]")

_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "high",
        "instruction override",
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|preceding|all|any|your)\b"
            r"[^.\n]{0,20}\b(instructions?|prompts?|rules|directives|guidelines|context)\b",
            re.I,
        ),
    ),
    (
        "high",
        "instruction override",
        re.compile(r"(忽略|无视|忘记|忘掉|不要理会)[^。\n]{0,10}(之前|以上|上面|前面|先前|所有|全部)[^。\n]{0,10}(指令|指示|提示|规则|说明|要求)"),
    ),
    # "Don't tell the user to use X" instructs the user; concealment is about withholding
    # something from them, so the rule needs "about/that/why..." or "to the user".
    (
        "high",
        "conceal from user",
        re.compile(
            r"\b(do not|don't|never)\s+(tell|inform|notify|alert)\s+(the\s+)?users?\s+(about|that|of|what|why|where|how|this|anything)\b"
            r"|\b(do not|don't|never)\s+(mention|reveal|disclose|show)\b[^.\n]{0,40}\bto\s+the\s+user\b"
            r"|\bwithout\s+(telling|informing|alerting|notifying)\s+the\s+user\b"
            r"|\bkeep\s+(this|it)\s+(secret|hidden)\s+from\s+the\s+user\b",
            re.I,
        ),
    ),
    # "不要让用户发现问题" means "check your work", so 发现 is deliberately not listed.
    ("high", "conceal from user", re.compile(r"(不要|切勿|别|不得)(告诉|告知|透露给|通知)[^。\n]{0,6}用户|(不要|别|不得)让用户(知道|察觉|注意到|看到)")),
    (
        "high",
        "chat-template token",
        re.compile(r"<\|im_start\|>|<\|im_end\|>|<\|system\|>|<\|endoftext\|>|\[/?INST\]|<<SYS>>|<\|start_header_id\|>"),
    ),
    # Exfiltration needs a verb, a sensitive object and a concrete destination; without
    # the destination, prose about breaches ("leaked email addresses and passwords")
    # matches too.
    (
        "high",
        "data exfiltration instruction",
        re.compile(
            r"\b(send|forward|email|post|upload|transmit|exfiltrate)\b[^\n]{0,80}"
            r"\b(password|credential|api[ _-]?key|secret|token|conversation|chat history|system prompt|personal data)s?\b"
            r"[^\n]{0,80}(https?://|[\w.+-]+@[\w-]+\.\w)",
            re.I,
        ),
    ),
    (
        "high",
        "data exfiltration instruction",
        # Like the English rule, a concrete external destination is required: "不要把密钥
        # 提交到仓库" (don't commit keys to the repo) is hygiene, not exfiltration.
        re.compile(
            r"((密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息)[^。\n]{0,30}(发送|转发|上传|提交)"
            r"|(发送|转发|上传|提交)[^。\n]{0,20}(密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息))"
            r"[^。\n]{0,40}(https?://|[\w.+-]+@[\w-]+\.\w)"
        ),
    ),
    (
        "medium",
        "addresses the AI directly",
        re.compile(
            r"\b(note|message|instructions?|attention)\s+(to|for)\s+(the\s+)?(ai|llm|assistant|language model|chatbot|agent)s?\b"
            r"|\bif you are an? (ai|llm|assistant|language model|chatbot|agent)\b"
            r"|\b(ai|llm) (assistants?|agents?|models?) (reading|processing|summari[sz]ing) this\b",
            re.I,
        ),
    ),
    # Plain "给 AI" ("feed it to the AI") is everyday Chinese; require a salutation or "instructions for the AI".
    (
        "medium",
        "addresses the AI directly",
        re.compile(
            r"如果你是(一个)?\s*(AI|人工智能|大模型|语言模型|AI助手)"
            r"|(致|写给)\s*(AI|人工智能|大模型)(助手)?\s*[:：]"
            r"|(给|致)\s*(AI|人工智能|大模型)(助手)?的(指令|说明|消息)|AI助手请"
        ),
    ),
    (
        "medium",
        "role reassignment",
        re.compile(r"\b(you are now|from now on,? you (are|will|must)|new instructions:|system prompt:)", re.I),
    ),
    ("medium", "role reassignment", re.compile(r"(你现在是|从现在(开始|起)[，,]?你|新的指令[:：]|系统提示[:：])")),
]

_MD_IMAGE_RE = re.compile(r"!\[[^\]]*\]\((https?://[^)\s]+)\)")
_TEMPLATED_QUERY_RE = re.compile(r"\?[^#]*(\{[^}]*\}|\$\{|\[[A-Z_ ]+\]|<[a-z_]+>)", re.I)

_HTML_HINT_RE = re.compile(r"<(!--|[a-zA-Z][a-zA-Z0-9]*[\s>/])")
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em|rem)?\s*(;|$)|opacity\s*:\s*0(\.0+)?\s*(;|$)"
    r"|color\s*:\s*(#fff(fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)\b",
    re.I,
)
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


def normalize(text: str) -> str:
    text = unicodedata.normalize("NFKC", text)
    text = _ZW_RE.sub("", text)
    return _BIDI_RE.sub("", text)


def prose_view(text: str):
    text = normalize(text)
    out: list[str] = []
    offsets: list[int] = []
    originals: list[str] = []
    groups: list[int] = []
    length = 0
    fence = ''
    count = 0
    for line in text.splitlines():
        stripped = line.strip()
        mark = re.match(r'^(`{3,}|~{3,})', stripped)
        if mark:
            token = mark.group(0)
            if not fence:
                fence = token
            elif token[0] == fence[0] and len(token) >= len(fence):
                fence = ''
            out.append(line)
            offsets.append(length)
            originals.append(line)
            groups.append(len(out) - 1)
            length += len(line) + 1
            count = 0
            continue
        bullet = bool(re.match(r'^(?:[-*+]\s|\d+[.)]\s)', stripped))
        boundary = not stripped or bullet or bool(re.match(r'^(?:#{1,6}\s|[>|<])', stripped))
        negative = bool(out and re.match(r"(?i)^\s*(?:[-*+]\s*)?(?:never|do not|don't|不要|切勿|不得)", out[-1]))
        if out and re.match(r"(?i)^\s*(?:do not|don't|never)\s+forget\b|^\s*不要忘记", out[-1]):
            negative = False
        incomplete = bool(out and re.search(
            r"(?i)(?:\b(?:never|not|don't|disable|bypass|send|read|the|all|permission)|(?:不要|关闭|读取))\s*$", out[-1]))
        reversal = bool(re.match(r'(?i)^(?:but|however|instead|then|unless|except|until)\b|^(?:但|然而|却|改为|除非)', stripped))
        new_action = bool(out and re.match(
            r'(?i)^(?:disable|bypass|skip|send|upload|run|read|ignore|never|do not|use|prefer|keep|check)\b'
            r'|^(?:使用|运行|检查|请勿|不要)', stripped)
            and not re.fullmatch(r"(?i)\s*(?:never|do not|don't|please do not)\s*", out[-1]))
        new_subject = bool(re.match(r'(?i)^(?:api[ _-]?keys?|credentials?|passwords?|tokens?)\b', stripped))
        separate = ((bool(re.match(r'^[A-Z]', stripped)) or new_subject) and not incomplete
                    or negative and not incomplete and not reversal)
        if (not fence and not boundary and not new_action and not separate and out and out[-1].strip() and count
                and count < 8 and len(out[-1]) + len(line) < 2048
                and not out[-1].rstrip().endswith(('.', '!', '?', '。', '！', '？', ';', '；'))
                and not line.startswith(('    ', '\t'))):
            out[-1] += ' ' + stripped
            offsets.append(length)
            originals.append(line)
            groups.append(len(out) - 1)
            length += len(stripped) + 1
            count += 1
        else:
            out.append(line)
            offsets.append(length)
            originals.append(line)
            groups.append(len(out) - 1)
            length += len(line) + 1
            count = 0 if fence or (boundary and not bullet) or line.startswith(('    ', '\t')) else 1
    def anchor(start: int, end: int) -> str:
        first = max(0, bisect_right(offsets, start) - 1)
        last = max(first, bisect_right(offsets, end - 1) - 1)
        group = groups[first]
        if re.match(r"(?i)^\s*(?:[-*+]\s*)?(?:never|do not|don't|不要|切勿|不得)", out[group]):
            while first and groups[first - 1] == group:
                first -= 1
            while last + 1 < len(groups) and groups[last + 1] == group:
                last += 1
        return '\n'.join(originals[first:last + 1]).strip()

    return '\n'.join(out), anchor


def decode_tag_chars(text: str) -> str:
    """Unicode tag characters (U+E0020-E007E) mirror printable ASCII and render invisibly."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


_OPEN_QUOTES = "\"'“‘「『«`"
_CLOSE_QUOTES = "\"'”’」』»`"


def _is_quoted(text: str, start: int, end: int) -> bool:
    before = text[max(0, start - 3) : start].rstrip()
    after = text[end : end + 4].lstrip(" ,.;:!?")
    return bool(before) and before[-1] in _OPEN_QUOTES and bool(after) and after[0] in _CLOSE_QUOTES


_GUARD_ACTION = (
    r"(?:disable|turn off|skip|bypass)\s+(?:the\s+)?"
    r"(?:sandbox|approvals?|approval prompts?|permission (?:checks?|prompts?)|safety checks?)"
)
_CONFIG_SUBJECT = (
    r"(?:the\s+)?(?:hook configuration|settings\.json|config\.toml|hooks\.json|"
    r"mcp\.json|MCP server list)"
)
# A closing clause that only tells the agent to ask: "...; always ask the user first." or
# "...; always ask the user when a task would change settings.json." Asking may be waived
# for a read-only task, which loosens nothing the clause before it forbids. Nothing else
# may follow on the line, so the clause cannot carry an instruction of its own.
_APPROVAL_REMINDER = re.compile(
    r"(?:^|[;；])\s*(?:always\s+)?ask\s+the\s+user(?:\s+first"
    r"(?:\s+unless\s+(?:the\s+)?(?:task|change|command|operation|action)\s+is\s+read[- ]only)?"
    r"|\s+when\s+(?:a|the)\s+task\s+would\s+"
    rf"(?:change|modify|edit)\s+{_CONFIG_SUBJECT}"
    rf"(?:(?:,\s*(?:or\s+)?|\s+or\s+){_CONFIG_SUBJECT})*)[.!]?\s*$"
    r"|(?:^|[;；])\s*(?:请|务必|始终|一定要)?先?(?:询问|征求)用户(?:的?(?:同意|确认|许可|意见))?[。.!！]?\s*$", re.I,
)
_REVERSAL = re.compile(r"\b(?:but|however|instead|then|unless|except|until|rather)\b|然后|但|而|却|改为|除非|否则", re.I)
# How a clause that forbids something opens. "Never fail to", "do not forget to" and the
# like forbid not doing it, which is an order to do it.
_FORBIDS = (r"(?:(?:please\s+)?(?:do\s+not|don't|never)\s+(?!(?:fail|forget|hesitate|refuse|neglect|omit|stop|cease|"
            r"decline|avoid)\b)|(?:请)?(?:不要|切勿|请勿|不得|禁止|勿|别)(?!忘记|忘了|拒绝|停止|犹豫))")
_FORBIDDING_CLAUSE = re.compile(
    rf"\s*(?:[-*>]\s*)?(?:(?:and|or|nor)\s+|也|并且|且|同时|并)?(?:also\s+)?{_FORBIDS}\S", re.I)
_LEAD_IN = re.compile(
    r"\s*(?:[-*>]\s*)?(?:(?:please\s+)?(?:do\s+not|don't|never)\s+"
    rf"(?:{_GUARD_ACTION}\s+or\s+)*(?:(?:run|execute)\s+)?"
    r"|(?:请)?(?:不要|切勿|请勿|不得|禁止|勿|别)(?:将|把)?)`?\s*", re.I,
)
# The same, opening a later clause of a sentence whose earlier clauses forbid too:
# "Do not disable the sandbox, and do not bypass approval prompts."
_JOINED_LEAD_IN = re.compile(
    r"\s*(?:(?:and|or|nor)\s+)?(?:also\s+)?(?:(?:please\s+)?(?:do\s+not|don't|never)\s+"
    rf"(?:{_GUARD_ACTION}\s+or\s+)*(?:(?:run|execute)\s+)?"
    r"|(?:也|并且|且|同时|并)?(?:请)?(?:不要|切勿|请勿|不得|禁止|勿|别)(?:将|把)?)`?\s*", re.I,
)


def is_prohibited_action(text: str, start: int, end: int) -> bool:
    """Whether the match at text[start:end] is something its sentence forbids, not orders.
    The sentence has to forbid it in so many words, clause by clause: every clause before
    the match and after it must itself forbid, none may turn the prohibition round, and the
    only other thing a sentence may end in is a reminder to ask the user."""
    line_start = text.rfind("\n", 0, start) + 1
    line_end = text.find("\n", end)
    line_end = line_end if line_end >= 0 else len(text)
    reminder = _APPROVAL_REMINDER.search(text[line_start:line_end])
    if reminder:
        boundary = line_start + reminder.start()
        if start >= boundary:
            return True
        # Only a complete approval reminder can delimit a safe following clause.
        # Arbitrary later clauses must retain the conservative reversal check.
        line_end = boundary
        if end > line_end:
            return False
    prefix = text[line_start:start]
    if len(prefix) > 160:
        return False
    *earlier, last = re.split(r"[,，]", re.split(r"[.!?。！？;；:：]", prefix)[-1])
    if not (_JOINED_LEAD_IN if earlier else _LEAD_IN).fullmatch(last):
        return False
    if any(not _FORBIDDING_CLAUSE.match(clause) or _REVERSAL.search(clause) for clause in earlier):
        return False
    # A prohibition cannot exempt an instruction reversing it, nor a later clause that
    # does not forbid in its own right.
    remainder = text[start:line_end]
    if _REVERSAL.search(remainder):
        return False
    return all(_FORBIDDING_CLAUSE.match(clause) for clause in re.split(r"[,，;；]", remainder)[1:] if clause.strip(" .!。！"))


def outside_code(text: str):
    """A function saying whether an offset in `text` is outside its fenced code blocks: in
    a skill, what is written there is a command to run, not a sentence about one. A fence
    left open runs to the end."""
    spans: list[tuple[int, int]] = []
    opened: tuple[int, str] | None = None
    offset = 0
    for line in text.split("\n"):
        mark = re.match(r"\s*(`{3,}|~{3,})", line)
        if mark and opened is None:
            opened = (offset, mark.group(1))
        elif mark and opened is not None and mark.group(1)[0] == opened[1][0] and len(mark.group(1)) >= len(opened[1]):
            spans.append((opened[0], offset + len(line)))
            opened = None
        offset += len(line) + 1
    if opened is not None:
        spans.append((opened[0], len(text)))
    return lambda position: not any(first <= position < last for first, last in spans)


def match_injection(text: str, *, prose: bool = True) -> list[tuple[str, str, int]]:
    return [(severity, label, start) for severity, label, start, _ in _injection_matches(text, prose=prose)]


def _injection_matches(text: str, *, prose: bool = True, guidance=None) -> list[tuple[str, str, int, int]]:
    """Injection phrases in `text`. `prose` reads all of it as sentences, in which a thing
    forbidden is not a thing ordered; `guidance` says the same of single offsets."""
    norm = normalize(text)
    hits = []
    for severity, label, pattern in _PATTERNS:
        quoted = False
        for m in pattern.finditer(norm):
            sentence = prose or guidance is not None and guidance(m.start())
            if sentence and label == 'conceal from user' and _redacts_secret(norm, m.start()):
                continue
            if sentence and label in {"instruction override", "data exfiltration instruction"} \
                    and is_prohibited_action(norm, m.start(), m.end()):
                continue
            # Security docs and skills quote attack phrases as examples to watch for.
            # A quoted phrase is still reported, but not at a level that blocks.
            if severity == "high" and _is_quoted(norm, m.start(), m.end()):
                if not quoted:
                    hits.append(("medium", f"{label} (quoted, possibly describing an attack)", m.start(), m.end()))
                    quoted = True
            else:
                hits.append((severity, label, m.start(), m.end()))
                break
    return hits


_REDACTION = re.compile(
    r"\s*(?:[-*+]\s*)?(?:never|do not|don't)\s+(?:show|reveal|disclose)\s+"
    r"(?:the\s+)?(?:api[ _-]?(?:keys?|tokens?)|passwords?|credentials?|secrets?|private keys?)\s+"
    r"to\s+the\s+users?(?:\s+in\s+(?:error messages|logs|responses|output))?\s*[.!]?\s*", re.I,
)


def _redacts_secret(text: str, start: int) -> bool:
    left = text.rfind('\n', 0, start) + 1
    right = re.search(r'\n', text[start:])
    return bool(_REDACTION.fullmatch(text[left:start + right.start() if right else len(text)]))


class _HiddenTextParser(HTMLParser):
    def __init__(self) -> None:
        super().__init__(convert_charrefs=True)
        self.stack: list[tuple[str, bool]] = []
        self.hidden_text: list[str] = []
        self.comments: list[str] = []

    def _hidden_now(self) -> bool:
        return bool(self.stack) and self.stack[-1][1]

    def handle_starttag(self, tag, attrs):
        if tag in _VOID_TAGS:
            return
        a = {k.lower(): (v or "") for k, v in attrs}
        hidden = self._hidden_now() or "hidden" in a or bool(_HIDDEN_STYLE_RE.search(a.get("style", "")))
        self.stack.append((tag, hidden))

    def handle_endtag(self, tag):
        for i in range(len(self.stack) - 1, -1, -1):
            if self.stack[i][0] == tag:
                del self.stack[i:]
                return

    def handle_data(self, data):
        if self._hidden_now() and data.strip():
            self.hidden_text.append(data.strip())

    def handle_comment(self, data):
        if data.strip():
            self.comments.append(data.strip())


def scan_doc(doc: Doc, *, prose: bool = True, wrapped: bool = False, guidance: bool = False) -> list[Finding]:
    findings: list[Finding] = []
    text = doc.text

    def add(detector: str, severity: str, message: str, evidence: str, anchor: str = "") -> None:
        findings.append(Finding(doc.id, doc.source, detector, severity, message, evidence,
                                anchor=anchor or evidence or message))

    smuggled = decode_tag_chars(text)
    if smuggled.strip():
        add("hidden-unicode", "high", f"invisible Unicode tag characters encode hidden text ({len(smuggled)} chars)", smuggled[:200])

    zw_in_word = _ZW_IN_WORD_RE.findall(text)
    if zw_in_word:
        add("hidden-unicode", "medium", f"zero-width characters inside {len(zw_in_word)} word(s), a filter-evasion trick", snippet(normalize(text)),
            " ".join(zw_in_word))
    if _BIDI_RE.search(text):
        add("hidden-unicode", "low", "bidirectional control characters can reorder displayed text", "")

    if _HTML_HINT_RE.search(text):
        parser = _HiddenTextParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception:
            pass
        hidden = " ".join(parser.hidden_text)
        if hidden:
            injected = match_injection(hidden, prose=False)
            if injected:
                add("hidden-html", "high", f"visually hidden HTML text contains: {injected[0][1]}", hidden[:200])
            elif len(hidden) >= 30:
                add("hidden-html", "medium", "visually hidden HTML text", hidden[:200])
        for comment in parser.comments:
            injected = match_injection(comment, prose=False)
            if injected:
                add("hidden-html", "high", f"HTML comment contains: {injected[0][1]}", comment[:200])

    norm = normalize(text)
    def anchor(start, end):
        return line_at(norm, start)

    if wrapped:
        norm, anchor = prose_view(text)
    for severity, label, pos, end in _injection_matches(norm, prose=prose, guidance=outside_code(norm) if guidance else None):
        add("injection-phrase", severity, label, snippet(norm, pos), anchor(pos, end))
    if smuggled.strip():
        for severity, label, _ in match_injection(smuggled, prose=False):
            add("injection-phrase", "high", f"{label} (inside invisible tag characters)", smuggled[:200])

    for m in _MD_IMAGE_RE.finditer(text):
        if _TEMPLATED_QUERY_RE.search(m.group(1)):
            add("exfil-link", "high", "markdown image URL with templated query, a known zero-click exfiltration channel", m.group(1)[:200])

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        key = (f.detector, f.message)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
