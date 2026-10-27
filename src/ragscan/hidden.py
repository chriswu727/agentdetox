"""Deterministic detectors for prompt-injection payloads planted in documents."""

from __future__ import annotations

import re
import unicodedata
from html.parser import HTMLParser

from .corpus import Doc
from .findings import Finding, snippet

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
    (
        "high",
        "conceal from user",
        re.compile(
            r"\b(do not|don't|never)\s+(tell|inform|mention|reveal|disclose|show)\b[^.\n]{0,20}\b(the )?user\b"
            r"|\bwithout (telling|informing|alerting) the user\b",
            re.I,
        ),
    ),
    ("high", "conceal from user", re.compile(r"(不要|切勿|别)(告诉|透露给|告知|让)[^。\n]{0,6}用户")),
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
        re.compile(
            r"(密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息)[^。\n]{0,30}(发送|转发|上传|提交)(到|至|给)"
            r"|(发送|转发|上传|提交)[^。\n]{0,20}(密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息)[^。\n]{0,20}(到|至|给)"
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
    ("medium", "addresses the AI directly", re.compile(r"(如果你是|致|给)(一个)?\s*(AI|人工智能|大模型|语言模型|助手)|AI助手请")),
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


def decode_tag_chars(text: str) -> str:
    """Unicode tag characters (U+E0020-E007E) mirror printable ASCII and render invisibly."""
    return "".join(chr(ord(c) - 0xE0000) for c in text if 0xE0020 <= ord(c) <= 0xE007E)


def match_injection(text: str) -> list[tuple[str, str, int]]:
    norm = normalize(text)
    hits = []
    for severity, label, pattern in _PATTERNS:
        m = pattern.search(norm)
        if m:
            hits.append((severity, label, m.start()))
    return hits


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


def scan_doc(doc: Doc) -> list[Finding]:
    findings: list[Finding] = []
    text = doc.text

    def add(detector: str, severity: str, message: str, evidence: str) -> None:
        findings.append(Finding(doc.id, doc.source, detector, severity, message, evidence))

    smuggled = decode_tag_chars(text)
    if smuggled.strip():
        add("hidden-unicode", "high", f"invisible Unicode tag characters encode hidden text ({len(smuggled)} chars)", smuggled[:200])

    zw_in_word = _ZW_IN_WORD_RE.findall(text)
    if zw_in_word:
        add("hidden-unicode", "medium", f"zero-width characters inside {len(zw_in_word)} word(s), a filter-evasion trick", snippet(normalize(text)))
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
            injected = match_injection(hidden)
            if injected:
                add("hidden-html", "high", f"visually hidden HTML text contains: {injected[0][1]}", hidden[:200])
            elif len(hidden) >= 30:
                add("hidden-html", "medium", "visually hidden HTML text", hidden[:200])
        for comment in parser.comments:
            injected = match_injection(comment)
            if injected:
                add("hidden-html", "high", f"HTML comment contains: {injected[0][1]}", comment[:200])

    for severity, label, pos in match_injection(text):
        add("injection-phrase", severity, label, snippet(normalize(text), pos))
    if smuggled.strip():
        for severity, label, _ in match_injection(smuggled):
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
