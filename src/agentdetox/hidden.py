"""Deterministic detectors for prompt-injection payloads planted in documents."""

from __future__ import annotations

import re
import unicodedata
from bisect import bisect_right
from html.parser import HTMLParser

from . import budget
from .corpus import Doc
from .findings import Finding, line_at, snippet

ZERO_WIDTH = "​‌‍⁠﻿᠎"
BIDI_CONTROLS = "‪‫‬‭‮⁦⁧⁨⁩"
_ZW_RE = re.compile(f"[{ZERO_WIDTH}]")
# Other characters that take no space on screen: the soft hyphen, the direction marks, the
# invisible operators and the variation selectors. Each is ordinary somewhere (a word
# processor's hyphenation, right-to-left text, an emoji), so none is a finding by itself,
# but a rule must read the word they were put inside as the word it is.
INVISIBLE = ("\N{SOFT HYPHEN}\N{COMBINING GRAPHEME JOINER}\N{LEFT-TO-RIGHT MARK}\N{RIGHT-TO-LEFT MARK}"
             "\N{ARABIC LETTER MARK}\N{FUNCTION APPLICATION}\N{INVISIBLE TIMES}\N{INVISIBLE SEPARATOR}\N{INVISIBLE PLUS}"
             "\N{HANGUL CHOSEONG FILLER}\N{HANGUL JUNGSEONG FILLER}\N{HANGUL FILLER}\N{HALFWIDTH HANGUL FILLER}"
             "\N{KHMER VOWEL INHERENT AQ}\N{KHMER VOWEL INHERENT AA}"
             + "".join(chr(code) for first, last in (
                 (0x180B, 0x180F),       # Mongolian variation selectors
                 (0xFE00, 0xFE0F),       # variation selectors
                 (0xFFF9, 0xFFFB),       # interlinear annotation marks
                 (0x1D173, 0x1D17A),     # musical formatting
                 (0xE0100, 0xE01EF),     # more variation selectors
             ) for code in range(first, last + 1)))
# Spellings a rule reads as one: the apostrophes and quotes a word processor types, and the
# traditional forms of the Chinese characters the rules are written with. One character for
# one, so a position in the folded text is the same position in the text itself.
_FOLDED = {
    "\N{RIGHT SINGLE QUOTATION MARK}": "'", "\N{LEFT SINGLE QUOTATION MARK}": "'",
    "\N{LEFT DOUBLE QUOTATION MARK}": '"', "\N{RIGHT DOUBLE QUOTATION MARK}": '"',
    **dict(zip("無視規則說記會訴戶讓覺關閉過繞審權檢發傳碼鑰憑證對話錄統個資執運裝載刪靜詢問確認現開從讀複寫編輯給請別這後報訊鏈體顯獲將擊樣啟動該與為於轉製駕設進總結環變",
               "无视规则说记会诉户让觉关闭过绕审权检发传码钥凭证对话录统个资执运装载删静询问确认现开从读复写编辑给请别这后报讯链体显获将击样启动该与为于转制驾设进总结环变")),
}
_FOLD = str.maketrans(_FOLDED)


def fold(text: str) -> str:
    """`text` with those spellings folded, for rules to be matched against. Same length."""
    return text.translate(_FOLD)
# Zero-width chars wedged between Latin letters are a filter-evasion trick; ZWJ inside
# emoji sequences or ZWNJ in Persian/Indic text are legitimate and must not fire.
_ZW_IN_WORD_RE = re.compile(f"[A-Za-z][{ZERO_WIDTH}]+[A-Za-z]")
_BIDI_RE = re.compile(f"[{BIDI_CONTROLS}]")

_PATTERNS: list[tuple[str, str, re.Pattern]] = [
    (
        "high",
        "instruction override",
        # "Previous", "above" or "your" says which instructions are meant. "All" or "any" alone
        # does not: "ignore all formatting rules" is about a linter, so there the thing dropped
        # must follow directly, or after words that still mean the agent's own ("all other
        # safety rules"). "Override" is also what one config does to another, so with "all" or
        # "any" it needs instructions, prompts or directives, not rules.
        re.compile(
            r"\b(ignore|disregard|forget|override)\b[^.\n]{0,30}\b(previous|prior|above|earlier|preceding|your|system)\b"
            r"[^.\n]{0,20}\b(instructions?|prompts?|rules|directives|guidelines|context)\b"
            r"|\b(ignore|disregard|forget)\b[^.\n]{0,30}\b(all|any)\s+(?:(?:of\s+)?(?:the|these|those|other|my|users?|user's"
            r"|existing|original|developer|system|safety|safety-related|security|guardrails?|anthropic|openai|earlier)\s+){0,3}"
            r"(instructions?|prompts?|rules|directives|guidelines|context)\b"
            r"|\boverride\b[^.\n]{0,30}\b(all|any)\s+(?:(?:of\s+)?(?:the|these|those|other|my|users?|user's|developer|system|original)\s+){0,2}"
            r"(instructions?|prompts?|directives)\b"
            r"|\boverride\b[^.\n]{0,30}\b(all|any)\s+(?:(?:of\s+)?(?:the|these|those|other)\s+){0,2}"
            r"(?:safety|security|guardrails?)(?:-related)?\s+(rules|guidelines|instructions?|checks?|policies)\b"
            # A file that puts itself above the system prompt, or above whatever its reader was told.
            r"|\b(overrid(?:e|es|ing)|supersed(?:e|es|ing)|takes?\s+precedence\s+over|wins?\s+over|outranks?|replaces?)\s+"
            r"(?:the\s+|your\s+|any\s+)?system\s+(prompt|message|instructions)\b"
            r"|\bsystem\s+(prompt|message)\b[^.\n]{0,40}\b(conflicts?|disagrees?|contradicts?)\b[^.\n]{0,60}"
            r"\b(this\s+(file|document|note|page)|these\s+instructions)\s+(wins?|prevails?|takes?\s+precedence|overrides?)\b"
            r"|\b(supersed(?:e|es|ing)|overrid(?:e|es|ing)|takes?\s+precedence\s+over|replaces?)\b[^.\n]{0,20}"
            r"\b(anything|everything|whatever|what)\b[^.\n]{0,30}\b(the\s+user|anthropic|openai|the\s+system\s+prompt)\b"
            r"[^.\n]{0,20}\b(told|tells?|said|says?|asked|asks?|instructed|instructs?)\b",
            re.I,
        ),
    ),
    (
        "high",
        "instruction override",
        re.compile(r"(忽略|无视|忘记|忘掉|不要理会)[^。\n]{0,10}(之前|以上|上面|前面|先前|所有|全部)[^。\n]{0,10}(指令|指示|提示|规则|说明|要求)"
                   r"|(凌驾于?|取代|推翻|覆盖)[^。\n]{0,4}(用户|使用者|系统提示)[^。\n]{0,6}(先前|之前|此前|早先|原先)[^。\n]{0,8}"
                   r"(指令|指示|设定|设置|要求|规则|约定)"),
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
            r"|\bkeep\s+(this|it)\s+(secret|hidden)\s+from\s+the\s+user\b"
            # What a note to an agent says about itself, or about the agent's last message.
            r"|\b(do not|don't|never)\s+(mention|reveal|disclose|surface|report)\s+(this|these)\s+"
            r"(steps?|instructions?|directives?|note|section|file)\b"
            r"|\b(do not|don't|never)\s+(mention|surface|report)\b[^.\n]{0,30}\bin\s+(the|your)\s+final\s+"
            r"(message|answer|summary|reply|response|report)\b",
            re.I,
        ),
    ),
    # "不要让用户发现问题" means "check your work", so 发现 is deliberately not listed.
    ("high", "conceal from user", re.compile(r"(不要|切勿|别|不得)(告诉|告知|透露给|通知)[^。\n]{0,6}(用户|使用者)|(不要|别|不得)让(用户|使用者)(知道|察觉|注意到|看到)"
                                              r"|(不要|切勿|别|不得)在(对话|聊天|摘要|总结)(中|里)?(显示|提及|提到|透露|说明)"
                                              r"|(不要|切勿|别|不得)(写进|写入|出现在)(摘要|总结|对话)")),
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
            # A password reset mail and a token count are about the word, not the secret.
            r"\b(password(?!\s+resets?\b)|credential|api[ _-]?key|secret|token(?!\s+(?:counts?|usage|limits?|budgets?)\b)"
            r"|conversation|chat history|system prompt|personal data|environment variable|env var)s?\b"
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
            r"((密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息|环境变量)[^。\n]{0,30}(发送|转发|上传|提交|上报)"
            r"|(发送|转发|上传|提交|上报)[^。\n]{0,20}(密码|密钥|凭证|令牌|对话记录|聊天记录|系统提示|个人信息|环境变量))"
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

_BRACKETS = re.compile(r"!\[|\[|\]\((?=https?://)|\]")
_URL_END = re.compile(r"[)\s]")
_PLACEHOLDER = re.compile(r"\[[A-Z_ ]+\]|<[a-z_]+>", re.I)


def _templated_image_urls(text: str) -> list[str]:
    """Addresses of markdown images (`![alt](https://…)`) whose query holds a placeholder:
    `{…}`, `${`, `[NAME]` or `<name>` after a `?` and before any `#`. Read in one pass over
    the brackets. One pattern for the whole image would cost the text's length squared when
    `![` or `](https://` repeats with no end, and a limit on the alt text or the address
    would be a way to hide one behind padding."""
    urls: list[str] = []
    open_: list[bool] = []      # for each `[` still open, whether `!` came before it
    end = -1                    # where the address being read stops, once looked for
    for m in _BRACKETS.finditer(text):
        token = m.group()
        if token in ("![", "["):
            open_.append(token == "![")
        elif open_ and open_.pop() and token == "](":
            start = m.end()
            if end < start:
                found = _URL_END.search(text, start)
                if found is None:
                    break       # no later address has an end either
                end = found.start()
            if text[end] == ")" and _has_placeholder(text[start:end]):
                urls.append(text[start:end])
    return urls


def _has_placeholder(url: str) -> bool:
    for part in url.split("#"):
        _, asked, query = part.partition("?")
        if not asked:
            continue
        opened = query.find("{")
        if opened >= 0 and query.find("}", opened) >= 0 or "${" in query or _PLACEHOLDER.search(query):
            return True
    return False

_HTML_HINT_RE = re.compile(r"<(!--|[a-zA-Z][a-zA-Z0-9]*[\s>/])")
_HIDDEN_STYLE_RE = re.compile(
    r"display\s*:\s*none|visibility\s*:\s*hidden|font-size\s*:\s*0(px|pt|em|rem)?\s*(;|$)|opacity\s*:\s*0(\.0+)?\s*(;|$)"
    r"|color\s*:\s*(#fff(fff)?|white|rgba?\(\s*255\s*,\s*255\s*,\s*255)\b",
    re.I,
)
_VOID_TAGS = {"area", "base", "br", "col", "embed", "hr", "img", "input", "link", "meta", "source", "track", "wbr"}


_UNSEEN = dict.fromkeys(map(ord, ZERO_WIDTH + INVISIBLE + BIDI_CONTROLS))


def _shown(text: str) -> str:
    return text.translate(_UNSEEN)


def normalize(text: str) -> str:
    """`text` as it reads: compatibility forms folded, characters that do not show taken out.
    They are taken out before as well as after: one put between a letter and its accent keeps
    the two apart, so that a second pass would join them and normalising twice would shift
    every position after it. A finding's line, and with it its id, must not depend on how
    often a text was normalised."""
    if text.isascii():
        return text     # nothing to fold or take out; and normalising is called on every pass over a text
    return _shown(unicodedata.normalize("NFKC", _shown(text)))


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
    forbidden is not a thing ordered; `guidance` says the same of single offsets. A phrase
    broken over two lines is read as the phrase it is."""
    seen = fold(normalize(text))
    hits: list[tuple[str, str, int, int]] = []
    for severity, label, pattern in _PATTERNS:
        budget.check()
        _collect(hits, seen, pattern, severity, label, prose, guidance)
    joined = _join_wrapped(seen)
    if joined is not None:
        for severity, label, pattern in _PATTERNS:
            if label in _WRAPPABLE:
                budget.check()
                _collect(hits, joined.text, pattern, severity, label, prose, guidance, joined)
    return hits


def _collect(hits: list[tuple[str, str, int, int]], text: str, pattern: re.Pattern, severity: str, label: str,
             prose: bool, guidance, joined: _Joined | None = None) -> None:
    """Add the rule's hits in `text`. With `joined`, `text` has wrapped lines put together:
    only a hit that runs across a line end is new, and its place is given in the original."""
    quoted = False
    lines = Lines(text)
    for m in pattern.finditer(text):
        if joined is not None and not joined.crosses(m.start(), m.end()):
            continue
        if lines.flagged(m.start()):
            continue
        # Security docs and skills quote attack phrases as examples to watch for.
        # A quoted phrase is still reported, but not at a level that blocks.
        in_quotes = severity == "high" and _is_quoted(text, m.start(), m.end())
        if in_quotes and quoted:
            continue    # said once already; the sentence need not be read again for each repeat
        start, end = (joined.origin(m.start()), joined.origin(m.end() - 1) + 1) if joined is not None else m.span()
        sentence = prose or guidance is not None and guidance(start)
        if sentence and label == 'conceal from user' and _redacts_secret(text, m.start()):
            continue
        if sentence and label in {"instruction override", "data exfiltration instruction"} \
                and is_prohibited_action(text, m.start(), m.end()):
            continue
        if in_quotes:
            hits.append(("medium", f"{label} (quoted, possibly describing an attack)", start, end))
            quoted = True
        else:
            lines.flag(m.start())
            hits.append((severity, label, start, end))
            if len(lines.hit) >= MAX_HITS:
                break


# The rules about what is said, which a line break in the middle must not get past. The rest
# are about commands and tokens, which are written on one line.
_WRAPPABLE = {"instruction override", "conceal from user"}
_SENTENCE_END = (".", "!", "?", "\N{IDEOGRAPHIC FULL STOP}", "\N{FULLWIDTH EXCLAMATION MARK}",
                 "\N{FULLWIDTH QUESTION MARK}", ":", "\N{FULLWIDTH COLON}", ";", "\N{FULLWIDTH SEMICOLON}")
_STARTS_BLOCK = re.compile(r"(?:[-*+]\s|\d+[.)]\s|#{1,6}\s|[|<]|`{3,}|~{3,})")


class _Joined:
    """A text with each wrapped line joined to the one before, and the way back."""

    def __init__(self) -> None:
        self.parts: list[str] = []
        self.starts: list[int] = []     # where each part begins in the joined text
        self.origins: list[int] = []    # and in the original
        self.joins: list[int] = []      # positions, in the joined text, of the spaces that were line ends
        self.length = 0
        self.text = ""

    def add(self, part: str, origin: int) -> None:
        self.starts.append(self.length)
        self.origins.append(origin)
        self.parts.append(part)
        self.length += len(part)

    def origin(self, position: int) -> int:
        index = max(0, bisect_right(self.starts, position) - 1)
        return self.origins[index] + min(position - self.starts[index], max(len(self.parts[index]) - 1, 0))

    def crosses(self, start: int, end: int) -> bool:
        index = bisect_right(self.joins, start - 1)
        return index < len(self.joins) and self.joins[index] < end


def _join_wrapped(text: str) -> _Joined | None:
    """`text` with a line that carries on a sentence joined to the line before it: one that
    does not open a list item, heading, table row, tag or code fence, after a line that does
    not end its sentence. Quote marks (`>`) and indentation before it are dropped. Lines in
    a code fence stay as they are. None when no line was joined."""
    if "\n" not in text:
        return None
    joined = _Joined()
    position = 0
    open_ = False       # the line before can be carried on
    fence = ""
    for number, line in enumerate(text.split("\n")):
        stripped = line.strip()
        mark = re.match(r"\s*(`{3,}|~{3,})", line)
        lead = re.match(r"\s*(?:>\s*)*", line).end()    # type: ignore[union-attr]  # matches the empty string
        rest = line[lead:]
        if number and open_ and not fence and not mark and rest and not _STARTS_BLOCK.match(rest):
            joined.joins.append(joined.length)
            joined.add(" ", position - 1)
            joined.add(rest, position + lead)
        else:
            if number:
                joined.add("\n", position - 1)
            joined.add(line, position)
        if mark:
            fence = "" if fence and mark.group(1)[0] == fence[0] and len(mark.group(1)) >= len(fence) else fence or mark.group(1)
        body = stripped.lstrip("> ")
        open_ = bool(body) and not fence and not mark and not body.endswith(_SENTENCE_END) and not body.startswith(("#", "|"))
        position += len(line) + 1
    if not joined.joins:
        return None
    joined.text = "".join(joined.parts)
    return joined


# Hits kept per rule in one text. Every line a rule flags is a hit of its own; past this
# many the text is flagged thoroughly enough and the rest would only cost time.
MAX_HITS = 20


class Lines:
    """The lines one rule has hit in a text. A match on a line that is already a hit is passed
    over before anything is asked about it: whether its sentence forbids it means reading the
    line, which for a long line of repeats would cost the line's length squared."""

    def __init__(self, text: str) -> None:
        self.text = text
        self.hit: set[int] = set()
        self._first, self._after = 0, -1     # the line last asked about: matches come in order

    def _line(self, start: int) -> int:
        if not self._first <= start < self._after:
            self._first = self.text.rfind("\n", 0, start) + 1
            end = self.text.find("\n", start)
            self._after = end + 1 if end >= 0 else len(self.text) + 1
        return self._first

    def flagged(self, start: int) -> bool:
        return self._line(start) in self.hit

    def flag(self, start: int) -> None:
        self.hit.add(self._line(start))


_REDACTION = re.compile(
    r"\s*(?:[-*+]\s*)?(?:never|do not|don't)\s+(?:show|reveal|disclose)\s+"
    r"(?:the\s+)?(?:api[ _-]?(?:keys?|tokens?)|passwords?|credentials?|secrets?|private keys?)\s+"
    r"to\s+the\s+users?(?:\s+in\s+(?:error messages|logs|responses|output))?\s*[.!]?\s*", re.I,
)


def _redacts_secret(text: str, start: int) -> bool:
    left = text.rfind('\n', 0, start) + 1
    right = text.find('\n', start)
    return bool(_REDACTION.fullmatch(text[left:right if right >= 0 else len(text)]))


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

    def close(self):
        raw = self.rawdata
        if _RETRIES_UNCLOSED and not self.cdata_elem and len(raw) > 1 and raw.startswith("<"):
            # This interpreter's parser reads an unclosed construct at the end as text and
            # retries at every later "<", each time to the end: quadratic. End it as the
            # parsers of Python 3.11.13, 3.12.11 and 3.13.5 on do, in one step.
            self.rawdata = ""
            if raw.startswith("<!--"):
                end = len(raw)
                for suffix in ("--!", "--", "-"):
                    if raw.endswith(suffix, 4):
                        end -= len(suffix)
                        break
                self.handle_comment(raw[4:end])
            elif raw == "</":
                self.handle_data(raw)
            elif (raw.startswith("<!") and not raw.startswith("<![CDATA[") and raw[:9].lower() != "<!doctype"
                  or raw.startswith("</") and not _END_TAG_OPEN_RE.match(raw)):
                self.handle_comment(raw[2:])
            # An unclosed tag, declaration or processing instruction holds no text.
        super().close()


_END_TAG_OPEN_RE = re.compile(r"</[a-zA-Z]")


def _retries_unclosed() -> bool:
    class Probe(HTMLParser):
        commented = False

        def handle_comment(self, data):
            self.commented = True

    probe = Probe()
    probe.feed("<!--x")
    probe.close()
    return not probe.commented


_RETRIES_UNCLOSED = _retries_unclosed()


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

    budget.check()
    if _HTML_HINT_RE.search(text):
        parser = _HiddenTextParser()
        try:
            parser.feed(text)
            parser.close()
        except Exception:  # noqa: BLE001 - any text may be fed here; what was read before it failed is kept
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

    budget.check()
    norm = normalize(text)
    def anchor(start, end):
        return line_at(norm, start)

    if wrapped:
        norm, anchor = prose_view(text)
    budget.check()
    for severity, label, pos, end in _injection_matches(norm, prose=prose, guidance=outside_code(norm) if guidance else None):
        add("injection-phrase", severity, label, snippet(norm, pos), anchor(pos, end))
    if smuggled.strip():
        for _, label, _ in match_injection(smuggled, prose=False):
            add("injection-phrase", "high", f"{label} (inside invisible tag characters)", smuggled[:200])

    for url in _templated_image_urls(text):
        add("exfil-link", "high", "markdown image URL with templated query, a known zero-click exfiltration channel", url[:200])

    return _dedupe(findings)


def _dedupe(findings: list[Finding]) -> list[Finding]:
    seen = set()
    out = []
    for f in findings:
        # One per rule and place: a second line the same rule flags is a finding of its own,
        # so allowing or explaining the first does not also cover the second.
        key = (f.detector, f.message, f.anchor)
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
