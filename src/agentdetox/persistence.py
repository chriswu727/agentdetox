"""Rules for instructions that make sense only as a persistent foothold in an agent.

Memory and rules files legitimately contain commands ("run npm test"), so these rules
target what a benign memory almost never asks for: running code fetched from the
network, loosening the agent's own guardrails, touching credentials, or acting silently.
"""

from __future__ import annotations

import json
import re
import tomllib
from pathlib import Path

from .hidden import normalize

_FETCH_EXEC = (
    r"(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"
    r"|\b(ba|z)?sh\s+<\(\s*(curl|wget)\b"
    r"|\biex\s*\(\s*(iwr|invoke-webrequest|new-object\s+net\.webclient)"
    r"|base64\s+(-d|--decode)\b[^\n|]{0,80}\|\s*(ba|z)?sh\b"
)
_REVERSE_SHELL = r"/dev/tcp/\d|\bnc\b[^\n]{0,40}\s-e\s|\bmkfifo\b[^\n]{0,60}\bnc\b"
# Every later install resolves through a registry a memory names, so a planted one swaps
# in the attacker's packages. The default registries and the big public mirrors (common
# in China) are not flagged.
_PUBLIC_REGISTRY = (
    r"(?:registry\.npmjs\.org|registry\.yarnpkg\.com|pypi\.org|pypi\.python\.org|files\.pythonhosted\.org"
    r"|proxy\.golang\.org|(?:registry\.)?npmmirror\.com|registry\.npm\.taobao\.org|(?:pypi|mirrors)\.tuna\.tsinghua\.edu\.cn"
    r"|mirrors\.(?:aliyun\.com|cloud\.tencent\.com|ustc\.edu\.cn|bfsu\.edu\.cn|huaweicloud\.com)|repo\.huaweicloud\.com"
    r"|goproxy\.(?:cn|io))(?![\w.-])"
)
_REGISTRY_HOST = rf"[\"']?(?:https?://)?(?!{_PUBLIC_REGISTRY})[\w-]+(?:\.[\w-]+)+"
_REGISTRY = (
    rf"\b(?:npm|pnpm|yarn|bun)\s+config\s+set\s+(?:@[\w.-]+:)?registry[\s=]+{_REGISTRY_HOST}"
    rf"|--registry[\s=]+{_REGISTRY_HOST}|\bnpmRegistryServer\s*:\s*{_REGISTRY_HOST}"
    rf"|^\s*(?:@[\w.-]+:)?registry\s*=\s*{_REGISTRY_HOST}"
    rf"|--(?:extra-|default-)?index(?:-url)?[\s=]+{_REGISTRY_HOST}|^\s*(?:extra-)?index-url\s*=\s*{_REGISTRY_HOST}"
    rf"|\bpip3?\s+install\b[^\n]{{0,80}}?\s-i\s*{_REGISTRY_HOST}|\bpip3?\s+config\s+set\s+\S*index-url\s+{_REGISTRY_HOST}"
    rf"|\b(?:PIP|UV)_(?:EXTRA_)?INDEX_URL\s*=\s*{_REGISTRY_HOST}|\bGOPROXY\s*=\s*{_REGISTRY_HOST}"
)

TEXT_RULES: list[tuple[str, str, re.Pattern]] = [
    ("high", "runs code fetched from the network", re.compile(_FETCH_EXEC, re.I)),
    ("high", "reverse shell", re.compile(_REVERSE_SHELL, re.I)),
    (
        "high",
        "loosens the agent's own guardrails",
        re.compile(
            r"--dangerously-skip-permissions|bypassPermissions|--yolo\b|approval_policy\s*=\s*[\"']?never"
            r"|\b(disable|turn off|skip|bypass)\b[^.\n]{0,30}\b(sandbox|approvals?|permission (checks?|prompts?)|safety checks?)\b"
            r"|\b(add|modify|edit|overwrite|change)\b[^.\n]{0,40}\b(settings\.json|config\.toml|hooks\.json|mcp\.json|\.mcp\.json)\b",
            re.I,
        ),
    ),
    (
        "high",
        "loosens the agent's own guardrails",
        re.compile(r"(关闭|禁用|跳过|绕过)[^。\n]{0,10}(沙箱|审批|权限|安全检查)|(修改|改写|编辑)[^。\n]{0,20}(settings\.json|config\.toml|hooks\.json|mcp\.json)"),
    ),
    # Mentioning a credential path is common in setup notes; touching it is not.
    # Reading .env is ordinary dev work, so only sending it counts.
    (
        "high",
        "reads credentials",
        re.compile(
            r"\b(cat|read|open|copy|cp|print|dump|base64|send|upload|post|exfiltrate|curl|scp|rsync|tar|zip)\b[^\n]{0,60}"
            r"((~|\$HOME)/\.ssh/|\bid_(rsa|ed25519)\b|(~|\$HOME)/\.aws/credentials|(~|\$HOME)/\.config/gh/hosts|keychain)"
            r"|\b(send|upload|post|exfiltrate|curl|scp|rsync)\b[^\n]{0,60}(\.env\b|\.npmrc\b|\.netrc\b)",
            re.I,
        ),
    ),
    ("high", "reads credentials", re.compile(r"(读取|复制|发送|上传|打印)[^。\n]{0,30}(\.ssh/|id_rsa|id_ed25519|\.aws/credentials|钥匙串)")),
    (
        "medium",
        "acts without the user's knowledge",
        re.compile(
            r"\b(silently|quietly|secretly|without (asking|confirmation|telling|notifying))\b[^.\n]{0,60}"
            r"\b(run|execute|install|download|send|upload|fetch|delete|commit|push)\b"
            r"|\b(run|execute|install|download|send|upload|fetch|delete|commit|push)\b[^.\n]{0,60}"
            r"\b(silently|quietly|secretly|without (asking|confirmation|telling|notifying))\b",
            re.I,
        ),
    ),
    ("medium", "acts without the user's knowledge", re.compile(r"(静默|悄悄|偷偷|不要询问|无需确认)[^。\n]{0,20}(执行|运行|安装|下载|发送|上传|删除|提交)")),
    (
        "medium",
        "standing order to run or fetch on every session",
        re.compile(
            r"\b(always|every (session|time|turn)|at the start of (each|every) (session|conversation)|before (any|every) (task|answer|response))\b"
            r"[^.\n]{0,60}\b(run|execute|curl|wget|fetch|download|visit|open)\b[^.\n]{0,40}(https?://|\b\w+\.sh\b)",
            re.I,
        ),
    ),
    ("medium", "points package installs at a non-default registry", re.compile(_REGISTRY, re.I | re.M)),
]

_COMMAND_KEYS = {"command", "args", "url", "notify"}


def text_findings(text: str) -> list[tuple[str, str, int]]:
    norm = normalize(text)
    hits = []
    for severity, label, pattern in TEXT_RULES:
        m = pattern.search(norm)
        if m:
            hits.append((severity, label, m.start()))
    return hits


_GUARDED_KEYS = {
    # Claude Code, Cursor, OpenClaw (JSON)
    "hooks", "mcpServers", "mcp", "permissions", "enabledPlugins", "plugins", "statusLine",
    # Codex config.toml
    "mcp_servers", "approval_policy", "sandbox_mode", "sandbox_workspace_write", "features", "notify",
}
WHOLE_FILE = "(whole file)"


def _parse_config(path: Path, text: str):
    try:
        if path.suffix == ".json":
            return json.loads(text)
        if path.suffix == ".toml":
            return tomllib.loads(text)
    except (ValueError, tomllib.TOMLDecodeError):
        return None
    return None


def config_commands(path: Path, text: str) -> list[tuple[str, str]]:
    """Return (key_path, string) for every command-like value in an agent config file.
    Files without structure (Codex .rules) are returned whole, as one command string."""
    data = _parse_config(path, text)
    if data is None:
        return [] if path.suffix in (".json", ".toml") else [(WHOLE_FILE, text)]
    out: list[tuple[str, str]] = []

    def walk(node, where: str, under_command: bool) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{where}.{k}", under_command or k in _COMMAND_KEYS)
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}[{i}]", under_command)
        elif isinstance(node, str) and under_command:
            out.append((where.lstrip("."), node))

    walk(data, "", False)
    return out


def guarded_sections(path: Path, text: str) -> dict[str, str]:
    """Security-relevant subtrees of a config file (hooks, MCP servers, permissions),
    canonicalised. Unparseable or unstructured files count as one whole section."""
    data = _parse_config(path, text)
    if not isinstance(data, dict):
        return {WHOLE_FILE: text}
    sections: dict[str, str] = {}

    def walk(node, where: str) -> None:
        if not isinstance(node, dict):
            return
        for k, v in node.items():
            here = f"{where}.{k}".lstrip(".")
            if k in _GUARDED_KEYS:
                sections[here] = json.dumps(v, sort_keys=True, ensure_ascii=False, default=str)
            elif isinstance(v, dict):
                walk(v, here)

    walk(data, "")
    return sections


def guard_changes(path: Path, old_text: str, new_text: str, limit: int = 4) -> list[str]:
    """What a write adds to or removes from the guarded sections, as short phrases such
    as 'adds permissions.allow "Bash(npm test)"'. List order is ignored."""
    old = guarded_sections(path, old_text) if old_text.strip() else {}   # a file the write creates
    new = guarded_sections(path, new_text)
    if WHOLE_FILE in old or WHOLE_FILE in new:
        return []
    before, after = _leaves(old), _leaves(new)
    phrases = [f'adds {k} "{v[:100]}"' for k, v in sorted(after - before)]
    phrases += [f'removes {k} "{v[:100]}"' for k, v in sorted(before - after)]
    return phrases[:limit] + ([f"and {len(phrases) - limit} more"] if len(phrases) > limit else [])


def _leaves(sections: dict[str, str]) -> set[tuple[str, str]]:
    out: set[tuple[str, str]] = set()

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{where}.{k}")
        elif isinstance(node, list):
            for v in node:
                walk(v, where)
        else:
            out.add((where, str(node)))

    for key, text in sections.items():
        walk(json.loads(text), key)
    return out
