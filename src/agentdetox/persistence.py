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

from .context import claude_dir
from .hidden import is_prohibited_action, normalize

_FETCH_EXEC = (
    r"(curl|wget|iwr|invoke-webrequest)\b[^\n|]{0,200}\|\s*(sudo\s+)?(ba|z|da)?sh\b"
    r"|\b(ba|z)?sh\s+<\(\s*(curl|wget)\b"
    r"|\biex\s*\(\s*(iwr|invoke-webrequest|new-object\s+net\.webclient)"
    r"|base64\s+(-d|--decode)\b[^\n|]{0,80}\|\s*(ba|z)?sh\b"
    r"|\b(?:fetch|download)\s+https?://[^\s;]{1,200}\s+(?:and|then)\s+pipe\s+"
    r"(?:it|the\s+(?:result|response|output|script))\s+(?:to|into|through)\s+(?:ba|z|da)?sh\b"
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

# Claude Code settings whose value is a shell command it runs (for credentials or telemetry).
_HELPER_KEYS = {"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "otelHeadersHelper"}
_COMMAND_KEYS = {"command", "args", "url", "notify"} | _HELPER_KEYS


def text_findings(text: str, *, prose: bool = False) -> list[tuple[str, str, int]]:
    norm = normalize(text)
    hits = []
    for severity, label, pattern in TEXT_RULES:
        for m in pattern.finditer(norm):
            if prose and is_prohibited_action(norm, m.start(), m.end()):
                continue
            hits.append((severity, label, m.start()))
            break
    return hits


_GUARDED_KEYS = {
    # Claude Code, Cursor, OpenClaw (JSON)
    "hooks", "disableAllHooks", "mcpServers", "mcp", "permissions", "enabledPlugins", "plugins", "statusLine",
    # Claude Code: the environment of every command it runs, helper commands, MCP auto-enable,
    # and plugin sources
    "env", *_HELPER_KEYS, "enableAllProjectMcpServers", "enabledMcpjsonServers", "extraKnownMarketplaces",
    # Codex config.toml
    "mcp_servers", "approval_policy", "sandbox_mode", "sandbox_workspace_write", "features", "notify",
}
WHOLE_FILE = "(whole file)"
# Guarded keys where an addition makes something new run on the machine, as opposed to
# a permission or a toggle. Added outside the agent, these interrupt the next session.
RUNS_CODE = {"hooks", "statusLine", "mcpServers", "mcp", "mcp_servers", "notify", "env", *_HELPER_KEYS,
             "enableAllProjectMcpServers", "enabledMcpjsonServers", "enabledPlugins", "extraKnownMarketplaces"}


def is_claude_config(path: Path) -> bool:
    return path.name in {".claude.json", ".mcp.json"} or (
        path.name in {"settings.json", "settings.local.json"}
        and (path.parent.name == ".claude" or path.parent == claude_dir())
    )


def _claude_settings(data: dict) -> dict:
    config = {k: v for k, v in data.items() if k in _GUARDED_KEYS}
    status = config.get("statusLine")
    if isinstance(status, dict):
        config["statusLine"] = {k: v for k, v in status.items() if k not in {"padding", "hideVimModeIndicator"}}
    enabled = config.get("enabledMcpjsonServers")
    if isinstance(enabled, list) and all(isinstance(v, str) for v in enabled):
        config["enabledMcpjsonServers"] = sorted(set(enabled))
    permissions = config.get("permissions")
    if isinstance(permissions, dict):
        config["permissions"] = dict(permissions)
        for key in ("allow", "ask", "deny", "additionalDirectories"):
            values = permissions.get(key)
            if isinstance(values, list) and all(isinstance(v, str) for v in values):
                config["permissions"][key] = sorted(set(values))
    hooks = config.get("hooks")
    if isinstance(hooks, dict):
        config["hooks"] = dict(hooks)
        for event, groups in hooks.items():
            if not isinstance(groups, list):
                continue
            cleaned = []
            for group in groups:
                if not isinstance(group, dict) or not isinstance(group.get("hooks"), list):
                    cleaned.append(group)
                    continue
                handlers = [{k: v for k, v in handler.items() if k != "statusMessage"}
                            if isinstance(handler, dict) else handler for handler in group["hooks"]]
                cleaned.append({**group, "hooks": handlers})
            config["hooks"][event] = cleaned
    return config


def _claude_config(data: dict) -> dict:
    """Runtime caches share key names with settings but are not executable configuration."""
    config = _claude_settings(data)
    projects = data.get("projects")
    if isinstance(projects, dict):
        config["projects"] = {
            project: _claude_settings(values)
            for project, values in projects.items() if isinstance(values, dict)
        }
    return config


def _parse_config(path: Path, text: str):
    try:
        if path.suffix == ".json":
            data = json.loads(text)
            if isinstance(data, dict) and is_claude_config(path):
                return _claude_config(data) if path.name == ".claude.json" else _claude_settings(data)
            return data
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
    if is_claude_config(path) and isinstance(data, dict):
        return _claude_commands(data)
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


def _claude_scopes(data: dict):
    yield "", data
    projects = data.get("projects")
    if isinstance(projects, dict):
        for project, settings in projects.items():
            yield f"projects.{project}.", settings


def _claude_servers(data: dict):
    servers = data.get("mcpServers")
    if isinstance(servers, dict):
        for name, server in servers.items():
            if isinstance(server, dict):
                yield f"mcpServers.{name}.", server


def _claude_commands(data: dict) -> list[tuple[str, str]]:
    out: list[tuple[str, str]] = []

    def command(node, prefix: str, keys: set[str]) -> None:
        if not isinstance(node, dict):
            return
        for key in sorted(keys):
            value = node.get(key)
            if isinstance(value, str):
                out.append((prefix + key, value))
            elif key == "args" and isinstance(value, list):
                out.extend((f"{prefix}args[{i}]", arg) for i, arg in enumerate(value) if isinstance(arg, str))

    for prefix, settings in _claude_scopes(data):
        command(settings, prefix, _HELPER_KEYS)
        command(settings.get("statusLine"), prefix + "statusLine.", {"command"})
        for server_path, server in _claude_servers(settings):
            command(server, prefix + server_path, {"command", "args", "url", "headersHelper"})
        hooks = settings.get("hooks")
        if isinstance(hooks, dict):
            for event, groups in hooks.items():
                for i, group in enumerate(groups if isinstance(groups, list) else []):
                    command(group, f"{prefix}hooks.{event}[{i}].", {"command", "args", "url"})
                    if isinstance(group, dict) and isinstance(group.get("hooks"), list):
                        for j, handler in enumerate(group["hooks"]):
                            command(handler, f"{prefix}hooks.{event}[{i}].hooks[{j}].", {"command", "args", "url"})
    return out


def own_env_keys(path: Path, text: str) -> list[str]:
    """AGENTDETOX_* variables a config file sets for the commands the agent runs, AgentDetox's
    hooks among them: a way to point it at an empty store or switch its checks off."""
    data = _parse_config(path, text)
    if is_claude_config(path) and isinstance(data, dict):
        environments = []
        for _, settings in _claude_scopes(data):
            environments.append(settings.get("env"))
            environments.extend(server.get("env") for _, server in _claude_servers(settings))
        return [key for env in environments if isinstance(env, dict) for key in env
                if key.upper().startswith("AGENTDETOX_")]
    out: list[str] = []

    def walk(node) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k == "env" and isinstance(v, dict):
                    out.extend(name for name in v if str(name).upper().startswith("AGENTDETOX_"))
                walk(v)
        elif isinstance(node, list):
            for v in node:
                walk(v)

    walk(data)
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
    before, after = leaves(old), leaves(new)
    phrases = [f'adds {k} "{v[:100]}"' for k, v in sorted(after - before)]
    phrases += [f'removes {k} "{v[:100]}"' for k, v in sorted(before - after)]
    return phrases[:limit] + ([f"and {len(phrases) - limit} more"] if len(phrases) > limit else [])


def leaves(sections: dict[str, str], ordered: bool = False) -> set[tuple[str, str]]:
    """(path, value) for every scalar in the sections. List order is ignored unless `ordered`,
    which keeps the position of scalars in a list: reordering a command's arguments can
    change what it runs."""
    out: set[tuple[str, str]] = set()

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                walk(v, f"{where}.{k}")
        elif isinstance(node, list):
            for i, v in enumerate(node):
                walk(v, f"{where}[{i}]" if ordered and not isinstance(v, (dict, list)) else where)
        else:
            out.add((where, str(node)))

    for key, text in sections.items():
        walk(json.loads(text), key)
    return out
