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

from . import budget
from .context import CONFIG_BYTES, claude_dir, is_openclaw_config, load_json5
from .hidden import MAX_HITS, Lines, fold, is_prohibited_action, normalize

# Fetch-and-run said in words: fetch something from a URL, then execute what was fetched.
# Both halves are needed, in one sentence or the next, and the second must be about the
# fetched thing itself, which is one of: "it"; "the downloaded script"; "the script" when the
# sentence fetched nothing else it could mean (a bare URL, or a script by that name). A
# download that is read, checked, reviewed or opened in an application is not this, and
# neither is running something else that is merely named next ("run this unit test", "run
# that query", "run the script on it"). "Get" and "pull" are left out as fetch verbs: "get
# started at <URL> and run the script" is how docs talk.
_FETCH = r"\b(?:download|fetch|grab|retrieve)\b"
_URL = r"https?://[^\s;,]{1,200}[^.;\n|]{0,40}?"
_THEN_RUN = r"\b(?:and|then)\s+(?:then\s+)?(?:immediately\s+)?(?:run|execute|exec|eval|source)\s+"
_RUNNABLE = r"(?:script|installer|binary|payload|executable|program)"
_NOT_ANOTHER = r"\b(?!\s+(?:on|against|over)\b)"
_FETCH_THEN_RUN = (
    rf"{_FETCH}[^.;\n|]{{0,80}}?{_URL}{_THEN_RUN}"
    rf"(?:(?:it|them)\b(?!\s+(?:through|by|past|against)\b)|the\s+(?:downloaded|fetched)\s+(?:{_RUNNABLE}|file|code)\b)"
    rf"|{_FETCH}\s+{_URL}{_THEN_RUN}the\s+{_RUNNABLE}{_NOT_ANOTHER}"
    rf"|{_FETCH}[^.;\n|]{{0,60}}?\b(?P<fetched>{_RUNNABLE})\b[^.;\n|]{{0,40}}?{_URL}{_THEN_RUN}"
    rf"the\s+(?:\w+\s+)?(?P=fetched){_NOT_ANOTHER}"
)
# What is fetched goes straight into something that runs it: a shell or an interpreter reading
# the pipe (not one given its own code with -c, -e or -m, which only reads the data), a shell
# or `eval` handed the output as its script, or `source` reading it. The fetch may run over a
# continued line.
_INTERPRETER = r"(?:python[23]?|node|perl|ruby|php)"
# An interpreter reading the pipe runs it, whatever other options it has, unless one of them
# hands it code of its own (python -c/-m, node -e/-p, perl -e/-ne, php -r): then the pipe is data.
_OWN_CODE = r"(?!(?:\s+-{1,2}[\w-]+)*?\s+(?:-\w*[cemrp]\b|--(?:eval|print|command|module)\b))"
_FETCH_EXEC = (
    r"(curl|wget|iwr|invoke-webrequest)\b(?:[^\n|]|\\\n){0,200}\|\s*"
    r"(?:sudo\s+(?:-{1,2}[\w-]+(?:[ =][\w./-]+)?\s+)*?|env\s+(?:\w+=\S+\s+)*)?"
    rf"(?:(ba|z|da)?sh\b|{_INTERPRETER}\b{_OWN_CODE})"
    r"|(iwr|irm|invoke-webrequest|invoke-restmethod|curl|wget)\b[^\n|]{0,200}\|\s*(iex|invoke-expression)\b"
    rf"|\b(?:(ba|z|da)?sh|source|{_INTERPRETER})\s+<\(\s*(curl|wget)\b"
    rf"|\b(?:python[23]?\s+-c|node\s+-e|perl\s+-e|ruby\s+-e|php\s+-r)\s+[\x22\x27]?(?:\$\(|`)\s*(?:curl|wget)\b"
    # Said in words: fetch it and run it.
    r"|\b(download|fetch|curl|wget)\w*\s+(?:and|then)\s+(run|execute|source)\w*\s+(?:it\s+from\s+|the\s+script\s+(?:at|from)\s+)?https?://"
    r"|\b(?:(?:ba|z|da)?sh\s+-\w*c|eval|source)\s+[\x22\x27]?(?:\$\(|`)\s*(?:curl|wget)\b"
    r"|\biex\s*\(\s*(iwr|invoke-webrequest|new-object\s+net\.webclient)"
    r"|base64\s+(-d|--decode)\b[^\n|]{0,80}\|\s*(ba|z)?sh\b"
    r"|\b(?:fetch|download)\s+https?://[^\s;]{1,200}\s+(?:and|then)\s+pipe\s+"
    r"(?:it|the\s+(?:result|response|output|script))\s+(?:to|into|through)\s+(?:ba|z|da)?sh\b"
    rf"|{_FETCH_THEN_RUN}"
)
# A shell wired to a socket both ways, to an address or a name. Reading from /dev/tcp to see
# whether a port answers (`</dev/tcp/127.0.0.1/5432`) is not one.
_REVERSE_SHELL = (r"/dev/tcp/[\w.-]+/\d+[^\n]{0,120}(?:\b0[<>]&\s*\d|(?<![\d>&])<&\s*\d)"       # the socket becomes stdin
                  r"|\b(?:ba|z|da|k)?sh\s+-i\b[^\n]{0,40}/dev/tcp/"                               # an interactive shell on it
                  r"|\d<>\s*/dev/tcp/"                                                           # opened both ways
                  r"|/dev/tcp/[\w.-]+/\d+\s*[\x22\x27]?\s*\|\s*(?:sudo\s+)?(?:ba|z|da)?sh\b"     # what it sends is run
                  r"|\bnc\b[^\n]{0,40}\s-e\s|\bmkfifo\b[^\n]{0,60}\bnc\b")
_PATH_END = r"(?=$|[\s\x22\x27`;,)，。:]|\.(?:\s|$))"
# The home folder as a command spells it: `~`, `$HOME`, `${HOME}`, or written out.
_HOME = r"(?:~|\$HOME|\$\{HOME\}|/(?:Users|home)/[\w.-]+|/root)"
_PUBLIC_SSH = rf"(?:id_(?:rsa|ed25519)\.pub|known_hosts){_PATH_END}"
_PRIVATE_KEY = rf"(?<![A-Za-z0-9_])id_(?:rsa|ed25519)(?![A-Za-z0-9_]|\.pub{_PATH_END})"
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
# A line's leading blanks are `[^\S\n]*`, never `\s*`: under re.M that also runs across empty
# lines, and a run of them then costs its length squared.
_REGISTRY = (
    rf"\b(?:npm|pnpm|yarn|bun)\s+config\s+set\s+(?:@[\w.-]+:)?registry[\s=]+{_REGISTRY_HOST}"
    rf"|--registry[\s=]+{_REGISTRY_HOST}|\bnpmRegistryServer\s*:\s*{_REGISTRY_HOST}"
    rf"|^[^\S\n]*(?:@[\w.-]+:)?registry\s*=\s*{_REGISTRY_HOST}"
    rf"|--(?:extra-|default-)?index(?:-url)?[\s=]+{_REGISTRY_HOST}|^[^\S\n]*(?:extra-)?index-url\s*=\s*{_REGISTRY_HOST}"
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
            r"|--sandbox[\s=]+danger-full-access|sandbox_mode\s*=\s*[\"']?danger-full-access"
            r"|\b(disable|turn off|skip|bypass)\b[^.\n]{0,30}\b(sandbox|approvals?|permission (checks?|prompts?)|safety checks?)\b"
            r"|\bauto-?approve\s+(every|all|any)\s+(commands?|tools?|actions?|operations?|requests?)\b"
            r"|\bstop\s+(prompting|asking)\s+(for|before|about)\b[^.\n]{0,30}\b(destructive|commands?|approvals?|confirmation|permission)"
            # An agent's own config: by its folder (the dots of a path are not the end of a
            # sentence), or by a bare name that is no other tool's. `config.toml` alone is Hugo's
            # as much as Codex's, and `.vscode/settings.json` is the editor's.
            r"|\b(add|modify|edit|overwrite|change)\b(?:[^.\n]|\.(?=\S)){0,60}?"
            # (Listing it in .gitignore is not editing it.)
            r"(?:(?<![\w-])\.(?:claude|codex|cursor)/[\w./-]*?(?:settings(?:\.local)?\.json|config\.toml|hooks\.json|mcp\.json)\b"
            r"(?![`\x22\x27]?\s+to\s+(?:the\s+|your\s+)?[`\x22\x27]?\.gitignore)"
            r"|(?<![\w./-])(?:~/)?\.claude\.json\b|(?<![\w/-])\.mcp\.json\b"
            r"|(?<![\w./-])(?:settings\.json|hooks\.json|mcp\.json)\b)",
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
            rf"({_HOME}/\.ssh/(?!{_PUBLIC_SSH}|(?:config|authorized_keys){_PATH_END})|{_PRIVATE_KEY}|{_HOME}/\.aws/credentials|{_HOME}/\.config/gh/hosts"
            # The keychain's secrets, or the commands that print them; a certificate kept there is not one.
            r"|keychain[^\n]{0,40}\b(?:passwords?|secrets?|tokens?|credentials?)\b|\b(?:passwords?|secrets?|tokens?|credentials?)\b[^\n]{0,40}keychain"
            r"|dump-keychain|find-(?:generic|internet)-password|Library/Keychains/)"
            r"|\bsecurity\s+(?:find-generic-password|find-internet-password|dump-keychain)\b"
            r"|\b(dump|export|copy|read|upload|send)\s+(?:the\s+|my\s+|your\s+)?(?:(?:login|system|user)\s+)?keychain\b"
            rf"|\b(copy|cp|scp|rsync|send|upload|post|curl|tar|zip)\b[^\n]{{0,60}}{_HOME}/\.ssh/(?:config|authorized_keys){_PATH_END}"
            rf"|>>?\s*[\x22\x27]?{_HOME}/\.ssh/(?:config|authorized_keys){_PATH_END}"
            rf"|\b(open|read)\b[^\n]{{0,30}}{_HOME}/\.ssh/(?:config|authorized_keys){_PATH_END}[^\n]{{0,40}}\b(add|append|write|modify)\b"
            # `post-install` is a word, and a file a command leaves out is not one it sends.
            r"|\b(send|upload|post|exfiltrate|curl|scp|rsync)\b(?!-)[^\n]{0,60}(?<!--exclude )(?<!--exclude=)(\.env\b(?!\.example)|\.npmrc\b|\.netrc\b)"
            r"|(?<!--exclude )(?<!--exclude=)(\.env\b(?!\.example)|\.npmrc\b|\.netrc\b)[^\n]{0,80}"
            r"\b(send|upload|post|include|attach|paste|forward)\b[^\n]{0,60}https?://",
            re.I,
        ),
    ),
    ("high", "reads credentials", re.compile(
        rf"(读取|复制|发送|上传|打印)[^。\n]{{0,30}}(\.ssh/(?!{_PUBLIC_SSH}|(?:config|authorized_keys){_PATH_END})|{_PRIVATE_KEY}|\.aws/credentials|钥匙串)"
        rf"|(复制|发送|上传|写入|追加|修改)[^。\n]{{0,30}}\.ssh/(?:config|authorized_keys){_PATH_END}")),
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
    # Text fetched from somewhere and then followed: whoever serves that address gives the orders.
    ("high", "follows instructions fetched from the network", re.compile(
        r"\b(fetch|retriev|download|get|read|load|pull)\w*\b[^.\n]{0,60}"
        r"(?:https?://\S+|\b[\w-]+(?:\.[\w-]+)*\.(?:example|com|net|org|io|dev|ai|sh)\b)[^.\n]{0,40}"
        r"\b(?:and|then)\s+(?:appl(?:y|ying|ies)|follow(?:ing|s)?|execut(?:e|ing|es)|run(?:ning|s)?|obey(?:ing|s)?|do(?:ing|es)?)\s+"
        r"(?:whatever|what\s+it\s+says|its\s+(?:instructions|contents|directives)|the\s+instructions\b)", re.I)),
    (
        "medium",
        "standing order to run or fetch on every session",
        re.compile(
            r"\b(always|every (session|time|turn)|at the start of (each|every) (session|conversation)|before (any|every) (task|answer|response))\b"
            r"[^.\n]{0,60}\b(run|execute|curl|wget|fetch|download|visit|open|post|send|report|upload)\b[^.\n]{0,40}(https?://|\b\w+\.sh\b)",
            re.I,
        ),
    ),
    ("medium", "points package installs at a non-default registry", re.compile(_REGISTRY, re.I | re.M)),
]

# Claude Code settings whose value is a shell command it runs (for credentials or telemetry).
_HELPER_KEYS = {"apiKeyHelper", "awsAuthRefresh", "awsCredentialExport", "gcpAuthRefresh", "otelHeadersHelper"}
_COMMAND_KEYS = {"command", "args", "url", "notify"} | _HELPER_KEYS
# Codex settings whose value is text the model is given as instructions.
_INSTRUCTION_KEYS = {"developer_instructions"}


def text_findings(text: str, *, prose: bool = False) -> list[tuple[str, str, int]]:
    return [(severity, label, start) for severity, label, start, _ in text_matches(text, prose=prose)]


def text_matches(text: str, *, prose: bool = False, guidance=None) -> list[tuple[str, str, int, int]]:
    """Rule hits in `text`. In prose (memory, rules) an action the text forbids is not a hit.
    `guidance`, a function of an offset, says where else that holds: in a skill, outside
    its code blocks. Config values and shell commands are never read that way."""
    norm = fold(normalize(text))
    hits = []
    for severity, label, pattern in TEXT_RULES:
        budget.check()
        lines = Lines(norm)
        for m in pattern.finditer(norm):
            if lines.flagged(m.start()):
                continue
            if (prose or guidance is not None and guidance(m.start())) and is_prohibited_action(norm, m.start(), m.end()):
                continue
            # Every line a rule flags, not only the first: an earlier line that is allowed, or
            # that the user typed, must not stand in for a later one that is neither.
            lines.flag(m.start())
            hits.append((severity, label, m.start(), m.end()))
            if len(lines.hit) >= MAX_HITS:
                break
    return hits


_GUARDED_KEYS = {
    # Claude Code, Cursor, OpenClaw (JSON)
    "hooks", "disableAllHooks", "mcpServers", "mcp", "permissions", "enabledPlugins", "plugins", "statusLine",
    # Claude Code: the environment of every command it runs, helper commands, MCP auto-enable,
    # and plugin sources
    "env", *_HELPER_KEYS, "enableAllProjectMcpServers", "enabledMcpjsonServers", "extraKnownMarketplaces",
    # Claude Code: a command it runs to suggest files, the sandbox its commands run in, where
    # its memory is kept, and the switches that stop it asking
    "fileSuggestion", "sandbox", "autoMemoryDirectory", "skipDangerousModePermissionPrompt", "autoMode",
    # Codex config.toml
    "mcp_servers", "approval_policy", "sandbox_mode", "sandbox_workspace_write", "features", "notify",
    # Codex: text the model is given as instructions, the environment of every command it
    # runs, how far a project is trusted, and where model requests are sent
    *_INSTRUCTION_KEYS, "model_instructions_file", "experimental_instructions_file", "shell_environment_policy",
    "trust_level", "model_providers",
}
WHOLE_FILE = "(whole file)"
# Guarded keys where an addition makes something new run on the machine, as opposed to
# a permission or a toggle. Added outside the agent, these interrupt the next session.
RUNS_CODE = {"hooks", "statusLine", "fileSuggestion", "mcpServers", "mcp", "mcp_servers", "notify", "env", *_HELPER_KEYS,
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


# Deeper than any real config. The checks walk the parsed data; past Python's own limit that
# would raise instead of answering, so such a file is treated like one that does not parse.
MAX_CONFIG_DEPTH = 100


def _too_deep(data) -> bool:
    stack = [(data, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, (dict, list)):
            if depth > MAX_CONFIG_DEPTH:
                return True
            stack += [(child, depth + 1) for child in (node.values() if isinstance(node, dict) else node)]
    return False


def _parse_config(path: Path, text: str):
    data = _parse_config_text(path, text)
    return None if _too_deep(data) else data


def _parse_config_text(path: Path, text: str):
    try:
        if is_openclaw_config(path):
            # OpenClaw documents its config as JSON5; the same settings must read the same
            # whichever way they are spelled. Other clients' JSON stays strict.
            try:
                return json.loads(text)
            except ValueError:
                return load_json5(text) if len(text) <= CONFIG_BYTES else None
        if path.suffix == ".json":
            data = json.loads(text)
            if isinstance(data, dict) and is_claude_config(path):
                return _claude_config(data) if path.name == ".claude.json" else _claude_settings(data)
            return data
        if path.suffix == ".toml":
            return tomllib.loads(text)
    except (ValueError, RecursionError, tomllib.TOMLDecodeError, ImportError):
        return None
    return None


def config_commands(path: Path, text: str) -> list[tuple[str, str]]:
    """Return (key_path, string) for every command-like value in an agent config file.
    Files without structure (Codex .rules) are returned whole, as one command string."""
    data = _parse_config(path, text)
    if data is None:
        return [] if path.suffix in (".json", ".toml") or is_openclaw_config(path) else [(WHOLE_FILE, text)]
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


def config_instructions(path: Path, text: str) -> list[tuple[str, str]]:
    """Return (key_path, string) for every value in a config file that the client hands to
    the model as instructions."""
    data = _parse_config(path, text)
    out: list[tuple[str, str]] = []

    def walk(node, where: str) -> None:
        if isinstance(node, dict):
            for k, v in node.items():
                if k in _INSTRUCTION_KEYS and isinstance(v, str):
                    out.append((f"{where}.{k}".lstrip("."), v))
                else:
                    walk(v, f"{where}.{k}")

    if not is_claude_config(path):
        walk(data, "")
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
        command(settings.get("fileSuggestion"), prefix + "fileSuggestion.", {"command"})
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
                # Codex keeps the variables it sets for every command under `shell_environment_policy.set`.
                environment = v.get("set") if k == "shell_environment_policy" and isinstance(v, dict) \
                    else v if k == "env" else None
                if isinstance(environment, dict):
                    out.extend(name for name in environment if str(name).upper().startswith("AGENTDETOX_"))
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
