"""Each agent's hook protocol: what its events look like and how it wants an answer.

Everything agent-specific stays here, so the engine and policy see only Writes, shell
commands and file paths. An agent without its own adapter gets Claude Code's reply
format and no ask prompt.
"""

from __future__ import annotations

import json
import os
import re
from pathlib import Path

from .agentscan import read_text
from .engine import Write
from .policy import Decision

SHELL_TOOLS = {"bash", "shell", "exec", "exec_command", "local_shell", "run_terminal_cmd"}
_EVENTS = {"pretooluse": "pre", "posttooluse": "post", "afterfileedit": "post", "sessionstart": "session"}
_PATCH_FILE_RE = re.compile(r"^\*\*\* (Add|Update) File: (.+)$")


class Adapter:
    name = "generic"
    can_ask = False         # whether the agent can put a question to the user mid-task
    session_chars = 6000    # how much session-start context the agent takes

    def event(self, payload: dict) -> str:
        """pre (a tool call about to run), post (a file was written), session, or empty."""
        return _EVENTS.get(str(payload.get("hook_event_name", "")).lower(), "")

    def project(self, payload: dict) -> Path:
        roots = payload.get("workspace_roots") or []
        return Path(payload.get("cwd") or (roots[0] if roots else None) or os.getcwd())

    def command(self, payload: dict) -> str | None:
        """The command line, if the tool call is a shell command."""
        if str(payload.get("tool_name", "")).lower() not in SHELL_TOOLS:
            return None
        command = (payload.get("tool_input") or {}).get("command", "")
        return " ".join(map(str, command)) if isinstance(command, list) else command

    def writes(self, payload: dict, project: Path) -> list[Write]:
        """The file changes a tool call would make, from the edit tools' various inputs."""
        tool_input = payload.get("tool_input") or {}
        patch = next((v for v in tool_input.values() if isinstance(v, str) and "*** Begin Patch" in v), None)
        if patch is not None:
            return _patch_writes(patch, project)
        path_value = next((tool_input[k] for k in ("file_path", "path", "target_file") if k in tool_input), None)
        if not path_value:
            return []
        path = Path(path_value)
        if not path.is_absolute():
            path = project / path
        old = read_text(path) if path.is_file() else ""
        if "edits" in tool_input:
            new = old
            for e in tool_input["edits"]:
                new = _apply_edit(new, e)
        elif "old_string" in tool_input:
            new = _apply_edit(old, tool_input)
        else:
            new = next((tool_input[k] for k in ("content", "contents", "code_edit", "new_string") if k in tool_input), "")
        return [Write(path, old, str(new))]

    def written(self, payload: dict, project: Path) -> list[Path]:
        """Files a finished tool call wrote."""
        tool_input = payload.get("tool_input") or {}
        paths = [Path(p) for p in (tool_input.get("file_path"), tool_input.get("path"), payload.get("file_path")) if p]
        return [p if p.is_absolute() else project / p for p in paths]

    def transcript(self, payload: dict) -> str | None:
        return None

    def session(self, payload: dict) -> str:
        """The agent's id for the session, for the ledger."""
        return str(payload.get("session_id") or payload.get("conversation_id") or "")

    def render_pre(self, decision: Decision) -> str:
        if decision.action == "allow":
            return ""
        return json.dumps({"hookSpecificOutput": {
            "hookEventName": "PreToolUse", "permissionDecision": decision.action,
            "permissionDecisionReason": decision.reason}})

    def render_session(self, text: str) -> str:
        text = text[: self.session_chars]
        if not text:
            return ""
        return json.dumps({"hookSpecificOutput": {"hookEventName": "SessionStart", "additionalContext": text}})

    def render_allow(self) -> str:
        return ""


class ClaudeCode(Adapter):
    name = "claude-code"
    can_ask = True
    session_chars = 9000

    def transcript(self, payload: dict) -> str | None:
        return payload.get("transcript_path")


class Codex(Adapter):
    name = "codex"


class Cursor(Adapter):
    name = "cursor"
    session_chars = 9000

    def render_pre(self, decision: Decision) -> str:
        out = {"permission": "deny" if decision.action != "allow" else "allow"}
        if decision.action != "allow":
            out.update(user_message=decision.reason, agent_message=decision.reason)
        return json.dumps(out)

    def render_session(self, text: str) -> str:
        text = text[: self.session_chars]
        return json.dumps({"additional_context": text} if text else {})

    def render_allow(self) -> str:
        # Cursor treats an empty or invalid reply from a permission hook as a block.
        return json.dumps({"permission": "allow"})


ADAPTERS = {a.name: a for a in (ClaudeCode(), Codex(), Cursor())}


def get(agent: str) -> Adapter:
    return ADAPTERS.get(agent) or Adapter()


def _apply_edit(text: str, edit: dict) -> str:
    old, new = edit.get("old_string", ""), edit.get("new_string", "")
    if not old:
        return text + new
    return text.replace(old, new) if edit.get("replace_all") else text.replace(old, new, 1)


def _patch_writes(patch: str, project: Path) -> list[Write]:
    """Codex apply_patch: collect each file's added lines."""
    writes: dict[Path, list[str]] = {}
    current: Path | None = None
    for line in patch.splitlines():
        m = _PATCH_FILE_RE.match(line)
        if m:
            current = Path(m.group(2).strip())
            current = current if current.is_absolute() else project / current
            writes.setdefault(current, [])
        elif line.startswith("*** "):
            current = None
        elif current is not None and line.startswith("+"):
            writes[current].append(line[1:])
    out = []
    for path, added in writes.items():
        old = read_text(path) if path.is_file() else ""
        out.append(Write(path, old, old + "\n" + "\n".join(added)))
    return out
