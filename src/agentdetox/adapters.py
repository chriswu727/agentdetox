"""Each agent's hook protocol: what its events look like and how it wants an answer.

Everything agent-specific stays here, so the engine and policy see only Writes, shell
commands and file paths. An agent without its own adapter gets Claude Code's reply
format and no ask prompt.

Where each shape comes from: Claude Code's from its hooks reference and real sessions;
Codex's event names, `Bash`, `apply_patch` and `tool_input.command` from events recorded
from Codex CLI 0.167; Cursor's from its hooks documentation only, which gives no input
shape for its Write and Delete tools, so those are read by the fields they carry.
"""

from __future__ import annotations

import json
import os
import shlex
from pathlib import Path

from . import patch as patches
from .agentscan import read_text
from .context import repository_root
from .engine import Write
from .policy import Decision

SHELL_TOOLS = {"bash", "shell", "exec", "exec_command", "local_shell", "run_terminal_cmd"}
# Tools that change the file they name. A call to one of these that names a file but no
# content this module reads is reported, not passed over.
WRITE_TOOLS = {"write", "edit", "multiedit", "notebookedit", "apply_patch"}
DELETE_TOOLS = {"delete"}
_EVENTS = {"pretooluse": "pre", "posttooluse": "post", "posttoolusefailure": "post-failed",
           "afterfileedit": "post", "sessionstart": "session"}
_CONTENT_KEYS = ("content", "contents", "code_edit", "new_string")
_TARGET_KEYS = ("file_path", "path", "target_file")


class Adapter:
    name = "generic"
    can_ask = False         # whether the agent can put a question to the user mid-task
    observes_shell = False
    session_chars = 6000    # how much session-start context the agent takes

    def event(self, payload: dict) -> str:
        """pre (a tool call about to run), post (a file was written), session, or empty."""
        return _EVENTS.get(str(payload.get("hook_event_name", "")).lower(), "")

    def cwd(self, payload: dict) -> Path:
        """The folder the tool runs in, which relative paths in its input are relative to."""
        roots = payload.get("workspace_roots") or []
        return Path(payload.get("cwd") or (roots[0] if roots else None) or os.getcwd())

    def project(self, payload: dict) -> Path:
        """The project whose files the agent loads."""
        return self.cwd(payload)

    def root_for(self, payload: dict, path: Path) -> Path:
        """The project `path` belongs to, for an agent that has several open at once."""
        return self.project(payload)

    def command(self, payload: dict) -> str | None:
        """The command line, if the tool call is a shell command."""
        if str(payload.get("tool_name", "")).lower() not in SHELL_TOOLS:
            return None
        command = (payload.get("tool_input") or {}).get("command", "")
        # A command given as its words is quoted word by word: joined with spaces, the
        # script of `["bash", "-lc", "cd x && rm y"]` would read as three commands of the
        # outer shell instead of one argument.
        return shlex.join(map(str, command)) if isinstance(command, list) else command

    def writes(self, payload: dict, project: Path) -> list[Write]:
        """The file changes a tool call would make, from the edit tools' various inputs. A
        call that only names a file (a read, a search) changes nothing."""
        tool_input = payload.get("tool_input") or {}
        tool = str(payload.get("tool_name", "")).lower()
        patch = _patch(tool_input, tool)
        if patch is not None:
            return [Write(c.path, c.old or "", c.new, c.problem) for c in patches.changes(patch, project)]
        path_value = next((tool_input[k] for k in _TARGET_KEYS if k in tool_input), None)
        if not path_value:
            return []
        path = Path(path_value)
        if not path.is_absolute():
            path = project / path
        if tool in DELETE_TOOLS:
            return [_removal(path)]
        old = read_text(path) if path.is_file() else ""
        if "edits" in tool_input:
            new = old
            for e in tool_input["edits"]:
                new = _apply_edit(new, e)
        elif "old_string" in tool_input:
            new = _apply_edit(old, tool_input)
        elif any(k in tool_input for k in _CONTENT_KEYS):
            new = next(tool_input[k] for k in _CONTENT_KEYS if k in tool_input)
        elif tool in WRITE_TOOLS:
            return [Write(path, old, old, f"the {payload.get('tool_name')} call does not say what it writes in a "
                                          "form AgentDetox reads")]
        else:
            return []
        return [Write(path, old, str(new))]

    def written(self, payload: dict, project: Path) -> list[Path]:
        """Files a finished tool call wrote, removed or moved."""
        tool_input = payload.get("tool_input") or {}
        tool = str(payload.get("tool_name", "")).lower()
        patch = _patch(tool_input, tool)
        if patch is not None:
            return patches.touched(patch, payload.get("tool_response"), project)
        # A tool that is named and is not an edit tool wrote nothing, whatever file it names:
        # recording a read would take a file changed by something else for the agent's own.
        if tool and tool not in WRITE_TOOLS | DELETE_TOOLS and not any(
                k in tool_input for k in (*_CONTENT_KEYS, "edits", "old_string")):
            return []
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

    def render_allow(self, event: str = "") -> str:
        return ""

    def render_observation(self, text: str, event: str) -> str:
        return self.render_allow("post")


def _nested_observation(text: str, event: str) -> str:
    if not text:
        return ''
    return json.dumps({'systemMessage': text, 'hookSpecificOutput': {
        'hookEventName': event, 'additionalContext': text}})


class ClaudeCode(Adapter):
    name = "claude-code"
    can_ask = True
    observes_shell = True
    session_chars = 9000

    def project(self, payload: dict) -> Path:
        # The event's cwd follows the session into subfolders; Claude Code gives hooks the
        # project root, whose CLAUDE.md and .claude/ still apply there.
        root = os.environ.get("CLAUDE_PROJECT_DIR")
        return Path(root) if root else self.cwd(payload)

    def transcript(self, payload: dict) -> str | None:
        return payload.get("transcript_path")

    def render_observation(self, text: str, event: str) -> str:
        return _nested_observation(text, event)


class Codex(Adapter):
    name = "codex"
    # PreToolUse and PostToolUse carry the same tool_use_id; PostToolUse also follows a
    # command that failed.
    observes_shell = True

    def project(self, payload: dict) -> Path:
        # Codex reads .codex/ layers, skills and AGENTS.md from the repository root down to
        # the folder it was started in, which is the event's cwd.
        cwd = self.cwd(payload)
        return repository_root(cwd) or cwd

    def render_observation(self, text: str, event: str) -> str:
        return _nested_observation(text, event)


class Cursor(Adapter):
    name = "cursor"
    session_chars = 9000
    # preToolUse, postToolUse and postToolUseFailure carry the same tool_use_id.
    observes_shell = True

    def _roots(self, payload: dict) -> list[Path]:
        roots = [Path(r) for r in payload.get("workspace_roots") or [] if isinstance(r, str) and r]
        # Cursor's own variable; its CLAUDE_PROJECT_DIR alias is for hooks written for Claude Code.
        return roots or ([Path(os.environ["CURSOR_PROJECT_DIR"])] if os.environ.get("CURSOR_PROJECT_DIR") else [])

    def _root_of(self, payload: dict, path: Path) -> Path | None:
        inside = [r for r in self._roots(payload) if _within(path, r)]
        return max(inside, key=lambda r: len(r.parts)) if inside else None

    def cwd(self, payload: dict) -> Path:
        tool_input = payload.get("tool_input")
        folder = tool_input.get("working_directory") if isinstance(tool_input, dict) else None
        if isinstance(folder, str) and folder:
            return Path(folder)
        roots = self._roots(payload)
        return Path(payload.get("cwd") or (roots[0] if roots else None) or os.getcwd())

    def project(self, payload: dict) -> Path:
        # The workspace root, not the folder a tool happens to run in: .cursor/ is read from
        # the root wherever in the workspace the agent is working.
        roots = self._roots(payload)
        if not roots:
            return self.cwd(payload)
        return self._root_of(payload, Path(payload.get("cwd") or roots[0])) or roots[0]

    def root_for(self, payload: dict, path: Path) -> Path:
        return self._root_of(payload, path) or self.project(payload)

    def render_pre(self, decision: Decision) -> str:
        out = {"permission": "deny" if decision.action != "allow" else "allow"}
        if decision.action != "allow":
            out.update(user_message=decision.reason, agent_message=decision.reason)
        return json.dumps(out)

    def render_session(self, text: str) -> str:
        text = text[: self.session_chars]
        return json.dumps({"additional_context": text} if text else {})

    def render_allow(self, event: str = "") -> str:
        # Cursor treats an empty or invalid reply from a permission hook as a block. Hooks that
        # only report take no permission.
        return "{}" if event in ("post", "post-failed", "session") else json.dumps({"permission": "allow"})

    def render_observation(self, text: str, event: str) -> str:
        return json.dumps({"additional_context": text} if text else {})


ADAPTERS = {a.name: a for a in (ClaudeCode(), Codex(), Cursor())}


def get(agent: str) -> Adapter:
    return ADAPTERS.get(agent) or Adapter()


def resolve(agent: str, payload: dict) -> Adapter:
    """The adapter for an event, which is not always the one the hook command names: Cursor
    loads the hooks in Claude Code's settings files and runs them on its own events. Those
    carry `cursor_version`; answering them as Claude Code would send "ask", which Cursor
    accepts and does not enforce."""
    if agent != "cursor" and isinstance(payload, dict) and "cursor_version" in payload:
        return ADAPTERS["cursor"]
    return get(agent)


def _within(path: Path, root: Path) -> bool:
    try:
        Path(os.path.abspath(path)).relative_to(os.path.abspath(root))
        return True
    except ValueError:
        return False


def _removal(path: Path) -> Write:
    """A delete of a file or of a folder; the engine looks for what a folder holds."""
    return Write(path, read_text(path) if path.is_file() else "", None)


def _apply_edit(text: str, edit: dict) -> str:
    old, new = edit.get("old_string", ""), edit.get("new_string", "")
    if not old:
        return text + new
    return text.replace(old, new) if edit.get("replace_all") else text.replace(old, new, 1)


_PATH_KEYS = ("file_path", "path", "target_file", "notebook_path")


def _patch(tool_input: dict, tool: str = "") -> str | None:
    """A Codex apply_patch body. A call that names its target file is an ordinary write,
    even when the text it writes mentions the patch format. The apply_patch tool's own
    input is a patch whatever comes before the envelope; one without an envelope is an
    error, not an edit of nothing."""
    if tool == "apply_patch":
        texts = [v for v in tool_input.values() if isinstance(v, str)]
        found = next((v for v in texts if any(line.strip() == patches.BEGIN for line in v.split("\n"))), None)
        if found is None:
            raise patches.PatchError("the apply_patch call carries no patch envelope")
        return found
    if any(tool_input.get(k) for k in _PATH_KEYS):
        return None
    return next((v for v in tool_input.values() if isinstance(v, str) and v.lstrip().startswith(patches.BEGIN)), None)
