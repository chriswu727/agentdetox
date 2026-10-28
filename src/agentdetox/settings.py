"""User settings in ~/.agentdetox/config.toml.

An environment variable AGENTDETOX_<KEY> overrides the file, so one run (a benchmark, a
CI job) can differ from the everyday setup. A hook must keep working when the file is
broken, so problems fall back to the defaults and are reported by `agentdetox doctor`
and `agentdetox status` instead of raising.
"""

from __future__ import annotations

import os
import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .integrity import private_dir, store_dir, store_lock, write_private

MODES = ("ask", "record", "off")
DEFAULTS = {"suspicious": "ask", "copied": "ask", "contradiction": "record"}
LABELS = {
    "suspicious": "suspicious writes",
    "copied": "copied from untrusted input",
    "contradiction": "contradictions",
}

TEMPLATE = """\
# AgentDetox settings. Change them here or with `agentdetox config <key> <value>`.
# An environment variable (AGENTDETOX_SUSPICIOUS, AGENTDETOX_COPIED,
# AGENTDETOX_CONTRADICTION) overrides the value here.
#
# Each check is one of:
#   "ask"     Claude Code asks you before the write (agents without an ask
#             prompt record instead)
#   "record"  the write goes through and is logged; see `agentdetox events`
#   "off"
# Writes that clearly plant instructions are always blocked. If one of those is a
# false positive, run `agentdetox allow <id>` with the id from the message.

[checks]
# Writes to agent memory, rules or skills that look like planted instructions but
# are not clear-cut.
suspicious = "{suspicious}"

# Memory copied from a web page, file, command or MCP tool output the agent just
# read, when you did not ask it to remember anything.
copied = "{copied}"

# New memory that contradicts existing memory (needs agentdetox[nli]). The model
# still misreads terse notes, so the default only records.
contradiction = "{contradiction}"
"""


@dataclass
class Setting:
    key: str
    value: str
    source: str  # "default", "config" or "env"


def config_path() -> Path:
    return store_dir() / "config.toml"


def _read_checks() -> tuple[dict, list[str]]:
    path = config_path()
    if not path.exists():
        return {}, []
    try:
        data = tomllib.loads(path.read_text(encoding="utf-8"))
    except (OSError, UnicodeDecodeError, tomllib.TOMLDecodeError) as e:
        return {}, [f"{path} could not be read ({e}); using the defaults"]
    checks = data.get("checks", {})
    if not isinstance(checks, dict):
        return {}, [f"[checks] in {path} is not a table; using the defaults"]
    unknown = sorted(set(data) - {"checks"}) + sorted(set(checks) - set(DEFAULTS))
    problems = [f"unknown setting {k!r} in {path} is ignored" for k in unknown]
    return checks, problems


def load() -> tuple[list[Setting], list[str]]:
    """Effective settings and any problems found while reading them."""
    checks, problems = _read_checks()
    out = []
    for key, default in DEFAULTS.items():
        var = f"AGENTDETOX_{key.upper()}"
        env = os.environ.get(var)
        if env:
            if env in MODES:
                out.append(Setting(key, env, "env"))
                continue
            problems.append(f"{var}={env!r} is not one of {', '.join(MODES)}; ignored")
        value = checks.get(key)
        if value is None:
            out.append(Setting(key, default, "default"))
        elif value in MODES:
            out.append(Setting(key, value, "config"))
        else:
            problems.append(f"{key} = {value!r} in {config_path()} is not one of {', '.join(MODES)}; "
                            f'using "{default}"')
            out.append(Setting(key, default, "default"))
    return out, problems


def mode(key: str) -> str:
    return next(s.value for s in load()[0] if s.key == key)


def set_mode(key: str, value: str) -> Path:
    """Change one check in the config file, keeping the rest of the file as written."""
    if key not in DEFAULTS:
        raise ValueError(f"unknown setting {key!r}; one of {', '.join(DEFAULTS)}")
    if value not in MODES:
        raise ValueError(f"{key} must be one of {', '.join(MODES)}")
    with store_lock():
        return _set_mode(key, value)


def _set_mode(key: str, value: str) -> Path:
    path = config_path()
    text = path.read_text(encoding="utf-8") if path.exists() else TEMPLATE.format(**DEFAULTS)
    line = f'{key} = "{value}"'
    existing = re.compile(rf"(?m)^[ \t]*{key}[ \t]*=.*$")
    header = re.compile(r"(?m)^\[checks\][ \t]*$")
    if existing.search(text):
        text = existing.sub(lambda _: line, text, count=1)
    elif header.search(text):
        text = header.sub(lambda _: "[checks]\n" + line, text, count=1)
    else:
        text = text.rstrip("\n") + "\n\n[checks]\n" + line + "\n"
    try:
        written = tomllib.loads(text).get("checks", {}).get(key)
    except tomllib.TOMLDecodeError:
        written = None
    if written != value:
        raise ValueError(f"{path} is not valid TOML or has an unexpected layout; edit it by hand")
    tmp = private_dir(store_dir()) / "config.toml.tmp"
    write_private(tmp, text.encode())
    tmp.replace(path)
    return path
