from __future__ import annotations

import sys


def _utf8_output() -> None:
    # Memory is often Chinese or other non-Latin text. Windows encodes piped output (an
    # agent running `agentdetox status`) as cp1252 and would crash on it; agents read UTF-8.
    for stream in (sys.stdout, sys.stderr):
        if (getattr(stream, "encoding", None) or "").lower().replace("-", "") != "utf8" and hasattr(stream, "reconfigure"):
            stream.reconfigure(encoding="utf-8", errors="replace")


def main(argv: list[str] | None = None) -> int:
    args = sys.argv[1:] if argv is None else argv
    if len(args) == 2 and args[0] == "hook" and args[1] in ("claude-code", "codex", "cursor"):
        from .hooks import main_hook

        _utf8_output()
        return main_hook(args[1])
    from .cli import main as cli_main

    return cli_main(args)
