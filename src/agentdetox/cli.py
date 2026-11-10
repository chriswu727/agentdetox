from __future__ import annotations

import argparse
import contextlib
import hashlib
import json
import os
import sys
from collections import Counter
from dataclasses import asdict
from pathlib import Path

from . import (
    __version__,
    allowlist,
    background,
    daemon,
    demo,
    doctor,
    events,
    ledger,
    review,
    settings,
    status,
    storage,
)
from .agentscan import consistency_findings, scan_context
from .allowlist import finding_flag
from .consistency import NLI, NLI_MODEL
from .context import KINDS, PROFILES, discover, display_path, short_path, survey, watched_roots
from .corpus import load_corpus
from .entrypoint import _utf8_output
from .findings import ID_LENGTH, SEVERITY_ORDER, at_least, finding_id, printable
from .hooks import main_hook
from .install import (
    claude_code_plugin,
    claude_code_settings,
    codex_hooks,
    cursor_hooks,
    default_settings_path,
    hook_command,
    install_claude_code,
    remove_claude_code_hooks,
    uninstall_claude_code,
)
from .integrity import StoreError, gc, reset_baseline, snapshot, snapshot_text, store_dir, verify
from .persistence import guarded_sections


def main(argv: list[str] | None = None) -> int:
    _utf8_output()
    parser = argparse.ArgumentParser(prog="agentdetox", description=__doc__)
    parser.add_argument("--version", action="version", version=f"agentdetox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

    p_review = sub.add_parser("review", help="review changes, evidence and exact versions")
    p_review.add_argument("action", nargs="?")
    p_review.add_argument("id", nargs="?")
    p_review.add_argument("--since", help="show recent changes, e.g. 7d")
    p_review.add_argument("--all", action="store_true", help="include changes that need no attention")
    review_scope = p_review.add_mutually_exclusive_group()
    review_scope.add_argument("--project", type=Path, help="only this project's files and Claude auto memory")
    review_scope.add_argument("--global", dest="global_scope", action="store_true", help="include shared user context in interactive review")
    p_review.add_argument("--file", type=Path, help="only this file (relative to --project when supplied)")
    p_review.add_argument("--search", default="", help="match a path or finding description")
    p_review.add_argument("--page", type=int, default=1)
    p_review.add_argument("--page-size", type=int, default=20)
    p_review.add_argument("--group-by", choices=["file", "change"], default="file")
    p_review.add_argument("--interactive", action="store_true", help="browse and handle changes in a terminal")
    p_review.add_argument("--format", choices=["text", "json"], default="text")
    p_restore = sub.add_parser("restore", help="preview recovery of a recorded change")
    p_restore.add_argument("id")
    p_restore.add_argument("--apply", action="store_true", help="apply the previewed recovery")
    p_clean = sub.add_parser("clean", help="preview removal of selected added lines, preserving later edits")
    p_clean.add_argument("id", help="a recorded change (C42) or an inspected library file (M42)")
    p_clean.add_argument("--lines", help="line numbers in the recorded version, e.g. 3,5-7; omit to list added lines")
    p_clean.add_argument("--expected-hash", help="current-file hash printed by the cleanup preview")
    p_clean.add_argument("--apply", action="store_true", help="apply the preview; requires --lines and --expected-hash")
    p_clean.add_argument("--format", choices=["text", "json"], default="text")
    p_export = sub.add_parser("export", help="export change history as JSONL")
    p_export.add_argument("--format", choices=["jsonl"], default="jsonl")
    p_health = sub.add_parser("health", help="acknowledge a previously investigated hook failure")
    p_health.add_argument("action", choices=["acknowledge", "acknowledge-recovery"])
    p_health.add_argument("id", help="event id from events --format json, 'fallback', or recovery id from doctor")

    p_history = sub.add_parser("history", help="preview or apply history retention")
    p_history.add_argument("action", choices=["prune"])
    p_history.add_argument("--older-than", default="90d")
    p_history.add_argument("--apply", action="store_true")

    def corpus_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("path", type=Path, help="directory of .txt/.md/.html files, or a .jsonl file")
        p.add_argument("--text-field", default="text", help="JSONL field holding the passage text")
        p.add_argument("--id-field", default="id", help="JSONL field holding the passage id")
        p.add_argument("--chunk-chars", type=int, default=0, help="split files into ~N-char chunks (0 = whole file)")
        p.add_argument("--embedder", default="auto",
                       help="'auto' (MiniLM if agentdetox[st] is installed, else hashing), 'hashing', or 'st:<model>'")
        p.add_argument("--format", choices=["text", "json"], default="text")

    p_scan = sub.add_parser("scan", help="scan a knowledge base for poisoned or injected documents")
    corpus_args(p_scan)
    p_scan.add_argument("--no-cluster", action="store_true", help="only run the per-document injection detectors")
    p_scan.add_argument("--k", type=int, default=10, help="neighbours per passage in the similarity graph")
    p_scan.add_argument("--z", type=float, default=2.5, help="edge threshold = mean + z * std of kNN similarities")
    p_scan.add_argument("--min-clique", type=int, default=3)
    p_scan.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high",
                        help="exit 1 if any finding is at least this severe (default: high)")

    p_library = sub.add_parser("library", help="inspect a folder of memory files you choose: inventory, scan, review")
    lsub = p_library.add_subparsers(dest="library_command", required=True, metavar="action")
    l_scan = lsub.add_parser("scan", help="list the folder and inspect files that changed since they were inspected")
    l_scan.add_argument("target", help="the folder, or the id of a library scanned before (L1)")
    l_scan.add_argument("--full", action="store_true", help="inspect every file again, not only changed ones")
    l_scan.add_argument("--restart", action="store_true",
                        help="abandon an unfinished run and start a new one; nothing it verified counts")
    l_scan.add_argument("--background", action="store_true", help="scan in a detached worker and return")
    l_scan.add_argument("--format", choices=["text", "json"], default="text")
    l_status = lsub.add_parser("status", help="coverage and progress of each library, or of one")
    l_status.add_argument("target", nargs="?")
    l_status.add_argument("--format", choices=["text", "json"], default="text")
    l_review = lsub.add_parser("review", help="list a library's files by state, or show one file (M42)")
    l_review.add_argument("target", nargs="?", help="a folder, a library id (L1) or a file id (M42)")
    l_review.add_argument("--state", choices=library_states(), default="suspicious")
    l_review.add_argument("--page", type=int, default=1)
    l_review.add_argument("--page-size", type=int, default=20)
    l_review.add_argument("--format", choices=["text", "json"], default="text")
    l_dismiss = lsub.add_parser("dismiss", help="set a finding aside as a false positive in one file, for the exact "
                                                "bytes and detector reviewed; nothing is allowed elsewhere")
    l_dismiss.add_argument("file", help="the file id shown by library review (M42)")
    l_dismiss.add_argument("ids", nargs="+", metavar="id", help="finding ids shown by `library review M42`")
    l_dismiss.add_argument("--expected-hash", required=True, help="review hash printed by `library review M42`")
    l_dismiss.add_argument("--note", default="", help="why it is a false positive, kept and shown with the dismissal")
    l_dismiss.add_argument("--format", choices=["text", "json"], default="text")
    l_reopen = lsub.add_parser("reopen", help="undo a dismissal: the finding is listed and counted again")
    l_reopen.add_argument("file", help="the file id (M42)")
    l_reopen.add_argument("ids", nargs="+", metavar="id", help="dismissed finding ids shown by `library review M42`")
    l_reopen.add_argument("--format", choices=["text", "json"], default="text")
    l_cancel = lsub.add_parser("cancel", help="stop an unfinished scan after the file in hand; it can be continued")
    l_cancel.add_argument("target")
    l_worker = lsub.add_parser("_worker")  # no help: started by scan --background
    l_worker.add_argument("run", type=int)

    p_trace = sub.add_parser("trace", help="find which passages likely caused a wrong answer")
    corpus_args(p_trace)
    p_trace.add_argument("--question", "-q", required=True)
    p_trace.add_argument("--answer", "-a", required=True, help="the wrong answer the RAG system produced")
    p_trace.add_argument("--top-k", type=int, default=5, help="passages your RAG retrieves per query")

    p_agent = sub.add_parser("agent", help="protect an agent's memory, rules, skills and config")
    asub = p_agent.add_subparsers(dest="agent_command", required=True)

    def agent_args(p: argparse.ArgumentParser) -> None:
        p.add_argument("--agent", action="append", choices=sorted(PROFILES),
                       help="limit to these agents (repeatable; default: all known agents)")
        p.add_argument("--project", type=Path, default=Path.cwd(),
                       help="project root whose project-level files to include (default: current directory)")
        p.add_argument("--user-only", action="store_true", help="skip project-level files")
        p.add_argument("--format", choices=["text", "json"], default="text")

    a_scan = asub.add_parser("scan", help="scan context files for planted instructions (read-only)")
    agent_args(a_scan)
    a_scan.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    a_scan.add_argument("--consistency", action="store_true",
                        help="also look for memory entries that contradict each other (needs agentdetox[nli])")
    a_inspect = asub.add_parser("inspect", help="scan, and record what is flagged or changed as review items "
                                                "(C ids) that `review` and `clean` take; nothing flagged is trusted")
    agent_args(a_inspect)
    a_inspect.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    a_snap = asub.add_parser("snapshot", help="record recovery checkpoints for current context files")
    agent_args(a_snap)
    a_snap.add_argument("--reset", action="store_true",
                        help="start a new snapshot list when the old one is damaged or missing")
    a_verify = asub.add_parser("verify", help="report context files changed since the snapshot")
    agent_args(a_verify)
    a_verify.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    a_restore = asub.add_parser("restore", help="put back the snapshotted version; the current one is quarantined")
    a_restore.add_argument("paths", type=Path, nargs="+")
    asub.add_parser("gc", help="delete snapshot copies nothing refers to (also runs daily on its own)")

    p_hook = sub.add_parser("hook", help="hook entry point called by the agent (reads the event JSON on stdin)")
    p_hook.add_argument("agent_name", choices=["claude-code", "codex", "cursor"])

    p_install = sub.add_parser("install", help="register AgentDetox's hooks with an agent")
    p_install.add_argument("agent_name", choices=["claude-code", "codex", "cursor"])
    p_install.add_argument("--scope", choices=["user", "project"], default="user")
    p_install.add_argument("--project", type=Path, default=Path.cwd())
    p_install.add_argument("--apply", action="store_true", help="write the config (default: print it)")

    p_uninstall = sub.add_parser("uninstall", help="remove AgentDetox's hooks, keeping all other settings")
    p_uninstall.add_argument("agent_name", choices=["claude-code"])
    p_uninstall.add_argument("--scope", choices=["user", "project"], default="user")
    p_uninstall.add_argument("--project", type=Path, default=Path.cwd())

    p_events = sub.add_parser("events", help="show what AgentDetox recently asked, blocked, noticed or recorded")
    p_events.add_argument("-n", type=int, default=20, help="number of events (default 20)")
    p_events.add_argument("--format", choices=["text", "json"], default="text")

    p_status = sub.add_parser("status", help="what AgentDetox protects, how its checks are set, what it did lately")
    p_status.add_argument("--project", type=Path, default=Path.cwd())
    p_status.add_argument("--format", choices=["text", "json"], default="text")

    p_allow = sub.add_parser("allow", help="stop flagging something you reviewed, by the id in AgentDetox's message")
    p_allow.add_argument("ids", nargs="*", metavar="id")
    p_allow.add_argument("--note", default="", help="why it is safe, kept with the entry")
    p_allow.add_argument("--list", action="store_true", help="show allowed ids (also the default with no ids)")
    p_allow.add_argument("--remove", action="store_true", help="flag these ids again")

    p_config = sub.add_parser("config", help="show settings, or change one: agentdetox config copied record")
    p_config.add_argument("key", nargs="?", choices=list(settings.DEFAULTS))
    p_config.add_argument("value", nargs="?", choices=settings.MODES)

    p_daemon = sub.add_parser("daemon", help="the background process that keeps the contradiction model loaded")
    p_daemon.add_argument("action", choices=["status", "stop", "retry"])
    p_serve = sub.add_parser("_daemon")  # no help: hidden from the listing
    p_serve.add_argument("--job")

    p_doctor = sub.add_parser("doctor", help="check that hooks are installed, current and runnable (read-only)")
    p_doctor.add_argument("--project", type=Path, default=Path.cwd())

    sub.add_parser("fetch-models", help=f"download the contradiction-detection model ({NLI_MODEL}, ~560 MB)")
    sub.add_parser("demo", help="watch an attack on an agent get caught and undone, in a throwaway folder")

    p_log = sub.add_parser("log", help="what changed in the agent's memory, rules and config, and where it came from")
    p_log.add_argument("path", nargs="?", type=Path, help="only changes to this file")
    p_log.add_argument("-n", type=int, default=30, help="how many of the most recent changes to show")
    p_log.add_argument("--format", choices=["text", "json"], default="text")

    p_blame = sub.add_parser("blame", help="where each line of a memory, rules or config file came from")
    p_blame.add_argument("path", type=Path)

    args = parser.parse_args(argv)
    if args.command in ("review", "restore", "clean", "export", "health", "history"):
        try:
            return _review_command(args)
        except (ValueError, OSError, StoreError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    if args.command == "library":
        try:
            return _library(args)
        except (ValueError, OSError, StoreError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    if args.command == "demo":
        return demo.run()
    if args.command == "log":
        return _log(args)
    if args.command == "blame":
        return _blame(args)
    if args.command == "fetch-models":
        if not NLI.installed():
            print("needs the optional extra: pip install 'agentdetox[nli]'", file=sys.stderr)
            return 2
        NLI(local_only=False).contradiction([("The sky is blue.", "The sky is green.")])
        print(f"{NLI_MODEL} is ready; hooks now check memory writes for contradictions")
        return 0
    if args.command == "_daemon":
        return daemon.serve(args.job)
    if args.command == "daemon":
        return _daemon_command(args.action)
    if args.command == "events":
        rows = events.read(args.n)
        if args.format == "json":
            print(json.dumps(rows, ensure_ascii=False, indent=2))
        else:
            for r in rows:
                what, about, ids = status.describe(r)
                print(f"{r.get('ts', '')}  {what:<13} {about[:150]}" + (f" [{ids}]" if ids else ""))
            if not rows:
                print("no events yet")
        return 0
    if args.command == "status":
        data = status.collect(args.project.expanduser().absolute())
        print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else status.render(data))
        return 0
    if args.command == "allow":
        return _allow(args)
    if args.command == "config":
        return _config(args)
    if args.command == "doctor":
        checks = doctor.run(args.project.expanduser().absolute())
        print(doctor.render(checks))
        return 1 if any(c.status == "fail" for c in checks) else 0
    if args.command == "uninstall":
        target = default_settings_path(args.agent_name, args.scope, args.project.expanduser().absolute())
        try:
            removed, backup = uninstall_claude_code(target)
        except (OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"removed AgentDetox hooks from {target} (backup: {backup})" if removed
              else f"no AgentDetox hooks found in {target}")
        if removed:
            try:
                _trust_own_removal(target, args.project.expanduser().absolute())
            except (StoreError, OSError, ValueError) as e:
                print(f"error: hooks were removed, but recovery metadata could not be updated: {e}. "
                      "Run `agentdetox doctor` to inspect the store.", file=sys.stderr)
                return 2
        return 0
    if args.command == "agent":
        return _agent(args)
    if args.command == "hook":
        return main_hook(args.agent_name)
    if args.command == "install":
        try:
            return _install(args)
        except (StoreError, OSError, ValueError) as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    if not args.path.exists():
        parser.error(f"{args.path} does not exist")
    from .embed import get_embedder
    from .scan import scan
    from .trace import trace

    docs = load_corpus(args.path, args.text_field, args.id_field, args.chunk_chars)
    if not docs:
        parser.error(f"no readable documents under {args.path}")

    if args.command == "scan":
        embedder = None if args.no_cluster else get_embedder(args.embedder)
        result = scan(docs, embedder, k=args.k, z=args.z, min_clique=args.min_clique)
        _print_scan(result, args.format)
        if args.fail_on != "none" and any(at_least(f.severity, args.fail_on) for f in result.findings):
            return 1
        return 0

    embedder = get_embedder(args.embedder)
    texts = [d.text for d in docs]
    if hasattr(embedder, "fit"):
        embedder.fit(texts)
    rows = trace(docs, embedder.encode(texts), embedder, args.question, args.answer, args.top_k)
    _print_trace(rows, args.format)
    return 0


def _log(args) -> int:
    path = str(args.path.expanduser().absolute()) if args.path else None
    rows = ledger.entries(path, limit=args.n) if args.n > 0 else []
    if args.format == "json":
        print(json.dumps([asdict(e) for e in rows], ensure_ascii=False, indent=2))
        return 0
    if not rows:
        print("no recorded changes" + (f" to {short_path(path)}" if path else "") + " yet")
    for e in rows:
        session = f" [session {e.session[:8]}]" if e.session else ""
        print(f"{e.ts.replace('T', ' ')}  {e.origin:<9} {display_path(e.path)}: {e.describe()}{session}")
    return 0


def _blame(args) -> int:
    path = args.path.expanduser().absolute()
    if not path.exists():
        print(f"error: {path} does not exist", file=sys.stderr)
        return 2
    labels = {ledger.EARLIER: "earlier", ledger.UNRECORDED: "not yet recorded"}
    rows = ledger.blame(path)
    for text, cause in rows:
        if isinstance(cause, ledger.Entry):
            label = f"{dict(you='user-text match', copied='tool-text match').get(cause.origin, cause.origin)} {cause.ts[5:16].replace('T', ' ')}"
            if cause.origin == "copied" and cause.source:
                label += " " + cause.source.split()[0]
        else:
            label = labels[cause]
        print(f"{label[:32]:<32} | {text}")
    causes = {cause for _, cause in rows if isinstance(cause, str)}
    notes = {ledger.EARLIER: "earlier: there before AgentDetox recorded a change to this file.",
             ledger.UNRECORDED: "not yet recorded: changed since, outside the agent's edit tools; the next "
                                "session records it."}
    print("\n" + "\n".join(notes[c] for c in (ledger.EARLIER, ledger.UNRECORDED) if c in causes)
          + f"\nDetails: agentdetox log {short_path(str(path))}")
    return 0


def _trust_own_removal(path: Path, project: Path) -> None:
    """Take the file without AgentDetox's hooks as its new snapshot, as `install` does with
    them, so the removal is not reported as tampering. Only when nothing else it guards has
    changed since the snapshot: anything that has is still reported at the next session."""
    before = snapshot_text(str(path))
    if before is None:
        return
    data = path.read_bytes()
    try:
        expected = json.dumps(remove_claude_code_hooks(json.loads(before)))
    except ValueError:
        return
    cf = next((cf for cf in discover(project=project) if cf.path == path), None)
    if cf is None:
        return
    if guarded_sections(path, expected) != guarded_sections(path, data.decode("utf-8", "replace")):
        print("Other settings in this file changed since AgentDetox last checked it; the next session reports "
              "them, with the hooks' removal. `agentdetox review` shows them.")
        return
    snapshot([cf], watched_roots(project), expected={str(path): hashlib.sha256(data).hexdigest()})


def _install(args) -> int:
    project = args.project.expanduser().absolute()
    target = default_settings_path(args.agent_name, args.scope, project)
    if args.agent_name == "claude-code":
        plugin = claude_code_plugin(project)
        if plugin:
            print(f"The {plugin} plugin is enabled in Claude Code and already runs AgentDetox's hooks. Adding "
                  "them to settings as well would run every check twice, so nothing was changed.")
            return 0
        _, backup = install_claude_code(target, args.apply)
        if not args.apply:
            added = claude_code_settings({}, hook_command("claude-code"))
            print(f"# Adds these hooks to {short_path(str(target))}, keeping everything else in it:\n"
                  f"{json.dumps(added, indent=2, ensure_ascii=False)}\n"
                  "Re-run with --apply to write it (the old file is backed up).")
            return 0
        # Scan before trusting, so content that is already poisoned never becomes the baseline.
        files = discover(project=project)
        flagged = {f.doc_id for f in allowlist.unsuppressed(scan_context(files)) if f.severity == "high"}
        trusted = [cf for cf in files if str(cf.path) not in flagged]
        snapshot(trusted, watched_roots(project))
        kinds = Counter(cf.kind for cf in trusted)
        print(f"AgentDetox hooks added to {short_path(str(target))}"
              + (f" (backup: {short_path(str(backup))})" if backup else "") + ".")
        print("Restart Claude Code to load them. From then on AgentDetox checks every write Claude Code makes to "
              "its memory, rules, skills and config, and reports changes made outside it at the next session.")
        print(f"Watching {len(trusted)} context files ("
              + ", ".join(f"{kinds[k]} {k}" for k in KINDS if kinds[k]) + ").")
        if flagged:
            print(f"{len(flagged)} file(s) look suspicious and were left out of the snapshot; "
                  "review them with `agentdetox agent scan`.")
        print("See it catch an attack without touching your files: agentdetox demo\n"
              "Check on it any time: agentdetox status")
        return 0
    command = hook_command(args.agent_name)
    if args.agent_name == "cursor":
        print(f"# Experimental, built from Cursor's hooks documentation and not yet verified on a real install.\n"
              f"# Merge into {target}:")
        print(json.dumps(cursor_hooks(command), indent=2))
        print("# Cursor does not enforce \"ask\" from preToolUse, so AgentDetox blocks or records there. If Cursor "
              "also loads\n# Claude Code's hooks (Settings, Third-Party Imports), AgentDetox's hooks in "
              "~/.claude/settings.json run in Cursor too.")
    else:
        print(f"# Experimental. Merge into {target}:")
        print(json.dumps(codex_hooks(command), indent=2))
        print("# Codex runs a hook only after you review and trust it: open /hooks in Codex. A hook whose command "
              "changes\n# (an upgrade that moves agentdetox) is skipped until it is trusted again. Codex cannot "
              "ask from a hook, so\n# AgentDetox blocks or records there.")
    if args.apply:
        print("\n--apply is only supported for claude-code until installing these hooks is verified on real "
              "installs.", file=sys.stderr)
        return 2
    return 0


def _daemon_command(action: str) -> int:
    if action == "retry":
        requeued, waiting = daemon.retry()
        remaining = len(background.failed())
        if remaining:
            print(f"{requeued} failed check(s) queued again; {remaining} failed check(s) could not be retried. "
                  "Inspect `agentdetox doctor` and the retained queue files.")
            return 1
        print(f"{requeued} failed check(s) queued again; the background worker now has {waiting} check(s) to run"
              if waiting else "no background checks are waiting or failed")
        return 0
    info = daemon.ping()
    if action == "stop":
        if info is None:
            print("not running")
            return 0
        stopped = daemon.stop()
        print(f"stopped (pid {info['pid']})" if stopped else f"pid {info['pid']} did not stop within 10 s")
        return 0 if stopped else 1
    if info is None:
        print("not running; starts on the next changed memory write; loads the model only for candidates" if daemon.SERVER
              else "not available on Windows yet: each contradiction check loads the model in a background worker")
        return 0
    print(f"running: pid {info['pid']}, started {info['started'].replace('T', ' ')}, model "
          f"{'loaded' if info['model_loaded'] else 'not loaded yet'}, {info['jobs']} job(s), "
          f"idle {info['idle_seconds'] // 60} min (exits after {int(daemon.idle_seconds() // 60)})")
    if info["code"] != daemon.code_id():
        print("it runs an older build and will be replaced on its next job")
    return 0


def _allow(args) -> int:
    if args.list or not args.ids:
        rows = allowlist.entries()
        for i, e in rows.items():
            note = f"  ({e['note']})" if e.get("note") else ""
            print(f"{i}  {e.get('added', '')[:10]}  {e.get('what', '')[:120]}{note}")
        if not rows:
            print("nothing allowed yet; ids appear in every AgentDetox message and in `agentdetox agent scan`")
        return 0
    bad = [i for i in args.ids if not allowlist.ID_RE.match(i)]
    if bad:
        print(f"error: not an AgentDetox id: {' '.join(bad)} (ids are {ID_LENGTH} hex characters)", file=sys.stderr)
        return 2
    try:
        if args.remove:
            for i in args.ids:
                print(f"{i} will be flagged again" if allowlist.remove(i) else f"{i} was not allowed")
            return 0
        known = _describe_ids(args.ids)
        for i in args.ids:
            allowlist.add(i, known.get(i, ""), args.note)
            print(f"allowed {i}: {known[i]}" if i in known else
                  f"allowed {i} (not seen in the event log or current context files; check the id, and undo "
                  f"with `agentdetox allow --remove {i}`)")
    except ValueError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2
    return 0


def _describe_ids(ids: list[str]) -> dict[str, str]:
    """What each id was flagged for: from the event log, else from a rules scan of the
    current context files. Contradiction ids from `agent scan --consistency` need the log."""
    found: dict[str, str] = {}
    for r in events.read(None):
        for f in r.get("flags") or []:
            found.setdefault(f.get("id", ""), f.get("what", ""))
        if r.get("event") == "contradiction" and r.get("id"):
            found.setdefault(r["id"], status.describe(r)[1])
    if not set(ids) <= set(found):
        for f in scan_context(discover(project=Path.cwd())):
            flag = finding_flag(f)
            found.setdefault(flag.id, flag.what)
    return {i: found[i] for i in ids if i in found}


def _config(args) -> int:
    if args.key and args.value:
        try:
            path = settings.set_mode(args.key, args.value)
        except ValueError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
        print(f"{args.key} = {args.value} ({path})")
        var = f"AGENTDETOX_{args.key.upper()}"
        if os.environ.get(var):
            print(f"note: {var}={os.environ[var]} is set in this environment and overrides the file")
        return 0
    current, problems = settings.load()
    for s in current:
        if args.key in (None, s.key):
            source = {"default": "default", "config": "config file", "env": f"AGENTDETOX_{s.key.upper()}"}[s.source]
            print(f"{s.key:<14} {s.value:<7} {settings.LABELS[s.key]} ({source})")
    path = settings.config_path()
    print(f"\nconfig file: {path}" + ("" if path.exists() else
                                       " (not created yet; `agentdetox config <key> <value>` creates it)"))
    print("values: ask (Claude Code asks you first), record (allowed and logged), off")
    for p in problems:
        print(f"warning: {p}", file=sys.stderr)
    return 0


def _agent(args) -> int:
    try:
        return _agent_command(args)
    except StoreError as e:
        print(f"error: {e}", file=sys.stderr)
        return 2


def _agent_command(args) -> int:
    if args.agent_command == "gc":
        freed = gc(force=True)
        print(f"removed {freed['objects']} old snapshot cop{'y' if freed['objects'] == 1 else 'ies'} "
              f"({freed['bytes'] / 1024:.0f} KB); quarantined files are kept")
        return 0
    if args.agent_command == "restore":
        for path in args.paths:
            try:
                print(review.restore_trusted(path.expanduser().absolute()))
            except KeyError as e:
                print(f"error: {e.args[0]}", file=sys.stderr)
                return 2
            except (OSError, StoreError) as e:
                print(f"error: {e}", file=sys.stderr)
                return 1
        return 0

    project = None if args.user_only else args.project.expanduser().absolute()
    if args.agent_command == "inspect":
        return _inspect(args, project)
    found = survey(args.agent, project)
    files = found.files
    roots = watched_roots(project)

    if args.agent_command == "snapshot":
        if args.reset:
            kept = reset_baseline()
            if kept:
                print(f"old snapshot list kept as {kept}")
        # Like install and the first session: a planted instruction never becomes trusted
        # by accident. Allowing its id is the deliberate way.
        flagged = {f.doc_id for f in allowlist.unsuppressed(scan_context(files)) if f.severity == "high"}
        n = snapshot([cf for cf in files if str(cf.path) not in flagged], roots)
        print(f"snapshot of {n} context file(s) saved to {store_dir()}")
        if flagged:
            print(f"left out {len(flagged)} file(s) with high-severity findings; record them for review and cleanup "
                  "with `agentdetox agent inspect`, or `agentdetox allow <id>` if they are fine:")
            for path in sorted(flagged):
                print(f"  {path}")
        for problem in found.problems:
            print(f"not resolved: {problem}", file=sys.stderr)
        return 0

    if args.agent_command == "scan":
        hits = []
        for cf in files:
            try:
                hits += scan_context([cf])
            except OSError as error:
                found.unread.append(f"{cf.path} could not be read ({type(error).__name__})")
        if args.consistency:
            nli = NLI()
            if not nli.available():
                print("contradiction check skipped: install 'agentdetox[nli]' and run `agentdetox fetch-models`",
                      file=sys.stderr)
            else:
                hits += consistency_findings(files, project, nli)
        findings = allowlist.unsuppressed(hits)
        header = f"agentdetox {__version__}: scanned {len(files)} context file(s)"
        _print_findings(findings, header, args.format, len(hits) - len(findings),
                        extra={"files": [str(f.path) for f in files]}, found=found)
    else:
        changes, hits = verify(files, roots)
        findings = allowlist.unsuppressed(hits)
        header = f"agentdetox {__version__}: {len(changes)} context file(s) changed since snapshot"
        for c in changes:
            header += f"\n  {c.status:<8} {c.kind:<12} {c.path}"
        _print_findings(findings, header, args.format, len(hits) - len(findings),
                        extra={"changes": [{"path": c.path, "status": c.status, "kind": c.kind} for c in changes]},
                        found=found)
    if args.fail_on != "none" and (found.problems or any(at_least(f.severity, args.fail_on) for f in findings)):
        return 1
    return 0


def _inspect(args, project: Path | None) -> int:
    from . import inspection

    result = inspection.run(args.agent, project)
    found = result["survey"]
    items = result["items"]
    # Incomplete: a folder that was asked for was not looked in, or a file found was not read.
    incomplete = bool(found.problems or result["unread"])
    if args.format == "json":
        print(json.dumps({"version": __version__, "files": result["files"], "checkpointed": result["trusted"],
                          "complete": not incomplete, "items": items, "unread": result["unread"],
                          "coverage": inspection.coverage(found), "problems": found.problems},
                         ensure_ascii=False, indent=2))
    else:
        print(f"agentdetox {__version__}: inspected {result['files']} context file(s)\n")
        print("\n".join(inspection.render_coverage(found, short_path)))
        if result["unread"]:
            print("Not inspected (found, but not read):")
            for row in result["unread"]:
                print(f"  {short_path(row['path'])} ({row['error']})")
        review_items = [item for item in items if item["state"] == "review"]
        if review_items:
            print("\nNeeds review (each id is bound to the exact version found):")
        for item in review_items:
            worst = "HIGH" if any(f["severity"] == "high" for f in item["findings"]) else "MEDIUM"
            print(f"  {item['changes'][0]:<6} {worst:<6} {display_path(item['path'])}  ({item['agent']} {item['kind']})")
            for f in item["findings"]:
                line = f"line {f['line']}: " if f["line"] else ""
                print(f"         {f['id']} {line}{printable(f['reason'])}")
        others = [item for item in items if item["state"] != "review"]
        if others:
            print("\nRecorded, with nothing flagged:")
            for item in others:
                print(f"  {item['changes'][0]:<6} {item['state']:<8} {display_path(item['path'])}")
        print(f"\n{result['trusted']} file(s) have a recovery checkpoint of the version inspected. A checkpoint is "
              "something to restore to, not an acceptance: a file with a clear-cut (high) finding gets none, and a "
              "file with only lesser findings gets one while those findings stay open for review. Nothing was "
              "allowed.")
        if review_items:
            first = review_items[0]["changes"][0]
            print(f"Next: `agentdetox review {first}` shows a record; `agentdetox clean {first}` lists its lines, and "
                  f"with --lines previews removing the ones you choose.\n"
                  "A cleanup keeps a backup and can be undone with `agentdetox restore` on the record it prints. "
                  "Config files are not cleaned line by line.")
        if incomplete:
            print("The inspection is incomplete: what is listed as not resolved or not inspected was not looked at"
                  + ("." if items else ", so finding nothing here does not mean nothing is there."))
        elif not items:
            print("Nothing needs review.")
    severities = [f["severity"] for item in items for f in item["findings"]]
    if args.fail_on != "none" and (incomplete or any(at_least(sev, args.fail_on) for sev in severities)):
        return 1
    return 0


def _print_findings(findings, header: str, fmt: str, allowed: int, extra: dict, found=None) -> None:
    from . import inspection

    findings = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.doc_id))
    if fmt == "json":
        coverage = {"coverage": inspection.coverage(found), "problems": found.problems} if found is not None else {}
        json.dump({"version": __version__, **extra, "allowed": allowed, "findings": [f.to_dict() for f in findings],
                   **coverage}, sys.stdout, ensure_ascii=False, indent=2)
        print()
        return
    print(header + "\n")
    if found is not None:
        print("\n".join(inspection.render_coverage(found, short_path)) + "\n")
    for f in findings:
        print(f"{f.severity.upper():<6} {f.detector:<17} {f.source}  [{finding_id(f)}]")
        print(f"       {printable(f.message)}")
        if f.evidence:
            print(f"       > {printable(' '.join(f.evidence.split())[:160])}")
    counts = Counter(f.severity for f in findings)
    print(f"\n{counts['high']} high, {counts['medium']} medium, {counts['low']} low"
          + (f"; {allowed} allowed and not shown (`agentdetox allow --list`)" if allowed else ""))
    if found is not None and found.problems:
        print("The scan is incomplete: the folders listed under \"Not resolved\" were not looked at.")
    if findings:
        print("To review and remove flagged lines: `agentdetox agent inspect` records them as review items for "
              "`agentdetox clean`.\nFalse positive? `agentdetox allow <id>` stops it being reported.")


def _print_scan(result, fmt: str) -> None:
    findings = sorted(result.findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.cluster or 0, f.doc_id))
    if fmt == "json":
        c = result.cluster
        json.dump(
            {
                "version": __version__,
                "documents": result.n_docs,
                "embedder": result.embedder,
                "cluster_threshold": None if c.tau is None else {"tau": c.tau, "mu": c.mu, "sigma": c.sigma},
                "findings": [f.to_dict() for f in findings],
            },
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        print()
        return

    print(f"agentdetox {__version__}: scanned {result.n_docs} passages", end="")
    print(f" (embedder: {result.embedder})" if result.embedder else " (clustering off)")
    c = result.cluster
    if c.tau is not None:
        print(f"similarity-clique threshold tau={c.tau:.3f} (mu={c.mu:.3f}, sigma={c.sigma:.3f}); "
              f"{len(c.groups)} suspicious cluster(s)")
    print()
    for f in findings:
        tag = f" [cluster {f.cluster}]" if f.cluster else ""
        print(f"{f.severity.upper():<6} {f.detector:<17} {f.source}{tag}")
        print(f"       {printable(f.message)}")
        if f.evidence:
            print(f"       > {printable(' '.join(f.evidence.split())[:160])}")
    counts = Counter(f.severity for f in findings)
    docs_hit = len({f.doc_id for f in findings})
    print(f"\n{counts['high']} high, {counts['medium']} medium, {counts['low']} low across {docs_hit} passage(s)")


def _print_trace(rows, fmt: str) -> None:
    if fmt == "json":
        json.dump(
            [
                {
                    "id": r.doc.id, "source": r.doc.source, "score": r.score, "responsible": r.responsible,
                    "retrieval": r.retrieval, "answer_similarity": r.answer_sim,
                    "contains_answer": r.contains_answer, "injection_markers": r.markers,
                }
                for r in rows
            ],
            sys.stdout,
            ensure_ascii=False,
            indent=2,
        )
        print()
        return
    print("Approximate attribution (embedding signals only; see README for limits)\n")
    print(f"{'':2}{'score':>7} {'retr':>6} {'ans':>6} {'has-ans':>7}  source")
    for r in rows:
        mark = "=>" if r.responsible else "  "
        extra = f"  [{', '.join(r.markers)}]" if r.markers else ""
        print(f"{mark}{r.score:7.2f} {r.retrieval:6.3f} {r.answer_sim:6.3f} {str(r.contains_answer):>7}  {r.doc.source}{extra}")
    n = sum(r.responsible for r in rows)
    print(f"\n{n} passage(s) marked => as likely responsible")



def library_states() -> tuple[str, ...]:
    # The states are the inventory's; the module is loaded only for library commands.
    return ("suspicious", "low", "dismissed", "stale", "queued", "uninspected", "failed", "missing", "inspected")


@contextlib.contextmanager
def _stop_requested():
    """A function saying whether Ctrl-C or a termination signal arrived, so that a scan
    stops after the file in hand and saves what it verified."""
    import signal
    import threading

    flag = threading.Event()
    previous = {}
    for name in ("SIGINT", "SIGTERM"):
        with contextlib.suppress(ValueError, OSError, AttributeError):
            previous[getattr(signal, name)] = signal.signal(getattr(signal, name), lambda *_: flag.set())
    try:
        yield flag.is_set
    finally:
        for number, handler in previous.items():
            with contextlib.suppress(ValueError, OSError):
                signal.signal(number, handler)


def _scan_progress():
    import time

    last = [time.monotonic()]

    def report(**info) -> None:
        now = time.monotonic()
        if now - last[0] < 2.0:
            return
        last[0] = now
        text = (f"listing folders: {info['folders']:,} done" if info["phase"] == "enumerate" else
                f"verifying files: {info['done']:,} of {info['total']:,}")
        print(f"agentdetox library: {text}", file=sys.stderr, flush=True)

    return report


def _library(args) -> int:
    from . import library

    command = args.library_command
    if command == "_worker":
        with library.runner_lock(wait=library.LOCK_PATIENCE) as held:
            if not held:
                print("agentdetox library: another scan holds the library lock; this worker did not start",
                      file=sys.stderr)
                return 2
            with _stop_requested() as stop:
                state = library.run(args.run, stop=stop)
        print(f"agentdetox library: run {args.run} {state}", file=sys.stderr)
        return 0
    if command == "cancel":
        print(library.cancel(args.target))
        return 0
    if command in ("dismiss", "reopen"):
        result = (library.dismiss(args.file, args.ids, expected_hash=args.expected_hash, note=args.note)
                  if command == "dismiss" else library.reopen(args.file, args.ids))
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.format == "json" else library.render_triage(result))
        return 0
    if command == "status":
        rows = library.status(args.target)
        print(json.dumps(rows, ensure_ascii=False, indent=2) if args.format == "json" else library.render_status(rows))
        return 0
    if command == "review":
        target = args.target
        if target is None:
            known = library.status()
            if len(known) != 1:
                raise ValueError("Name the library to review: a folder, L<ID>, or a file M<ID> "
                                 "(`agentdetox library status` lists them)")
            target = known[0]["id"]
        if target[:1] in ("M", "m") and target[1:].isdigit():
            data = library.detail(target)
            print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else library.render_detail(data))
        else:
            data = library.page(target, args.state, args.page, args.page_size)
            print(json.dumps(data, ensure_ascii=False, indent=2) if args.format == "json" else library.render_page(data))
        return 0
    state = "prepared"
    with library.runner_lock(wait=library.LOCK_PATIENCE) as held:
        if not held:
            raise StoreError("A library scan is already running. `agentdetox library status` shows its progress; "
                             "`agentdetox library cancel <folder>` stops it")
        run = library.prepare(args.target, full=args.full, restart=args.restart)
        what = (f"Continuing run {run['run']} ({run['mode']})" if run["resumed"] else
                f"Run {run['run']} ({run['mode']})") + f" of library {run['root']} · {short_path(run['path'])}"
        if not args.background:
            print(what, file=sys.stderr, flush=True)
            with _stop_requested() as stop:
                state = library.run(run["run"], progress=_scan_progress(), stop=stop)
    if args.background:
        started, detail = library.start_background(run["run"])
        if not started:
            print(f"error: {detail}. Run {run['run']} is saved: after fixing the cause, continue it with "
                  f"`agentdetox library scan {run['root']}`.", file=sys.stderr)
            return 1
        if args.format == "json":
            print(json.dumps({**run, "background": True, "worker": detail}, ensure_ascii=False, indent=2))
        else:
            print(f"{what} is scanning in the background ({detail}).\n"
                  f"Progress: agentdetox library status {run['root']}\nStop: agentdetox library cancel {run['root']}")
        return 0
    rows = library.status(run["root"])
    print(json.dumps(rows, ensure_ascii=False, indent=2) if args.format == "json" else library.render_status(rows))
    if state == "cancelled":
        print(f"Stopped before the end. What was verified is kept; continue with `agentdetox library scan "
              f"{run['root']}`.", file=sys.stderr)
        return 3
    return 0


def _review_command(args) -> int:
    if args.command == 'review' and args.interactive:
        if args.action or args.id or args.format == 'json':
            raise ValueError('Use --interactive with list filters, without an action, id or JSON format')
        from . import review_ui

        return review_ui.run(global_scope=args.global_scope, since=args.since, all_changes=args.all, project=args.project, file=args.file,
                             search=args.search, page_number=args.page, page_size=args.page_size, group_by=args.group_by)
    if args.command == "history":
        result = review.prune(args.older_than, args.apply)
        print(f"{'Removed' if args.apply else 'Would remove'} {result['changes']} history entries and "
              f"{result['events']} events. Pending findings, approved versions and each file's latest entry are kept.")
        print("Run `agentdetox agent gc` to remove unreferenced objects." if args.apply else
              "Add --apply to remove these records. History before the retained boundary will no longer be attributed.")
    elif args.command == "restore":
        print(review.restore(args.id, args.apply))
    elif args.command == "clean":
        if args.id[:1] in ("M", "m"):
            from . import library

            result = library.clean(args.id, args.lines, apply=args.apply, expected_hash=args.expected_hash)
        else:
            result = review.clean(args.id, args.lines, apply=args.apply, expected_hash=args.expected_hash)
        print(json.dumps(result, ensure_ascii=False, indent=2) if args.format == 'json' else review.render_cleanup(result))
    elif args.command == "export":
        for entry in ledger.entries():
            print(json.dumps(asdict(entry), ensure_ascii=False))
    elif args.command == "health":
        if args.action == 'acknowledge-recovery':
            review.acknowledge_recovery(args.id)
            print('Acknowledged this recovery after checking the on-disk version. File contents were not changed.')
            return 0
        if args.id == 'fallback':
            import uuid

            from .integrity import store_lock

            with store_lock():
                path = store_dir() / 'events-fallback.jsonl'
                if not path.exists():
                    raise ValueError('No fallback events to acknowledge')
                kept = path.with_name(f'events-fallback.acknowledged-{uuid.uuid4().hex}.jsonl')
                path.replace(kept)
            print(f'Acknowledged fallback events; retained at {kept}. Future errors remain visible.')
            return 0
        with storage.connection(write=True) as db:
            changed = db.execute("UPDATE events SET resolved=1 WHERE id=? AND event='hook_error'", (args.id,)).rowcount
            if not changed:
                raise ValueError("Unknown hook failure event")
        print("Acknowledged this failure. Future failures will still degrade protection status.")
    elif args.action == "accept":
        if not args.id:
            raise ValueError("Use agentdetox review accept C<ID>")
        review.accept(args.id)
        print(f"Accepted {args.id}: only this exact version, with no permanent source exception.")
    elif args.action == "dismiss":
        if not args.id:
            raise ValueError("Use agentdetox review dismiss F<ID>")
        review.dismiss(args.id)
        print(f"Dismissed {args.id}: the file is unchanged and no permanent exception was added.")
    elif args.action:
        detail = review.detail(args.action)
        print(json.dumps({"change": review.get(args.action), "detail": detail}, ensure_ascii=False, indent=2)
              if args.format == "json" else detail)
    else:
        data = review.page(since=args.since, all_changes=args.all, project=args.project, file=args.file,
                           search=args.search, page_number=args.page, page_size=args.page_size, group_by=args.group_by)
        print(json.dumps(data, indent=2, ensure_ascii=False) if args.format == "json" else review.render_page(data))
    return 0


if __name__ == "__main__":
    sys.exit(main())
