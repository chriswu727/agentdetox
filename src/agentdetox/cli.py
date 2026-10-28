from __future__ import annotations

import argparse
import json
import os
import sys
from collections import Counter
from pathlib import Path

from . import __version__, allowlist, daemon, doctor, events, settings, status
from .agentscan import consistency_findings, scan_context
from .allowlist import finding_flag
from .consistency import NLI, NLI_MODEL
from .context import PROFILES, discover, home_dir
from .corpus import load_corpus
from .embed import get_embedder
from .findings import ID_LENGTH, SEVERITY_ORDER, at_least, finding_id
from .hooks import main_hook
from .install import cursor_hooks, default_settings_path, hook_command, install_claude_code, uninstall_claude_code
from .integrity import StoreError, gc, reset_baseline, restore, snapshot, store_dir, verify
from .scan import scan
from .trace import trace


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="agentdetox", description=__doc__)
    parser.add_argument("--version", action="version", version=f"agentdetox {__version__}")
    sub = parser.add_subparsers(dest="command", required=True, metavar="command")

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

    a_scan = asub.add_parser("scan", help="scan context files for planted instructions")
    agent_args(a_scan)
    a_scan.add_argument("--fail-on", choices=["low", "medium", "high", "none"], default="high")
    a_scan.add_argument("--consistency", action="store_true",
                        help="also look for memory entries that contradict each other (needs agentdetox[nli])")
    a_snap = asub.add_parser("snapshot", help="record the current context files as trusted")
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
    p_daemon.add_argument("action", choices=["status", "stop"])
    p_serve = sub.add_parser("_daemon")  # no help: hidden from the listing
    p_serve.add_argument("--job")

    p_doctor = sub.add_parser("doctor", help="check that hooks are installed, current and runnable (read-only)")
    p_doctor.add_argument("--project", type=Path, default=Path.cwd())

    sub.add_parser("fetch-models", help=f"download the contradiction-detection model ({NLI_MODEL}, ~560 MB)")

    args = parser.parse_args(argv)
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
        removed, backup = uninstall_claude_code(target)
        print(f"removed AgentDetox hooks from {target} (backup: {backup})" if removed
              else f"no AgentDetox hooks found in {target}")
        return 0
    if args.command == "agent":
        return _agent(args)
    if args.command == "hook":
        return main_hook(args.agent_name)
    if args.command == "install":
        try:
            return _install(args)
        except StoreError as e:
            print(f"error: {e}", file=sys.stderr)
            return 2
    if not args.path.exists():
        parser.error(f"{args.path} does not exist")
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


def _install(args) -> int:
    project = args.project.expanduser().absolute()
    target = default_settings_path(args.agent_name, args.scope, project)
    if args.agent_name == "claude-code":
        text, backup = install_claude_code(target, args.apply)
        if not args.apply:
            print(f"# {target} would become:\n{text}\nRe-run with --apply to write it (the old file is backed up).")
            return 0
        # Scan before trusting, so content that is already poisoned never becomes the baseline.
        files = discover(project=project)
        flagged = {f.doc_id for f in allowlist.unsuppressed(scan_context(files)) if f.severity == "high"}
        n = snapshot([cf for cf in files if str(cf.path) not in flagged], [home_dir(), project])
        print(f"wrote AgentDetox hooks to {target}" + (f" (backup: {backup})" if backup else ""))
        print(f"snapshot of {n} context file(s) taken; restart Claude Code to load the hooks")
        if flagged:
            print(f"{len(flagged)} file(s) look suspicious and were left out of the snapshot; "
                  "run `agentdetox agent scan` to review them")
        return 0
    command = hook_command(args.agent_name)
    if args.agent_name == "cursor":
        print(f"# Experimental. Add to {target} (merge with existing hooks):")
        print(json.dumps(cursor_hooks(command), indent=2))
    else:
        print(f"# Experimental. Register this command for Codex's SessionStart, PreToolUse "
              f"(matcher apply_patch|shell) and PostToolUse hooks in {target}:\n{command}")
    if args.apply:
        print("\n--apply is only supported for claude-code until these hook formats are verified on real installs.",
              file=sys.stderr)
        return 2
    return 0


def _daemon_command(action: str) -> int:
    info = daemon.ping()
    if action == "stop":
        if info is None:
            print("not running")
            return 0
        stopped = daemon.stop()
        print(f"stopped (pid {info['pid']})" if stopped else f"pid {info['pid']} did not stop within 10 s")
        return 0 if stopped else 1
    if info is None:
        print("not running; it starts on the next memory write that has something to compare")
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
            path = path.expanduser().absolute()
            try:
                moved = restore(path)
            except KeyError as e:
                print(f"error: {e.args[0]}", file=sys.stderr)
                return 2
            print(f"restored {path}" + (f" (previous version quarantined at {moved})" if moved else ""))
        return 0

    project = None if args.user_only else args.project.expanduser().absolute()
    files = discover(args.agent, project)
    roots = [home_dir()] + ([project] if project else [])

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
            print(f"left out {len(flagged)} file(s) with high-severity findings; review them with "
                  "`agentdetox agent scan`, or `agentdetox allow <id>` if they are fine:")
            for path in sorted(flagged):
                print(f"  {path}")
        return 0

    if args.agent_command == "scan":
        found = scan_context(files)
        if args.consistency:
            nli = NLI()
            if not nli.available():
                print("contradiction check skipped: install 'agentdetox[nli]' and run `agentdetox fetch-models`",
                      file=sys.stderr)
            else:
                found += consistency_findings(files, project, nli)
        findings = allowlist.unsuppressed(found)
        header = f"agentdetox {__version__}: scanned {len(files)} context file(s)"
        _print_findings(findings, header, args.format, len(found) - len(findings),
                        extra={"files": [str(f.path) for f in files]})
    else:
        changes, found = verify(files, roots)
        findings = allowlist.unsuppressed(found)
        header = f"agentdetox {__version__}: {len(changes)} context file(s) changed since snapshot"
        for c in changes:
            header += f"\n  {c.status:<8} {c.kind:<12} {c.path}"
        _print_findings(findings, header, args.format, len(found) - len(findings),
                        extra={"changes": [{"path": c.path, "status": c.status, "kind": c.kind} for c in changes]})
    if args.fail_on != "none" and any(at_least(f.severity, args.fail_on) for f in findings):
        return 1
    return 0


def _print_findings(findings, header: str, fmt: str, allowed: int, extra: dict) -> None:
    findings = sorted(findings, key=lambda f: (-SEVERITY_ORDER[f.severity], f.doc_id))
    if fmt == "json":
        json.dump({"version": __version__, **extra, "allowed": allowed, "findings": [f.to_dict() for f in findings]},
                  sys.stdout, ensure_ascii=False, indent=2)
        print()
        return
    print(header + "\n")
    for f in findings:
        print(f"{f.severity.upper():<6} {f.detector:<17} {f.source}  [{finding_id(f)}]")
        print(f"       {f.message}")
        if f.evidence:
            print(f"       > {' '.join(f.evidence.split())[:160]}")
    counts = Counter(f.severity for f in findings)
    print(f"\n{counts['high']} high, {counts['medium']} medium, {counts['low']} low"
          + (f"; {allowed} allowed and not shown (`agentdetox allow --list`)" if allowed else ""))
    if findings:
        print("False positive? `agentdetox allow <id>` stops it being reported.")


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
        print(f"       {f.message}")
        if f.evidence:
            print(f"       > {' '.join(f.evidence.split())[:160]}")
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


if __name__ == "__main__":
    sys.exit(main())
