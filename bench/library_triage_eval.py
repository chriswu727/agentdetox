"""Run library scale contracts, then measure scoped triage on the same inventory."""

from __future__ import annotations

import time

from bench import library_eval


def triage(root) -> dict:
    from agentdetox import allowlist, library
    from agentdetox.integrity import store_dir

    before = library.status(root)[0]
    allowed = allowlist.entries()
    with library.connect() as db:
        targets = [f"M{r[0]}" for r in db.execute(
            "SELECT DISTINCT f.id FROM files f JOIN findings n ON n.file_id=f.id "
            "WHERE f.state='inspected' AND n.severity='high' ORDER BY f.id LIMIT 100")]
    timings = {}

    def timed(name, call):
        start, cpu = time.perf_counter(), time.process_time()
        result = call()
        timings[name] = {"seconds": time.perf_counter() - start, "cpu_seconds": time.process_time() - cpu}
        return result

    flags = {}

    def dismiss():
        for target in targets:
            detail = library.detail(target)
            flags[target] = [f["flag_id"] for f in detail["findings"]]
            library.dismiss(target, flags[target], expected_hash=detail["review_hash"], note="Synthetic triage measurement")

    timed("review_and_dismiss_100_files", dismiss)
    after = timed("status_with_dismissals", lambda: library.status(root)[0])
    page = timed("dismissed_page_20", lambda: library.page(root, "dismissed", page_size=20))
    timed("suspicious_page_20", lambda: library.page(root, page_size=20))
    detail = timed("review_one_dismissed_file", lambda: library.detail(targets[0]))

    def reopen():
        for target in targets:
            library.reopen(target, flags[target])

    timed("reopen_100_files", reopen)
    restored = library.status(root)[0]
    checks = {
        "only selected files leave the suspicious queue": after["suspicious"] == before["suspicious"] - len(targets),
        "dismissed files remain counted and reviewable": after["dismissed_files"] == len(targets)
        and page["total"] == len(targets) and len(page["rows"]) == min(20, len(targets))
        and detail["findings"] and all(f["dismissed"] for f in detail["findings"]),
        "dismissal does not create no-finding verdicts": after["no_findings"] == before["no_findings"],
        "reopen restores the suspicious queue": restored["suspicious"] == before["suspicious"]
        and restored["dismissed_findings"] == 0,
        "global allowlist and hook store are untouched": allowlist.entries() == allowed
        and not (store_dir() / "state.sqlite3").exists(),
    }
    return {"selected_files": len(targets), "scope": "after the six scan phases, in the same synthetic inventory",
            "timings": timings, "checks": checks, "passed": all(checks.values()),
            "exclusions": ["CLI startup", "real-world false positives", "concurrent triage latency"],
            "inventory_bytes_after_reopen": library.db_path().stat().st_size,
            "peak_rss_bytes": library_eval.peak_rss()}


def main() -> int:
    original = library_eval.run

    def measured(*args, **kwargs):
        result = original(*args, **kwargs)
        result["triage"] = triage(args[0])
        result["process_peak_rss_bytes"] = library_eval.peak_rss()
        result["passed"] = result["passed"] and result["triage"]["passed"]
        return result

    try:
        library_eval.run = measured
        return library_eval.main()
    finally:
        library_eval.run = original


if __name__ == "__main__":
    raise SystemExit(main())
