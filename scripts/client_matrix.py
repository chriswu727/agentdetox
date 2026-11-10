"""Walk the shared client corpus (tests/client_corpus.py) and print what held.

Every layout of every client is played through every content case in a throwaway home,
project and store, in this process, without an agent, a hook or a model. The output is a
report of offline file disinfection only: it says nothing about a client delivering hook
events. Hook event shapes are listed with where each comes from.

    python scripts/client_matrix.py            a Markdown report
    python scripts/client_matrix.py --json     the same as data
"""

from __future__ import annotations

import argparse
import io
import json
import os
import sys
import tempfile
from contextlib import redirect_stderr, redirect_stdout
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / 'tests'))

import client_corpus as corpus  # noqa: E402

_MOVED = ('CODEX_HOME', 'CLAUDE_CONFIG_DIR', 'CLAUDE_CODE_PROJECT_DIR_NAME', 'CLAUDE_PROJECT_DIR', 'CURSOR_CONFIG_DIR',
          'CURSOR_PROJECT_DIR', 'XDG_CONFIG_HOME', 'OPENCLAW_HOME', 'OPENCLAW_PROFILE', 'OPENCLAW_STATE_DIR',
          'OPENCLAW_CONFIG_PATH', 'OPENCLAW_WORKSPACE_DIR')


def cli(args: list[str]) -> tuple[int, str, str]:
    from agentdetox.cli import main

    out, err = io.StringIO(), io.StringIO()
    with redirect_stdout(out), redirect_stderr(err):
        try:
            code = main(args)
        except SystemExit as stop:
            code = stop.code if isinstance(stop.code, int) else 2
    return code, out.getvalue(), err.getvalue()


def run() -> dict:
    from agentdetox import __version__
    from agentdetox.agentscan import scan_text

    saved = dict(os.environ)
    walks = []
    try:
        for layout in corpus.LAYOUTS:
            for case in corpus.CASES:
                if layout.kind not in case.kinds:
                    continue
                with tempfile.TemporaryDirectory(prefix='agentdetox-clients-') as directory:
                    base = Path(directory).resolve()
                    roots = corpus.Roots(base / 'home', base / 'project', base / 'elsewhere')
                    os.environ.clear()
                    os.environ.update({k: v for k, v in saved.items() if k not in _MOVED and not k.startswith('AGENTDETOX_')})
                    os.environ.update(AGENTDETOX_USER_HOME=str(roots.home), AGENTDETOX_HOME=str(base / 'store'),
                                      AGENTDETOX_NLI='0')
                    target, moved = corpus.place(layout, roots)
                    os.environ.update(moved)
                    row = {'layout': layout.name, 'agent': layout.agent, 'variant': layout.variant, 'kind': layout.kind,
                           'case': case.name, 'source': layout.source}
                    try:
                        steps = corpus.walk(layout, case, roots, cli, target)
                        row.update(passed=True, steps=steps, refused=corpus.REFUSED in steps)
                    except corpus.Unexpected as error:
                        row.update(passed=False, refused=False, error=str(error).replace(str(base), '<tmp>'))
                    walks.append(row)
    finally:
        os.environ.clear()
        os.environ.update(saved)

    def flagged(text: str, kind: str, severities: tuple[str, ...]) -> bool:
        return any(f.severity in severities for f in scan_text('notes.md', 'notes.md', text + '\n', kind))

    return {
        'version': __version__,
        'scope': 'offline file disinfection through the command line; no agent, hook delivery or model involved',
        'walks': walks,
        'events': [{'name': e.name, 'registered_for': e.agent, 'evidence': e.evidence, 'reply': e.reply} for e in corpus.EVENTS],
        'known_misses': [{'what': what, 'text': text, 'still_missed': not flagged(text, 'memory', ('medium', 'high'))}
                         for what, text in corpus.MISSES],
        'known_false_alarms': [{'what': what, 'kind': kind, 'text': text, 'still_flagged': flagged(text, kind, ('high',))}
                               for what, kind, text in corpus.FALSE_ALARMS],
        'corrected': [{'what': what, 'text': text, 'was': 'miss',
                       'holds': all(flagged(text, kind, ('high',)) for kind in ('memory', 'instructions', 'skill'))}
                      for what, text in corpus.MUST_FLAG]
        + [{'what': what, 'text': text, 'was': f'false alarm ({kind})',
            'holds': not any(flagged(text, each, ('medium', 'high')) for each in ('memory', 'instructions', 'skill'))}
           for what, kind, text in corpus.MUST_PASS],
    }


def render(report: dict) -> str:
    cases = list(dict.fromkeys(row['case'] for row in report['walks']))
    lines = [f"# Client file-disinfection matrix (agentdetox {report['version']})", '', f"Scope: {report['scope']}.", '',
             '| Layout | Kind | ' + ' | '.join(str(i + 1) for i in range(len(cases))) + ' |',
             '|---|---|' + '---|' * len(cases)]
    by = {(row['layout'], row['case']): row for row in report['walks']}
    for layout in dict.fromkeys(row['layout'] for row in report['walks']):
        first = next(row for row in report['walks'] if row['layout'] == layout)
        cells = [('refused' if by[layout, c]['refused'] else 'pass' if by[layout, c]['passed'] else 'FAIL')
                 if (layout, c) in by else 'n/a' for c in cases]
        lines.append(f"| {layout} ({first['variant']}) | {first['kind']} | " + ' | '.join(cells) + ' |')
    lines += ['', 'Cases: ' + '; '.join(f'{i + 1} {name}' for i, name in enumerate(cases)) + '.',
              'n/a: the case is about prose and the layout is a skill file.', '']
    failed = [row for row in report['walks'] if not row['passed']]
    refused = [row for row in report['walks'] if row['refused']]
    lines += [f"{len(report['walks']) - len(failed) - len(refused)} of {len(report['walks'])} walks passed."]
    if refused:
        lines.append(f"{len(refused)} ended with the cleanup refused as unsupported on this system and the file "
                     'unchanged: nothing was cleaned in those.')
    lines += [f"- FAIL {row['layout']} / {row['case']}: {row['error']}" for row in failed]
    lines += ['', '## Hook event shapes and where each comes from', '', '| Event | Registered for | Reply | Evidence |',
              '|---|---|---|---|']
    lines += [f"| {e['name']} | {e['registered_for']} | {e['reply']} | {e['evidence']} |" for e in report['events']]
    lines += ['', '## Known misses of the rules (hostile text that is not flagged)', '']
    lines += [f"- {m['what']}: \"{m['text']}\"" + ('' if m['still_missed'] else ' (now flagged)') for m in report['known_misses']]
    lines += ['', '## Known false alarms of the rules (benign text flagged as clear-cut)', '']
    lines += [f"- {a['what']} ({a['kind']}): \"{a['text']}\"".replace('\n', '\\n') + ('' if a['still_flagged'] else ' (no longer flagged)')
              for a in report['known_false_alarms']]
    lines += ['', '## Corrected, and required since', '']
    lines += [f"- {c['what']} (was a {c['was']}): \"{c['text']}\"" + ('' if c['holds'] else ' (NO LONGER HOLDS)')
              for c in report['corrected']]
    return '\n'.join(lines) + '\n'


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    parser.add_argument('--json', action='store_true')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args()
    report = run()
    text = json.dumps(report, indent=2, ensure_ascii=False) + '\n' if args.json else render(report)
    if args.output:
        args.output.write_text(text, encoding='utf-8')
    else:
        sys.stdout.write(text)
    return 0 if all(row['passed'] for row in report['walks']) and all(c['holds'] for c in report['corrected']) else 1


if __name__ == '__main__':
    raise SystemExit(main())
