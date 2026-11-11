"""Generated commands, run in a real shell in a throwaway folder: whether the context file
changed is compared with what the shell check said. Hand-picked cases only cover shapes
someone already thought of; this covers the ways those shapes combine."""

import os
import random
import shutil
import subprocess

import pytest

from agentdetox import engine

pytestmark = pytest.mark.skipif(os.name != "posix", reason="runs POSIX shells")

TARGET = "CLAUDE.md"
ORIGINAL = "# Project\nUse pnpm.\n"

# Commands that change the context file, and commands that must leave it alone.
WRITERS = [
    f"echo x > {TARGET}",
    f"echo x >> {TARGET}",
    f"printf 'x\\n' >| {TARGET}",
    f": > {TARGET}",
    f"cp notes.txt {TARGET}",
    f"cat notes.txt > {TARGET}",
    f"tee {TARGET} < notes.txt",
    f"tee -a {TARGET} < notes.txt >/dev/null",
    f"rm {TARGET}",
    f"rm -f ./{TARGET}",
    f"mv {TARGET} moved.md",
    f"sed -i.bak 's/pnpm/npm/' {TARGET}",
    f"echo x 1> {TARGET}",
    f"echo a#b > {TARGET}",
    f"dd if=notes.txt of={TARGET} 2>/dev/null",
]
READERS = [
    f"cat {TARGET}",
    f"grep -c pnpm {TARGET}",
    f"wc -l {TARGET}",
    f"echo {TARGET}",
    f"echo 'rm {TARGET}'",
    f'echo "echo x > {TARGET}"',
    "echo x > other.txt",
    f"cp {TARGET} copy.md",
    f"true # rm {TARGET}",
    f"ls {TARGET} 2>&1",
    f"sed -n 1p {TARGET}",
    f"test -f {TARGET}",
]

# Ways to run a command; `{}` is the command. Each keeps a writer a writer.
WRAPPERS = [
    "{}",
    "true; {}",
    "true && {}",
    "false || {}",
    "true\n{}",
    "true\n\n{}\n",
    "({})",
    "(true); {}",
    "true &&({})",
    "{{ {}; }}",
    "if true; then {}; fi",
    "if true; then\n  {}\nfi",
    "for i in 1; do {}; done",
    "for i in 1; do\n  {}\ndone",
    "while true; do {}; break; done",
    "f() {{ {}; }}; f",
    "f() {{\n  {}\n}}\nf",
    "echo pre#fix; {}",
    "echo start # a comment; not a command\n{}",
    "{} # trailing comment",
    "cd . && {}",
    "true |\n cat; {}",
    "case x in x) {};; esac",
    "true \\\n&& {}",
    "export A=1; {}",
    "command {}",
    "env {}",
    "time {}",
]
# Ways to run a command given as one word of text.
QUOTING = [
    'echo "$({})"',
    "x=`{}`",
    'x="$({})"; echo "$x"',
    "x=$({})",
    "bash -c {q}",
    "sh -c {q}",
    "eval {q}",
    "bash <<< {q}",
    "echo {q} | sh",
    "printf '%s' {q} | bash",
    "bash <<EOF\n{}\nEOF",
    "bash <<'EOF'\n{}\nEOF\ntrue",
    "cat <<EOF | sh\n{}\nEOF",
    'bash -c "$(cat <<\'EOF\'\n{}\nEOF\n)"',
]


def _quote(command: str) -> str:
    return "'" + command.replace("'", "'\\''") + "'"


def _cases() -> list[tuple[str, bool]]:
    rng = random.Random(20261110)
    atoms = [(c, True) for c in WRITERS] + [(c, False) for c in READERS]
    cases: dict[str, bool] = {}
    for command, writes in atoms:
        for wrapper in WRAPPERS:
            cases[wrapper.format(command)] = writes
    for command, writes in atoms:
        # Commands with their own redirection of stdin cannot also read a heredoc or a pipe.
        if "<" in command:
            continue
        for form in QUOTING:
            text = form.replace("{q}", _quote(command)) if "{q}" in form else form.format(command)
            cases[text] = writes
    for _ in range(250):
        (first, w1), (second, w2) = rng.choice(atoms), rng.choice(atoms)
        if w1 and w2:
            continue    # after one writer ran, the second may find nothing to change
        if "<" in first or "<" in second:
            continue
        joined = rng.choice(["{}; {}", "{}\n{}", "{} && {}", "{} |& cat; {}", "({}); {}", "{}\n\n{}"]).format(first, second)
        outer = rng.choice(WRAPPERS + [q for q in QUOTING if "{q}" not in q and "EOF" not in q])
        cases[outer.format(joined)] = w1 or w2
    return sorted(cases.items())


def _changed(shell_path: str, command: str, folder) -> bool:
    if folder.exists():
        shutil.rmtree(folder)
    folder.mkdir()
    (folder / TARGET).write_text(ORIGINAL, encoding="utf-8")
    (folder / "notes.txt").write_text("notes\n", encoding="utf-8")
    env = {"PATH": os.environ.get("PATH", "/usr/bin:/bin"), "HOME": str(folder)}
    subprocess.run([shell_path, "-c", command], cwd=folder, env=env, capture_output=True, timeout=20,
                   stdin=subprocess.DEVNULL)
    target = folder / TARGET
    return not target.is_file() or target.read_text(encoding="utf-8") != ORIGINAL


@pytest.mark.parametrize("name", ["bash", "zsh"])
def test_verdict_matches_what_a_real_shell_does(name, tmp_path):
    shell_path = shutil.which(name)
    if not shell_path:
        pytest.skip(f"{name} is not installed")
    project = tmp_path / "judged"
    project.mkdir()
    (project / TARGET).write_text(ORIGINAL, encoding="utf-8")
    (project / "notes.txt").write_text("notes\n", encoding="utf-8")
    cases = _cases()
    missed, noisy, unsupported = [], [], 0
    for command, expected in cases:
        if "|&" in command and name == "bash" and _bash_major(shell_path) < 4:
            continue
        changed = _changed(shell_path, command, tmp_path / "run")
        if changed != expected:
            unsupported += 1    # this shell does not run the form as written; nothing to compare
            continue
        flagged = bool(engine.check_command(command, project, project))
        if changed and not flagged:
            missed.append(command)
        elif flagged and not changed:
            noisy.append(command)
    assert not missed, f"{len(missed)} commands changed {TARGET} unseen, e.g. {missed[:5]!r}"
    assert not noisy, f"{len(noisy)} commands were flagged without changing {TARGET}, e.g. {noisy[:5]!r}"
    assert unsupported < len(cases) / 10, f"{unsupported} of {len(cases)} generated forms did not run in {name}"


def _bash_major(path: str) -> int:
    out = subprocess.run([path, "-c", "echo ${BASH_VERSINFO[0]}"], capture_output=True, text=True).stdout.strip()
    return int(out) if out.isdigit() else 0
