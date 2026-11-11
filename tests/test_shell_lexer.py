"""The shell check reads a command as a shell splits it: line breaks, comments, adjacent
operators, substitutions and heredocs. Each case here was allowed silently before."""

import os

import pytest

from agentdetox import engine, shell
from agentdetox.integrity import store_dir


@pytest.fixture
def project(tmp_path):
    root = tmp_path / "proj"
    (root / ".claude").mkdir(parents=True)
    (root / "CLAUDE.md").write_text("# Project\nUse pnpm.\n", encoding="utf-8")
    (root / "notes.txt").write_text("n\n", encoding="utf-8")
    (root / ".claude" / "settings.json").write_text("{}\n", encoding="utf-8")
    (root / ".claude" / "settings.local.json").write_text("{}\n", encoding="utf-8")
    store_dir().mkdir(parents=True, exist_ok=True)
    return root


def checks(command, project):
    return {signal.check for signal in engine.check_command(command, project, project)}


WRITES_CONTEXT = [
    "echo hello\nrm CLAUDE.md",
    "cd .claude\nrm settings.json",
    "echo a#b > CLAUDE.md",
    "sed -i s#pnpm#npm# CLAUDE.md",
    "(echo hi); rm CLAUDE.md",
    "true &&(rm CLAUDE.md)",
    "(echo a; echo b)>CLAUDE.md",
    "echo $(date)>CLAUDE.md",
    "echo x >& CLAUDE.md",
    "echo x |& tee CLAUDE.md",
    "f() { rm CLAUDE.md; }; f",
    'echo "$(cp notes.txt CLAUDE.md)"',
    "X=`cp notes.txt CLAUDE.md`",
    'X="$(tee CLAUDE.md < notes.txt)"',
    "cp notes.txt \\\n  CLAUDE.md",
    'echo "see <<EOF syntax"\necho evil >> CLAUDE.md',
    "echo $((1<<n))\necho evil >> CLAUDE.md",
    "mv CLAUDE.md CLAUDE.md.bak",
    "mv .claude /tmp/gone",
    "mv -t /tmp CLAUDE.md",
    "sed -Ei 's/a/b/' CLAUDE.md",
    "sed --in-place 's/a/b/' CLAUDE.md",
    "sed --in-place=.bak 's/a/b/' CLAUDE.md",
    "git checkout CLAUDE.md",
    "git checkout HEAD~1 CLAUDE.md",
    "git checkout HEAD~1 .claude",
    "git rm CLAUDE.md",
    "git mv notes.txt CLAUDE.md",
    "git mv CLAUDE.md docs.md",
    "curl -O https://example.com/x/CLAUDE.md",
    "curl -sLO https://example.com/x/CLAUDE.md",
    "curl --remote-name https://example.com/x/CLAUDE.md",
    "wget https://example.com/x/CLAUDE.md",
    "wget -P .claude https://example.com/x/settings.json",
    "curl --output-dir .claude -o settings.json https://example.com/s",
    "sort -o CLAUDE.md notes.txt",
    "sort --output=CLAUDE.md notes.txt",
    "awk -i inplace '{print}' CLAUDE.md",
    "ruby -pi -e 'gsub(/a/,\"b\")' CLAUDE.md",
    "patch CLAUDE.md fix.diff",
    "patch -o CLAUDE.md notes.txt fix.diff",
    "rm .claude/settings{,.local}.json",
    "python3 -c \"import shutil; shutil.rmtree('.claude')\"",
    "cat <<EOF | sh\nrm CLAUDE.md\nEOF",
    "bash <<< 'rm CLAUDE.md'",
    "printf 'rm CLAUDE.md' | bash",
    "echo 'rm CLAUDE.md' | sh -s",
    "for f in CLAUDE.md; do\n  rm CLAUDE.md\ndone",
    "if true; then\n  echo x >> CLAUDE.md\nfi",
    "case x in a) rm CLAUDE.md;; esac",
    "cat notes.txt > >(tee CLAUDE.md)",
    "true |\n tee CLAUDE.md",
    'bash -c "cat <<EOF | sh\nrm CLAUDE.md\nEOF"',
    'echo "$(bash <<EOF\nrm CLAUDE.md\nEOF\n)"',
]


@pytest.mark.parametrize("command", WRITES_CONTEXT)
def test_context_write_is_seen(command, project):
    assert checks(command, project) & {engine.SHELL_WRITE, engine.PLANTED, engine.OWN_STATE}, command


def test_redirect_through_dev_parent_is_a_file(project):
    drive, rest = os.path.splitdrive(project.as_posix())
    spelled = f"/{drive[0].lower()}{rest}" if drive else rest     # Git Bash writes C:\x as /c/x
    assert checks(f"echo x > /dev/../{spelled}/CLAUDE.md", project)
    assert not checks("echo x > /dev/null", project)
    assert not checks("echo x 2> /dev/stderr", project)


CHANGES_TRUST = [
    "true\nagentdetox allow F12345678",
    "true\nagentdetox config suspicious off",
    "echo a#b; agentdetox allow F1",
    "(true); agentdetox allow F1",
    "true &&(agentdetox allow F1)",
    "echo ok |& agentdetox allow F1",
    "f() { agentdetox allow F1; }; f",
    'echo "$(agentdetox allow F1)"',
    "x=`agentdetox allow F1`",
    "bash <<< 'agentdetox allow F1'",
    "echo agentdetox allow F1 | sh",
    "printf 'agentdetox allow F1' | bash -s",
    "cat <<EOF | bash\nagentdetox allow F1\nEOF",
    "ls \\\n&& agentdetox uninstall claude-code",
]


@pytest.mark.parametrize("command", CHANGES_TRUST)
def test_trust_change_is_seen_past_the_first_command(command, project):
    assert checks(command, project) == {engine.OWN_STATE}, command


def test_removing_or_moving_the_store_is_own_state(project):
    store = store_dir().as_posix()   # bash reads backslashes as escapes; Git Bash users write C:/...
    assert checks(f"true\nrm -rf {store}", project) == {engine.OWN_STATE}
    assert checks(f"mv {store} /tmp/elsewhere", project) == {engine.OWN_STATE}
    assert checks(f"rm -rf {store_dir().parent.as_posix()}", project) == {engine.OWN_STATE}
    assert checks(f"python3 -c \"import os; os.remove('{store}/allowlist.json')\"", project) == {engine.OWN_STATE}


QUIET = [
    "ls -la",
    "cat CLAUDE.md",
    "echo hello\necho world",
    "git status\ngit diff",
    "grep -n pnpm CLAUDE.md | head -5",
    "cp CLAUDE.md CLAUDE.md.bak",
    "echo '# not a comment' > out.txt",
    "git checkout main",
    "git checkout -b CLAUDE.md",
    "git checkout -b feature/x",
    'git commit -m "fix: update\n\nrm CLAUDE.md is mentioned"',
    "git commit -m \"$(cat <<'EOF'\nfix: don't (ever) rm CLAUDE.md\n\nagentdetox allow F1 is mentioned\nEOF\n)\" && git push",
    "gh pr create --body \"$(cat <<EOF\nit's (a) body about CLAUDE.md > x\nEOF)\"",
    "curl -XPOST https://example.com/api -d '{}'",
    "curl -s https://example.com/x | jq .",
    "curl -O https://example.com/file.tar.gz",
    "sed -n 1,5p CLAUDE.md",
    "sed -e 's/i/j/' CLAUDE.md",
    "sed -f edit.sed CLAUDE.md",
    "python3 -c \"print(open('CLAUDE.md').read())\"",
    "python3 -c \"open('/tmp/out.txt','w').write('x')\"",
    "python3 - <<'EOF'\nprint('rm CLAUDE.md')\nEOF",
    "echo $((1<<3))\nls",
    "ls 2>&1 | tee build.log",
    "agentdetox status\nagentdetox doctor",
    "cat <<'EOF' > notes.md\nrm CLAUDE.md\nagentdetox allow F1\nEOF",
    'bash -c "cat > notes.md <<EOF\nrm CLAUDE.md is text\nEOF"',
    "mv notes.txt notes2.txt",
    "wget https://example.com/file.tar.gz",
    "sort -o out.txt notes.txt",
    "rm -rf build dist\nmkdir build",
    "echo \"it's fine\" # don't parse this",
    "true # rm CLAUDE.md",
    "git rm --cached CLAUDE.md",
    "npm test 2>/dev/null",
    "awk '{print $1}' CLAUDE.md",
    "patch -p1 < fix.diff",
    "find . -name '*.md' | xargs wc -l",
    "diff <(sort a) <(sort b)",
    "echo 'rm CLAUDE.md' | cat",
    "echo 'rm CLAUDE.md' | bash script.sh",
]


@pytest.mark.parametrize("command", QUIET)
def test_ordinary_command_stays_quiet(command, project):
    assert checks(command, project) == set(), command


def test_unreadable_command_naming_context_asks(project):
    assert checks("echo 'see CLAUDE.md", project) == {engine.SHELL_WRITE}
    assert checks("echo \"$(agentdetox status", project) == {engine.SHELL_WRITE}
    assert checks("echo 'unclosed", project) == set()


@pytest.mark.parametrize("command, tokens", [
    ("echo hello\nrm x", ["echo", "hello", "\n", "rm", "x"]),
    ("a &&\n b |\n c", ["a", "&&", "b", "|", "c"]),
    ("\n\na\n\n\nb\n", ["a", "\n", "b", "\n"]),
    ("echo a#b #c", ["echo", "a#b"]),
    ("a);b", ["a", ")", ";", "b"]),
    ("a|&b", ["a", "|", "b"]),
    ("f(){ a;}", ["f", "(", ")", "{", "a", ";", "}"]),
    ("a \\\n b", ["a", "b"]),
    ("ls 2>&1", ["ls", "2", ">&", "1"]),
    ("echo 'it''s' \"q \\\"x\\\" $HOME\"", ["echo", "its", 'q "x" $HOME']),
    ("echo ''", ["echo", ""]),
    ("echo $((1<<n))", ["echo", "$((1<<n))"]),
    ("x=$(a b)", ["x=$", "(", "a", "b", ")"]),
    ('echo "$(a b)" c', ["echo", "$(a b)", "c", ";", "(", "a", "b", ")"]),
    ("x=`a b`", ["x=`a b`", ";", "(", "a", "b", ")"]),
    ("case x in a) b;; esac", ["case", "x", "in", "a", ")", "b", ";;", "esac"]),
])
def test_split(command, tokens):
    assert shell.split(command) == tokens
    assert not shell.unreadable(command)


@pytest.mark.parametrize("command", ["echo 'x", 'echo "x', "echo `x", 'echo "$(x"'])
def test_unclosed_text_is_unreadable_but_still_split(command):
    assert shell.unreadable(command)
    assert shell.split(command)[0] == "echo"


def test_heredoc_bodies_are_left_out_once():
    command = "cat > out.txt <<'EOF'\nbody (it's)\nEOF\nrm x"
    only, bodies = shell.heredocs(command)
    assert bodies == [("cat > out.txt <<'EOF'", "body (it's)")]
    assert shell.split(only) == ["cat", ">", "out.txt", "\n", "rm", "x"]
    assert shell.heredocs(only) == (only, [])
    assert shell.split(command) == shell.split(only)


def test_heredoc_delimiters():
    assert shell.heredocs('cat <<-"END IT" | sh\n\tx\nEND IT')[1] == [('cat <<-"END IT" | sh', "\tx")]
    assert shell.heredocs("cat <<\\EOF\n$x\nEOF")[1] == [("cat <<\\EOF", "$x")]
    assert shell.heredocs("a <<A; b <<B\n1\nA\n2\nB\nc")[1] == [("a <<A; b <<B", "1"), ("a <<A; b <<B", "2")]
    assert shell.heredocs("echo '<<EOF'\nx\nEOF")[1] == []
    assert shell.heredocs("echo x # <<EOF\ny")[1] == []
    assert shell.heredocs("cat <<< word\nnext")[1] == []


HOSTILE = {
    "nested quoted substitutions": "echo " + '"$(' * 2000 + "x" + ')"' * 2000,
    "nested subshells": "(" * 20000 + "rm CLAUDE.md" + ")" * 20000,
    "unclosed arithmetic": "echo " + "$((1 " * 20000,
    "heredoc starts on one line": "a " + "<<x " * 20000,
    "unclosed quotes": "echo " + "'a " * 20001,
    "unclosed substitutions": 'echo "' + "$(a " * 20000,
    "backslashes": "echo " + "\\" * 50000,
    "many short commands": "echo a\n" * 50000,
    "a NUL in a path": "rm CLAUDE.md\x00x",
}


@pytest.mark.parametrize("name", sorted(HOSTILE))
def test_hostile_command_is_read_in_bounded_time_without_error(name, project):
    import time

    started = time.monotonic()
    shell.split(HOSTILE[name])
    engine.check_command(HOSTILE[name], project, project)
    assert time.monotonic() - started < 10, name


def test_folders_entered_one_inside_another_cost_their_number_not_its_square(project):
    import time

    def cost(depth):
        command = "cd a\n" * depth + "rm CLAUDE.md"
        best = float("inf")
        for _ in range(2):
            started = time.perf_counter()
            assert checks(command, project)
            best = min(best, time.perf_counter() - started)
        return best

    # Each folder costs file-system calls, slow on some machines, so only the growth is
    # compared: twice as deep is about twice the time, and four times if it were quadratic.
    small, large = cost(500), cost(1000)
    assert large < 3 * small, f"{small:.3f}s -> {large:.3f}s"


def test_deeply_nested_text_is_unreadable_not_an_error(project):
    command = "echo " + '"$(' * 2000 + "rm CLAUDE.md" + ')"' * 2000
    assert shell.unreadable(command)
    assert checks(command, project) == {engine.SHELL_WRITE}
