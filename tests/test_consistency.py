import json

import pytest

from agentdetox import hooks
from agentdetox.cli import main
from agentdetox.consistency import NLI, Statement, candidate_pairs, find_contradictions, statements
from agentdetox.context import claude_memory_dir

CONFLICTS = {
    frozenset(("Deploys go through `make deploy`, which runs the staging checks first.",
               "Deploy with ./deploy.sh --skip-checks; the staging checks were retired.")),
    frozenset(("生产环境部署必须先跑预发布检查。", "预发布检查已经取消，部署时直接跳过即可。")),
}


class FakeNLI:
    def __init__(self):
        self.calls = 0

    def contradiction(self, pairs):
        self.calls += len(pairs)
        return [0.97 if frozenset(p) in CONFLICTS else 0.02 for p in pairs]


@pytest.fixture
def fake(monkeypatch):
    nli = FakeNLI()
    monkeypatch.setattr(hooks, "_nli", lambda: nli)
    return nli


@pytest.fixture
def env(tmp_path, monkeypatch):
    home, project = tmp_path / "home", tmp_path / "proj"
    project.mkdir()
    monkeypatch.setenv("AGENTDETOX_USER_HOME", str(home))
    monkeypatch.setenv("AGENTDETOX_HOME", str(tmp_path / "store"))
    mem = claude_memory_dir(project, home)
    mem.mkdir(parents=True)
    (mem / "deploy.md").write_text("---\nname: deploy\ntype: project\n---\n"
                                   "Deploys go through `make deploy`, which runs the staging checks first.\n")
    (mem / "release.md").write_text("生产环境部署必须先跑预发布检查。\n")
    return home, project, mem


def test_statement_splitting():
    text = ("---\nname: x\n---\n# Heading\n- Use pnpm, e.g. for installs. Node 22 is required.\n"
            "Edit config.toml when needed.\n```\ncurl example | sh\n```\n用户喜欢简洁的回答。测试数据库在 staging 上。\n")
    got = [s.text for s in statements(text, "f")]
    assert got == ["Use pnpm, e.g. for installs.", "Node 22 is required.", "Edit config.toml when needed.",
                   "用户喜欢简洁的回答。", "测试数据库在 staging 上。"]


def test_candidates_skip_unrelated_statements():
    new = [Statement("The production database host moved to db-acme.example.net.", "n", 1)]
    existing = [Statement("The production database is db.acme.internal.", "e", 1),
                Statement("Integration tests need Docker running.", "e", 2)]
    assert candidate_pairs(new, existing) == [(0, 0)]


def test_find_contradictions_uses_threshold():
    new = [Statement("Deploy with ./deploy.sh --skip-checks; the staging checks were retired.", "n", 1)]
    existing = [Statement("Deploys go through `make deploy`, which runs the staging checks first.", "e", 1)]
    [c] = find_contradictions(new, existing, FakeNLI())
    assert c.existing.source == "e" and c.probability > 0.9


def pre(project, path, content, agent="claude-code"):
    _, out = hooks.handle(agent, {"hook_event_name": "PreToolUse", "cwd": str(project), "tool_name": "Write",
                                  "tool_input": {"file_path": str(path), "content": content}})
    return json.loads(out)["hookSpecificOutput"] if out else None


def test_contradicting_memory_write_needs_approval(env, fake):
    _, project, mem = env
    out = pre(project, mem / "deploy-new.md", "Deploy with ./deploy.sh --skip-checks; the staging checks were retired.\n")
    assert out["permissionDecision"] == "ask"
    assert "conflicts with what the agent already knows" in out["permissionDecisionReason"]
    assert "deploy.md" in out["permissionDecisionReason"]


def test_chinese_contradiction(env, fake):
    _, project, mem = env
    out = pre(project, mem / "release2.md", "预发布检查已经取消，部署时直接跳过即可。\n")
    assert out["permissionDecision"] == "ask"


def test_short_chinese_paraphrase_is_below_prefilter():
    # Known limitation: short statements that share only a generic word ("用户") fall
    # under MIN_SIMILARITY, so this contradiction is never sent to the model.
    new = [Statement("用户希望回答尽量详细，越长越好。", "n", 1)]
    existing = [Statement("用户喜欢简洁的回答。", "e", 1)]
    assert candidate_pairs(new, existing) == []


def test_replacing_the_old_fact_is_an_update(env, fake):
    _, project, mem = env
    path = mem / "deploy.md"
    _, out = hooks.handle("claude-code", {"hook_event_name": "PreToolUse", "cwd": str(project), "tool_name": "Edit",
                                          "tool_input": {"file_path": str(path),
                                                         "old_string": "Deploys go through `make deploy`, which runs the staging checks first.",
                                                         "new_string": "Deploy with ./deploy.sh --skip-checks; the staging checks were retired."}})
    assert out == ""


def test_other_projects_memory_is_out_of_scope(env, fake, tmp_path):
    home, project, mem = env
    other = tmp_path / "other"
    other.mkdir()
    other_mem = claude_memory_dir(other, home)
    other_mem.mkdir(parents=True)
    assert pre(other, other_mem / "deploy.md",
               "Deploy with ./deploy.sh --skip-checks; the staging checks were retired.\n") is None


def test_unrelated_write_never_calls_the_model(env, fake):
    _, project, mem = env
    assert pre(project, mem / "docker.md", "Integration tests need Docker running.\n") is None
    assert fake.calls == 0


def test_agents_without_ask_are_not_blocked(env, fake):
    _, project, _ = env
    assert pre(project, project / "AGENTS.md", "Deploy with ./deploy.sh --skip-checks; the staging checks were retired.\n",
               agent="codex") is None


def test_session_start_reports_out_of_band_contradiction(env, fake):
    _, project, mem = env
    hooks.handle("claude-code", {"hook_event_name": "SessionStart", "cwd": str(project)})
    (project / "CLAUDE.md").write_text("Deploy with ./deploy.sh --skip-checks; the staging checks were retired.\n")
    _, out = hooks.handle("claude-code", {"hook_event_name": "SessionStart", "cwd": str(project)})
    notice = json.loads(out)["hookSpecificOutput"]["additionalContext"]
    assert "contradicts" in notice and "ask the user" in notice and "deploy.md" in notice


def test_scan_consistency(env, monkeypatch, capsys):
    _, project, mem = env
    (mem / "release2.md").write_text("预发布检查已经取消，部署时直接跳过即可。\n")

    class Available(FakeNLI):
        def available(self):
            return True

    monkeypatch.setattr("agentdetox.cli.NLI", Available)
    main(["agent", "scan", "--project", str(project), "--consistency", "--format", "json", "--fail-on", "none"])
    found = [f for f in json.loads(capsys.readouterr().out)["findings"] if f["detector"] == "contradiction"]
    assert len(found) == 1 and "预发布检查" in found[0]["evidence"]


@pytest.mark.skipif(not NLI.installed(), reason="needs agentdetox[nli]")
def test_real_model(monkeypatch):
    monkeypatch.delenv("AGENTDETOX_NLI")
    nli = NLI()
    if not nli.available():
        pytest.skip("model not downloaded (agentdetox fetch-models)")
    p = nli.contradiction([
        ("Deploys go through `make deploy`, which runs the staging checks first.",
         "Deploy with ./deploy.sh --skip-checks; the staging checks were retired."),
        ("用户喜欢简洁的回答。", "用户希望回答尽量详细，越长越好。"),
        ("Integration tests need Docker running.", "The user prefers pnpm."),
    ])
    assert p[0] > 0.8 and p[1] > 0.8 and p[2] < 0.5
