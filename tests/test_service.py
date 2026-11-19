import asyncio
import json
from dataclasses import replace

import pytest
from workspace import FAKE_STRIPE

from foreman.errors import BUDGET_EXCEEDED, UNKNOWN_CHECK, GuardError
from foreman.policy import Limits, load_policy
from foreman.server import build_server
from foreman.service import Foreman, excluded
from foreman.telemetry import percentile, summarize


def test_percentiles():
    assert percentile([], 95) == 0.0
    assert percentile([1, 2, 3, 4, 100], 50) == 3
    assert percentile([1, 2, 3, 4, 100], 95) == 100


def test_every_call_is_audited_including_denials(foreman: Foreman):
    foreman.call("list_repos", {}, foreman.list_repos)
    with pytest.raises(GuardError):
        foreman.call("run_check", {"repo": "demo", "check": "nope"}, lambda: foreman.run_check("demo", "nope"))
    lines = (foreman.policy.state_dir / "audit.jsonl").read_text().splitlines()
    assert len(lines) == 2
    denied = json.loads(lines[1])
    assert denied["ok"] is False and denied["error_code"] == UNKNOWN_CHECK and denied["repo"] == "demo"
    report = foreman.usage_report()
    assert report["calls"] == 2 and report["denials_by_code"] == {UNKNOWN_CHECK: 1}


def test_budget(workspace, tmp_path):
    policy = replace(load_policy(workspace.policy), state_dir=tmp_path, limits=Limits(max_calls=2))
    fm = Foreman(policy)
    fm.call("list_repos", {}, fm.list_repos)
    fm.call("list_repos", {}, fm.list_repos)
    with pytest.raises(GuardError) as err:
        fm.call("list_repos", {}, fm.list_repos)
    assert err.value.code == BUDGET_EXCEEDED


def test_results_are_redacted_and_counted(foreman: Foreman):
    out = foreman.call("read_file", {"repo": "demo", "path": "src/settings.py"},
                       lambda: foreman.read_file("demo", "src/settings.py"))
    assert FAKE_STRIPE not in json.dumps(out)
    assert foreman.usage_report()["redactions"] >= 2


def test_summarize_groups_by_tool():
    recs = [{"tool": "a", "ok": True, "duration_ms": 5, "out_chars": 10},
            {"tool": "a", "ok": False, "error_code": "X", "duration_ms": 7, "out_chars": 0},
            {"tool": "b", "ok": True, "duration_ms": 1, "out_chars": 3}]
    s = summarize(recs)
    assert s["tools"]["a"]["calls"] == 2 and s["tools"]["a"]["errors"] == 1 and s["denials_by_code"] == {"X": 1}


def test_repo_status_and_search(foreman: Foreman):
    status = foreman.repo_status("demo")
    assert status["branch"] == "main" and status["recent_commits"][0]["subject"] == "initial fixture"
    hits = foreman.search_code("demo", "def greet")
    assert hits["count"] == 1 and hits["results"][0]["path"] == "src/greeter.py"


def test_python_search_fallback_matches_ripgrep(foreman: Foreman):
    foreman._rg = None
    hits = foreman.search_code("demo", "def greet")
    assert hits["engine"] == "python" and hits["results"][0]["path"] == "src/greeter.py"
    assert foreman.search_code("demo", "SECRET_THING")["count"] == 0  # lives only in .env


def test_mcp_in_process_round_trip(workspace, tmp_path):
    from mcp import Client

    policy = replace(load_policy(workspace.policy), state_dir=tmp_path)
    server, _ = build_server(policy)

    async def go():
        async with Client(server) as client:
            names = {t.name for t in (await client.list_tools()).tools}
            ok = await client.call_tool("run_check", {"repo": "demo", "check": "test"})
            bad = await client.call_tool("read_file", {"repo": "demo", "path": ".env"})
            return names, ok, bad

    names, ok, bad = asyncio.run(go())
    assert {"read_file", "run_check", "request_action", "execute_action", "usage_report"} <= names
    assert json.loads(ok.content[0].text)["passed"] is True
    assert bad.is_error and "SECRET_PATH" in bad.content[0].text


def test_excluded_globs():
    assert excluded("tmp/a/b.gd", ("tmp/**",)) and excluded("tmp", ("tmp/**",))
    assert not excluded("src/tmp.py", ("tmp/**",))
    assert excluded("Docs/shot.png", ("*.png",))


def test_search_deadline_returns_partial_results(workspace, tmp_path):
    policy = replace(load_policy(workspace.policy), state_dir=tmp_path, limits=Limits(search_timeout_s=0.0))
    fm = Foreman(policy)
    fm._rg = None
    out = fm.search_code("demo", "def greet")
    assert out["timed_out"] is True and "partial" in out["note"]


def test_ripgrep_and_python_engines_agree(foreman: Foreman):
    import shutil

    if not shutil.which("rg"):
        pytest.skip("ripgrep not installed")
    rg = foreman.search_code("demo", "greet")
    foreman._rg = None
    py = foreman.search_code("demo", "greet")
    key = lambda out: sorted((h["path"], h["line"]) for h in out["results"])  # noqa: E731
    assert key(rg) == key(py) and rg["engine"] == "ripgrep" and py["engine"] == "python"
