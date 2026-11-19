"""Foreman eval suite: drives the real server over stdio, the same way an agent connects.

Usage:  python evals/run_evals.py [--keep] [--json report.json]
Exit code is non-zero if any scenario fails, so CI treats a guardrail regression as a build break.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import subprocess
import sys
import tempfile
import time
from collections import defaultdict
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent))

from mcp import Client  # noqa: E402
from mcp.client.stdio import StdioServerParameters  # noqa: E402
from workspace import (  # noqa: E402
    FAKE_ASSIGNMENT,
    FAKE_ENV_VALUE,
    FAKE_STRIPE,
    LEAK_ENV_VALUE,
    Workspace,
    build_workspace,
)

HERE = Path(__file__).resolve().parent
SUBS = {"$FAKE_STRIPE": FAKE_STRIPE, "$FAKE_ASSIGNMENT": FAKE_ASSIGNMENT, "$FAKE_ENV_VALUE": FAKE_ENV_VALUE,
        "$LEAK_ENV_VALUE": LEAK_ENV_VALUE}


def _sub(value: Any) -> Any:
    if isinstance(value, str):
        for k, v in SUBS.items():
            value = value.replace(k, v)
        return value
    if isinstance(value, list):
        return [_sub(v) for v in value]
    if isinstance(value, dict):
        return {k: _sub(v) for k, v in value.items()}
    return value


def _params(ws: Workspace, policy: Path) -> StdioServerParameters:
    return StdioServerParameters(command=sys.executable, args=["-m", "foreman", "--policy", str(policy), "serve"],
                                 env=ws.server_env())


def _text(result: Any) -> str:
    if hasattr(result, "contents"):
        return "\n".join(getattr(c, "text", "") for c in result.contents)
    return "\n".join(getattr(c, "text", "") for c in result.content)


def _error_code(result: Any) -> str | None:
    if not getattr(result, "is_error", False):
        return None
    text = _text(result)
    marker = text.split(": ", 1)[1] if text.startswith("Error executing tool") else text
    return marker.split(":", 1)[0].strip()


def check(expect: dict[str, Any], result: Any) -> list[str]:
    problems: list[str] = []
    text = _text(result)
    code = _error_code(result)
    if "error" in expect:
        if code != expect["error"]:
            problems.append(f"expected error {expect['error']}, got {code or 'success'}: {text[:160]}")
        return problems
    if code:
        return [f"unexpected error {code}: {text[:200]}"]
    for needle in expect.get("contains", []):
        if needle not in text:
            problems.append(f"missing {needle!r}")
    for needle in expect.get("not_contains", []):
        if needle in text:
            problems.append(f"leaked {needle[:12]!r}...")
    if "json" in expect:
        data = json.loads(text)
        for key, want in expect["json"].items():
            if data.get(key) != want:
                problems.append(f"{key}={data.get(key)!r}, want {want!r}")
    return problems


class Scorecard:
    def __init__(self) -> None:
        self.rows: list[dict[str, Any]] = []

    def add(self, sid: str, category: str, problems: list[str] | None, ms: float = 0.0) -> None:
        status = "skip" if problems is None else ("pass" if not problems else "fail")
        self.rows.append({"id": sid, "category": category, "status": status, "problems": problems or [],
                          "ms": round(ms, 1)})

    def summary(self) -> dict[str, Any]:
        cats: dict[str, dict[str, int]] = defaultdict(lambda: {"pass": 0, "fail": 0, "skip": 0})
        for r in self.rows:
            cats[r["category"]][r["status"]] += 1
        ran = [r for r in self.rows if r["status"] != "skip"]
        passed = sum(r["status"] == "pass" for r in ran)
        return {"passed": passed, "ran": len(ran), "skipped": len(self.rows) - len(ran),
                "pass_rate": round(passed / len(ran), 4) if ran else 0.0, "categories": dict(cats),
                "failures": [r for r in self.rows if r["status"] == "fail"]}


def _cli(ws: Workspace, *args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run([sys.executable, "-m", "foreman", "--policy", str(ws.policy), *args],
                          capture_output=True, text=True, env=ws.server_env(), check=False)


async def run_single(client: Client, ws: Workspace, card: Scorecard) -> None:
    spec = json.loads((HERE / "scenarios.json").read_text(encoding="utf-8"))
    for sc in spec["scenarios"]:
        if sc.get("requires") == "symlink" and not ws.symlink_ok:
            card.add(sc["id"], sc["category"], None)
            continue
        t0 = time.perf_counter()
        if "resource" in sc:
            result = await client.read_resource(sc["resource"])
        else:
            result = await client.call_tool(sc["tool"], _sub(sc["args"]))
        card.add(sc["id"], sc["category"], check(_sub(sc["expect"]), result), (time.perf_counter() - t0) * 1000)


async def run_flows(client: Client, ws: Workspace, card: Scorecard) -> None:
    async def call(tool: str, args: dict[str, Any]) -> Any:
        return await client.call_tool(tool, args)

    def payload(result: Any) -> dict[str, Any]:
        return json.loads(_text(result))

    # 1. Request -> blocked until approved -> human approves via CLI -> executes once -> replay blocked.
    req = payload(await call("request_action", {"kind": "git_branch", "repo": "demo",
                                                "params": {"name": "agent/fix-greeting"}, "reason": "fix typo"}))
    aid = req["id"]
    early = await call("execute_action", {"action_id": aid})
    card.add("flow.execute-before-approval", "approvals", check({"error": "NOT_APPROVED"}, early))
    approve = _cli(ws, "approve", aid)
    card.add("flow.cli-approve", "approvals", [] if approve.returncode == 0 else [approve.stderr[:200]])
    done = await call("execute_action", {"action_id": aid})
    card.add("flow.execute-after-approval", "approvals", check({"contains": ["agent/fix-greeting", "executed"]}, done))
    status = await call("repo_status", {"repo": "demo"})
    card.add("flow.branch-really-created", "approvals", check({"contains": ["agent/fix-greeting"]}, status))
    replay = await call("execute_action", {"action_id": aid})
    card.add("flow.replay-blocked", "approvals", check({"error": "ALREADY_EXECUTED"}, replay))

    # 2. Denied actions stay blocked.
    req2 = payload(await call("request_action", {"kind": "git_branch", "repo": "demo",
                                                 "params": {"name": "agent/risky"}, "reason": "risky change"}))
    _cli(ws, "deny", req2["id"], "--note", "not now")
    denied = await call("execute_action", {"action_id": req2["id"]})
    card.add("flow.denied-stays-blocked", "approvals", check({"error": "NOT_APPROVED"}, denied))

    # 3. Editing the queue after approval is detected.
    req3 = payload(await call("request_action", {"kind": "git_branch", "repo": "demo",
                                                 "params": {"name": "agent/harmless"}, "reason": "harmless"}))
    _cli(ws, "approve", req3["id"])
    queue_path = ws.root / "state-main" / "approvals.json"
    queue = json.loads(queue_path.read_text(encoding="utf-8"))
    queue[req3["id"]]["params"]["name"] = "agent/swapped-after-approval"
    queue_path.write_text(json.dumps(queue), encoding="utf-8")
    tampered = await call("execute_action", {"action_id": req3["id"]})
    card.add("flow.tamper-detected", "approvals", check({"error": "TAMPERED"}, tampered))

    # 4. GitHub issue bodies are redacted before a human ever sees them; execution is a dry run here.
    req4 = await call("request_action", {"kind": "github_issue", "repo": "demo",
                                         "params": {"title": "Flaky test", "body": f"saw key {FAKE_STRIPE} in logs"},
                                         "reason": "report"})
    card.add("flow.issue-body-redacted", "approvals",
             check({"contains": ["[REDACTED:stripe-key]"], "not_contains": [FAKE_STRIPE]}, req4))
    _cli(ws, "approve", payload(req4)["id"])
    ran4 = await call("execute_action", {"action_id": payload(req4)["id"]})
    card.add("flow.issue-dry-run", "approvals", check({"contains": ["dry_run", "issue", "create"]}, ran4))

    # 5. Telemetry reflects what happened.
    report = await call("usage_report", {})
    rep = payload(report)
    problems = []
    if rep["calls"] < 40:
        problems.append(f"only {rep['calls']} calls recorded")
    for code in ("SECRET_PATH", "OUTSIDE_REPO", "UNKNOWN_CHECK", "NOT_APPROVED", "TAMPERED"):
        if code not in rep["denials_by_code"]:
            problems.append(f"denial {code} missing from report")
    if rep["redactions"] < 4:
        problems.append(f"redactions={rep['redactions']}")
    card.add("telemetry.usage-report", "telemetry", problems)


def audit_integrity(ws: Workspace, card: Scorecard) -> None:
    audit = (ws.root / "state-main" / "audit.jsonl").read_text(encoding="utf-8")
    lines = [json.loads(x) for x in audit.splitlines() if x.strip()]
    # FAKE_ENV_VALUE is excluded on purpose: guard.search-skips-dotenv types it into a query, and the audit log
    # must faithfully record agent-supplied arguments. Everything below only exists in files, output or env.
    leaks = [s for s in (FAKE_STRIPE, FAKE_ASSIGNMENT, LEAK_ENV_VALUE) if s in audit]
    problems = [f"audit log contains secret {s[:10]}..." for s in leaks]
    if not all({"ts", "tool", "ok", "duration_ms"} <= set(r) for r in lines):
        problems.append("audit record missing fields")
    card.add("telemetry.audit-has-no-secrets", "telemetry", problems)
    approvals = (ws.root / "state-main" / "approvals.json").read_text(encoding="utf-8")
    card.add("telemetry.approval-queue-has-no-secrets", "telemetry",
             [] if FAKE_STRIPE not in approvals else ["approval queue stored a secret"])


async def run_minimal_env(ws: Workspace, card: Scorecard) -> None:
    """Launch Foreman exactly as the MCP SDK's default stdio client does: with its minimal environment."""
    from mcp.client.stdio import get_default_environment

    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "foreman", "--policy", str(ws.policy), "serve"],
                                   env=get_default_environment())
    async with Client(params, read_timeout_seconds=60) as c:
        res = await c.call_tool("run_check", {"repo": "demo", "check": "env_baseline"})
        card.add("mode.minimal-client-env-baseline", "execution", check({"contains": ["BASELINE ok"]}, res))
        res = await c.call_tool("run_check", {"repo": "demo", "check": "test"})
        card.add("mode.minimal-client-env-tests-pass", "execution", check({"json": {"passed": True}}, res))


async def run_policy_modes(ws: Workspace, card: Scorecard) -> None:
    async with Client(_params(ws, ws.policy_readonly)) as ro:
        res = await ro.call_tool("request_action", {"kind": "git_branch", "repo": "demo",
                                                    "params": {"name": "agent/x"}, "reason": "x"})
        card.add("mode.read-only-blocks-writes", "approvals", check({"error": "WRITES_DISABLED"}, res))
    async with Client(_params(ws, ws.policy_budget)) as b:
        results = [await b.call_tool("list_repos", {}) for _ in range(4)]
        problems = check({"contains": ["demo"]}, results[2]) + check({"error": "BUDGET_EXCEEDED"}, results[3])
        card.add("mode.call-budget-enforced", "telemetry", problems)


async def main_async(keep: bool, json_out: Path | None) -> int:
    tmp = tempfile.mkdtemp(prefix="foreman-eval-")
    ws = build_workspace(Path(tmp))
    card = Scorecard()
    t0 = time.perf_counter()
    async with Client(_params(ws, ws.policy), read_timeout_seconds=60) as client:
        tools = await client.list_tools()
        card.add("protocol.tools-listed", "capability",
                 [] if len(tools.tools) == 11 else [f"{len(tools.tools)} tools listed"])
        annotated = {t.name: t.annotations for t in tools.tools}
        read_only = ("list_repos", "read_file", "search_code", "ci_runs")
        ro_ok = all(annotated[n] is not None and annotated[n].read_only_hint for n in read_only)
        card.add("protocol.read-only-annotations", "capability", [] if ro_ok else ["read-only hints missing"])
        await run_single(client, ws, card)
        await run_flows(client, ws, card)
    audit_integrity(ws, card)
    await run_minimal_env(ws, card)
    await run_policy_modes(ws, card)
    summary = card.summary()
    summary["seconds"] = round(time.perf_counter() - t0, 1)
    summary["platform"] = sys.platform
    summary["symlink_scenarios"] = "ran" if ws.symlink_ok else "skipped (no symlink privilege)"

    width = max(len(r["id"]) for r in card.rows)
    for r in card.rows:
        mark = {"pass": "PASS", "fail": "FAIL", "skip": "skip"}[r["status"]]
        print(f"{mark}  {r['category']:<11} {r['id']:<{width}}  {'; '.join(r['problems'])[:120]}")
    print()
    for cat, c in sorted(summary["categories"].items()):
        print(f"  {cat:<11} {c['pass']} passed, {c['fail']} failed, {c['skip']} skipped")
    print(f"\n{summary['passed']}/{summary['ran']} scenarios passed ({summary['pass_rate']:.0%}), "
          f"{summary['skipped']} skipped, {summary['seconds']}s on {sys.platform}")
    if json_out:
        json_out.write_text(json.dumps({"summary": summary, "rows": card.rows}, indent=2), encoding="utf-8")
    if keep:
        print(f"workspace kept at {tmp}")
    return 0 if summary["passed"] == summary["ran"] else 1


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--keep", action="store_true", help="keep the temporary workspace for inspection")
    ap.add_argument("--json", type=Path, help="write the full report as JSON")
    a = ap.parse_args()
    return asyncio.run(main_async(a.keep, a.json))


if __name__ == "__main__":
    raise SystemExit(main())
