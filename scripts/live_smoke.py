"""Live smoke run against the real repositories in foreman.toml, over stdio like an agent would.

Prints a compact transcript and the session's usage report. Read-only except for running approved checks.
"""

from __future__ import annotations

import asyncio
import json
import sys
from pathlib import Path

from mcp import Client
from mcp.client.stdio import StdioServerParameters

ROOT = Path(__file__).resolve().parents[1]


async def main() -> None:
    params = StdioServerParameters(command=sys.executable,
                                   args=["-m", "foreman", "--policy", str(ROOT / "foreman.toml"), "serve"])
    async with Client(params, read_timeout_seconds=900) as c:
        async def call(tool: str, **args):
            res = await c.call_tool(tool, args)
            text = res.content[0].text if res.content else ""
            data = None if res.is_error else json.loads(text)
            return res.is_error, text, data

        steps = [
            ("list_repos", {}),
            ("repo_status", {"repo": "fnad"}),
            ("search_code", {"repo": "fnad", "query": "func _process", "max_results": 5}),
            ("search_code", {"repo": "granite-rag", "query": "def retrieve"}),
            ("read_file", {"repo": "granite-rag", "path": ".env"}),
            ("read_file", {"repo": "street-gonzo", "path": "AGENTS.md", "start_line": 1, "end_line": 12}),
            ("run_check", {"repo": "granite-rag", "check": "test"}),
            ("run_check", {"repo": "granite-rag", "check": "lint"}),
            ("run_check", {"repo": "james-brandel", "check": "build"}),
            ("run_check", {"repo": "fnad", "check": "test"}),
            ("ci_runs", {"repo": "granite-rag", "limit": 3}),
            ("usage_report", {}),
        ]
        for tool, args in steps:
            err, text, data = await call(tool, **args)
            if err:
                print(f"- {tool} {json.dumps(args)} -> DENIED {text.split(': ', 1)[-1][:110]}")
                continue
            if tool == "list_repos":
                summary = ", ".join(f"{r['name']}({len(r['checks'])} checks)" for r in data["repos"])
            elif tool == "repo_status":
                summary = (f"branch={data['branch']} head={data['head']} changed={data['changed_files']} "
                           f"last='{data['recent_commits'][0]['subject'][:50]}'")
            elif tool == "search_code":
                summary = f"{data['count']} hits via {data['engine']}: " + ", ".join(
                    f"{h['path']}:{h['line']}" for h in data["results"][:3])
            elif tool == "read_file":
                summary = f"{data['path']} lines {data['start_line']}-{data['end_line']} of {data['total_lines']}"
            elif tool == "run_check":
                tail = (data["stdout_tail"].strip().splitlines() or [""])[-1][:80]
                summary = f"passed={data['passed']} exit={data['exit_code']} {data['duration_s']}s | {tail}"
            elif tool == "ci_runs":
                summary = "; ".join(f"{r['workflowName']} {r['conclusion']} ({r['headBranch']})" for r in data["runs"])
            else:
                summary = json.dumps({k: data[k] for k in ("calls", "errors", "redactions", "denials_by_code")})
                for name, t in data["tools"].items():
                    summary += f"\n    {name:<13} calls={t['calls']} p50={t['p50_ms']}ms p95={t['p95_ms']}ms"
            print(f"- {tool} {json.dumps(args)} -> {summary}")


if __name__ == "__main__":
    asyncio.run(main())
