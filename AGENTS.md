# Foreman MCP server

Python 3.11+, MCP SDK 2.x (`mcp.server.mcpserver.MCPServer`). Security-sensitive: this server is the boundary
between a coding agent and real repositories.

## Commands
- Setup: `uv venv --python 3.12 .venv && uv pip install --python .venv/Scripts/python.exe -e ".[dev]"`
- Definition of done: `.venv/Scripts/ruff check .`, `.venv/Scripts/python.exe -m pytest -q`, and
  `.venv/Scripts/python.exe evals/run_evals.py` must all pass.
- Live smoke against local repos: `.venv/Scripts/python.exe scripts/live_smoke.py` (needs `foreman.toml`).

## Layout
- `foreman/policy.py` policy model; `guard.py` paths, redaction, env scrubbing; `service.py` tool logic;
  `approvals.py` human approval queue; `telemetry.py` audit/budget; `server.py` MCP wiring; `cli.py` CLI.
- `evals/` protocol-level guardrail scenarios; `tests/` unit tests.

## Hard rules
- Never weaken a guard to make a test pass. A failing eval is a finding: fix the code or, if the
  scenario itself is wrong, say so in the commit message.
- No shell=True, ever. Checks are fixed argv lists from policy.
- Every tool must go through `Foreman.call` (budget, redaction, audit).
- Never put a real-looking credential literal in source; build fake ones from fragments (see evals/workspace.py).
- New tool or guard = new eval scenario.
