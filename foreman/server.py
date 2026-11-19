"""MCP wiring: exposes the Foreman service as MCP tools and resources."""

from __future__ import annotations

from typing import Any

from mcp.server.mcpserver import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from mcp_types import ToolAnnotations

from foreman import __version__
from foreman.errors import GuardError
from foreman.policy import Policy
from foreman.service import Foreman

INSTRUCTIONS = """\
Foreman gives you least-privilege access to the repositories listed by `list_repos`.
1. Before changing a repo, read its rules: resource foreman://repos/<name>/agents (AGENTS.md).
2. Explore with repo_status, list_files, search_code and read_file. Secret files are refused and
   credential-looking text is redacted.
3. Verify work with run_check. You can only run checks the policy approves, by name.
4. Writes (branches, GitHub issues) need a human: request_action, ask the user to run
   `foreman approve <id>`, then execute_action. Never retry a denied action under another name.
Errors start with a stable CODE (e.g. SECRET_PATH, UNKNOWN_CHECK, NOT_APPROVED). Treat them as final.
"""

READ = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
READ_REMOTE = ToolAnnotations(read_only_hint=True, destructive_hint=False, idempotent_hint=True, open_world_hint=True)
RUN = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=True, open_world_hint=False)
REQUEST = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=False)
EXECUTE = ToolAnnotations(read_only_hint=False, destructive_hint=False, idempotent_hint=False, open_world_hint=True)


def build_server(policy: Policy) -> tuple[MCPServer, Foreman]:
    fm = Foreman(policy)
    server = MCPServer("foreman", version=__version__, instructions=INSTRUCTIONS)

    def guarded(tool: str, args: dict[str, Any], fn) -> Any:
        try:
            return fm.call(tool, args, fn)
        except GuardError as err:
            raise ToolError(str(err)) from None

    @server.tool(annotations=READ)
    def list_repos() -> dict:
        """List the repositories this agent may access, their approved checks, and whether writes are enabled."""
        return guarded("list_repos", {}, fm.list_repos)

    @server.tool(annotations=READ)
    def repo_status(repo: str) -> dict:
        """Branch, HEAD, ahead/behind, uncommitted files, local branches and the last five commits."""
        return guarded("repo_status", {"repo": repo}, lambda: fm.repo_status(repo))

    @server.tool(annotations=READ)
    def list_files(repo: str, subdir: str = ".", pattern: str | None = None, limit: int = 300) -> dict:
        """List tracked and untracked (non-ignored) files, optionally under `subdir` or matching a glob."""
        args = {"repo": repo, "subdir": subdir, "pattern": pattern, "limit": limit}
        return guarded("list_files", args, lambda: fm.list_files(repo, subdir, pattern, limit))

    @server.tool(annotations=READ)
    def read_file(repo: str, path: str, start_line: int = 1, end_line: int | None = None) -> dict:
        """Read a text file (repo-relative path) with line numbers. Secret files are refused."""
        args = {"repo": repo, "path": path, "start_line": start_line, "end_line": end_line}
        return guarded("read_file", args, lambda: fm.read_file(repo, path, start_line, end_line))

    @server.tool(annotations=READ)
    def search_code(repo: str, query: str, glob: str | None = None, regex: bool = False,
                    max_results: int = 50) -> dict:
        """Search file contents (literal by default; set regex=true for a regular expression)."""
        args = {"repo": repo, "query": query, "glob": glob, "regex": regex, "max_results": max_results}
        return guarded("search_code", args, lambda: fm.search_code(repo, query, glob, regex, max_results))

    @server.tool(annotations=RUN)
    def run_check(repo: str, check: str) -> dict:
        """Run one policy-approved check (tests, lint, build) by name and return the exit code and output tail."""
        return guarded("run_check", {"repo": repo, "check": check}, lambda: fm.run_check(repo, check))

    @server.tool(annotations=READ_REMOTE)
    def ci_runs(repo: str, limit: int = 5) -> dict:
        """Recent GitHub Actions runs for the repo (read-only, via the GitHub CLI)."""
        return guarded("ci_runs", {"repo": repo, "limit": limit}, lambda: fm.ci_runs(repo, limit))

    @server.tool(annotations=REQUEST)
    def request_action(kind: str, repo: str, params: dict, reason: str) -> dict:
        """Ask a human to approve a write. kind: git_branch {name, from_ref} or github_issue {title, body}."""
        args = {"kind": kind, "repo": repo, "params": params, "reason": reason}
        return guarded("request_action", args, lambda: fm.request_action(kind, repo, params, reason))

    @server.tool(annotations=READ)
    def action_status(action_id: str) -> dict:
        """Show whether a requested action is pending, approved, denied or executed."""
        return guarded("action_status", {"action_id": action_id}, lambda: fm.action_status(action_id))

    @server.tool(annotations=EXECUTE)
    def execute_action(action_id: str) -> dict:
        """Execute a human-approved action exactly once, with the parameters that were approved."""
        return guarded("execute_action", {"action_id": action_id}, lambda: fm.execute_action(action_id))

    @server.tool(annotations=READ)
    def usage_report() -> dict:
        """This session's calls, errors, denials by code, latency (p50/p95), redactions and remaining budget."""
        return guarded("usage_report", {}, fm.usage_report)

    @server.resource("foreman://repos/{name}/agents", mime_type="text/markdown",
                     description="The repository's AGENTS.md (or CLAUDE.md): rules an agent must follow.")
    def agents_resource(name: str) -> str:
        return guarded("read_agents_md", {"repo": name}, lambda: fm.agents_md(name))

    return server, fm
