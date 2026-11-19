"""Tool implementations. Pure Python, no MCP types: the server module only wires these up.

Every public tool goes through `Foreman.call`, which enforces the budget, times the call,
redacts the result, caps its size and writes the audit record - for successes and denials alike.
"""

from __future__ import annotations

import contextlib
import fnmatch
import json
import os
import re
import shutil
import subprocess
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from foreman.approvals import ApprovalStore, make_runner, validate_action
from foreman.errors import (
    COMMAND_FAILED,
    GH_UNAVAILABLE,
    INVALID_ARGUMENT,
    TIMEOUT,
    UNKNOWN_CHECK,
    UNKNOWN_REPO,
    WRITES_DISABLED,
    GuardError,
)
from foreman.guard import baseline_env, is_denied, read_text_file, redact, resolve_in_repo, scrub_env
from foreman.policy import Policy, RepoPolicy
from foreman.telemetry import Ledger

SKIP_DIRS = {".git", "node_modules", ".venv", "venv", "__pycache__", "bin", "obj", "dist", "build", ".godot",
             ".import", ".mypy_cache", ".pytest_cache", ".ruff_cache", ".foreman", ".idea", ".vs"}
TAIL_CHARS = 6000


def _redact_tree(value: Any) -> tuple[Any, int]:
    if isinstance(value, str):
        return redact(value)
    if isinstance(value, list):
        total, out = 0, []
        for item in value:
            clean, n = _redact_tree(item)
            out.append(clean)
            total += n
        return out, total
    if isinstance(value, dict):
        total, out_d = 0, {}
        for key, item in value.items():
            clean, n = _redact_tree(item)
            out_d[key] = clean
            total += n
        return out_d, total
    return value, 0


def _clip_tree(value: Any, max_str: int) -> Any:
    if isinstance(value, str) and len(value) > max_str:
        return "...[clipped]..." + value[-max_str:]
    if isinstance(value, list):
        return [_clip_tree(v, max_str) for v in value]
    if isinstance(value, dict):
        return {k: _clip_tree(v, max_str) for k, v in value.items()}
    return value


def excluded(rel: str, globs: tuple[str, ...]) -> bool:
    """Policy-level noise filter (e.g. 'tmp/**'). Not a security boundary; deny globs are."""
    for g in globs:
        if fnmatch.fnmatch(rel, g):
            return True
        if g.endswith("/**") and (rel == g[:-3] or rel.startswith(g[:-3] + "/")):
            return True
    return False


def _child(rel_dir: str, name: str) -> str:
    return name if rel_dir in ("", ".") else f"{rel_dir}/{name}"


def _tail(text: str) -> str:
    return text if len(text) <= TAIL_CHARS else "...[earlier output omitted]...\n" + text[-TAIL_CHARS:]


class Foreman:
    def __init__(self, policy: Policy):
        self.policy = policy
        self.ledger = Ledger(policy.state_dir, policy.limits)
        self.approvals = ApprovalStore(policy.state_dir)
        self._runner = make_runner(policy)
        self._rg = shutil.which("rg")

    # ------------------------------------------------------------------ plumbing
    def call(self, tool: str, args: dict[str, Any], fn: Callable[[], Any]) -> Any:
        start = time.perf_counter()

        def elapsed() -> float:
            return (time.perf_counter() - start) * 1000

        try:
            self.ledger.check_budget()
            raw = fn()
        except GuardError as err:
            self.ledger.record(tool, args, ok=False, duration_ms=elapsed(), error_code=err.code)
            raise
        except Exception as err:  # unexpected: still audited, surfaced as a generic failure
            self.ledger.record(tool, args, ok=False, duration_ms=elapsed(), error_code=COMMAND_FAILED)
            raise GuardError(COMMAND_FAILED, f"{type(err).__name__}: {err}") from err
        clean, n = _redact_tree(raw)
        clean = _clip_tree(clean, self.policy.limits.max_result_chars)
        size = len(json.dumps(clean, default=str))
        self.ledger.record(tool, args, ok=True, duration_ms=elapsed(), out_chars=size, redactions=n)
        return clean

    def repo(self, name: str) -> RepoPolicy:
        if name not in self.policy.repos:
            raise GuardError(UNKNOWN_REPO, f"{name!r} is not in policy; known: {sorted(self.policy.repos)}")
        return self.policy.repos[name]

    def _git(self, repo: RepoPolicy, *args: str, check: bool = True) -> str:
        proc = subprocess.run(
            [self.policy.git_command, "-C", str(repo.root), *args],
            capture_output=True, text=True, encoding="utf-8", errors="replace",
            timeout=self.policy.limits.git_timeout_s, env=scrub_env(), stdin=subprocess.DEVNULL, check=False,
        )
        if check and proc.returncode != 0:
            raise GuardError(COMMAND_FAILED, f"git {args[0]}: {(proc.stderr or proc.stdout).strip()[:300]}")
        return proc.stdout if proc.returncode == 0 else ""

    # ------------------------------------------------------------------ read-only tools
    def list_repos(self) -> dict[str, Any]:
        repos = []
        for r in self.policy.repos.values():
            repos.append({
                "name": r.name,
                "checks": sorted(r.checks),
                "github": r.github,
                "has_agents_md": (r.root / "AGENTS.md").exists() or (r.root / "CLAUDE.md").exists(),
            })
        return {"repos": repos, "writes_enabled": self.policy.allow_writes}

    def repo_status(self, repo: str) -> dict[str, Any]:
        r = self.repo(repo)
        if not (r.root / ".git").exists():
            return {"repo": repo, "git": False}
        branch = self._git(r, "rev-parse", "--abbrev-ref", "HEAD", check=False).strip() or "(no commits)"
        head = self._git(r, "rev-parse", "--short", "HEAD", check=False).strip() or None
        ahead = behind = None
        counts = self._git(r, "rev-list", "--left-right", "--count", "@{upstream}...HEAD", check=False).split()
        if len(counts) == 2:
            behind, ahead = int(counts[0]), int(counts[1])
        porcelain = self._git(r, "status", "--porcelain=v1").splitlines()
        changed = [line[3:] for line in porcelain if line.strip()]
        changed = [p for p in changed if not is_denied(p.strip('"').replace("\\", "/"), self.policy.deny_globs)]
        log = self._git(r, "log", "-5", "--format=%h%x1f%ad%x1f%an%x1f%s", "--date=short", check=False)
        commits = []
        for line in log.splitlines():
            parts = line.split("\x1f")
            if len(parts) == 4:
                commits.append({"sha": parts[0], "date": parts[1], "author": parts[2], "subject": parts[3]})
        branches = self._git(r, "for-each-ref", "--format=%(refname:short)", "--count=50", "refs/heads",
                             check=False).split()
        return {
            "repo": repo, "git": True, "branch": branch, "head": head, "ahead": ahead, "behind": behind,
            "changed_files": len(changed), "changed_sample": changed[:50], "local_branches": branches,
            "recent_commits": commits,
        }

    def list_files(self, repo: str, subdir: str = ".", pattern: str | None = None, limit: int = 300) -> dict:
        r = self.repo(repo)
        limit = max(1, min(int(limit), 1000))
        base_rel = "" if subdir in ("", ".", "./") else resolve_in_repo(r.root, subdir, self.policy.deny_globs)[1]
        files: list[str] = []
        if (r.root / ".git").exists():
            out = self._git(r, "ls-files", "--cached", "--others", "--exclude-standard", "--", base_rel or ".")
            candidates = out.splitlines()
        else:
            candidates = []
            for dirpath, dirnames, filenames in os.walk(r.root / base_rel):
                rel_dir = Path(dirpath).relative_to(r.root).as_posix()
                dirnames[:] = [d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                               and not excluded(_child(rel_dir, d), r.exclude)]
                for f in filenames:
                    candidates.append((Path(dirpath) / f).relative_to(r.root).as_posix())
        for rel in candidates:
            if is_denied(rel, self.policy.deny_globs) or excluded(rel, r.exclude):
                continue
            if pattern and not (fnmatch.fnmatch(rel, pattern) or fnmatch.fnmatch(Path(rel).name, pattern)):
                continue
            files.append(rel)
        return {"repo": repo, "total": len(files), "files": files[:limit], "truncated": len(files) > limit}

    def read_file(self, repo: str, path: str, start_line: int = 1, end_line: int | None = None) -> dict:
        r = self.repo(repo)
        target, rel = resolve_in_repo(r.root, path, self.policy.deny_globs)
        text = read_text_file(target, self.policy.limits.max_file_bytes)
        lines = text.splitlines()
        start = max(1, int(start_line))
        end = len(lines) if end_line is None else min(len(lines), int(end_line))
        if end < start and lines:
            raise GuardError(INVALID_ARGUMENT, "end_line is before start_line")
        body = "\n".join(f"{i}\t{lines[i - 1]}" for i in range(start, end + 1))
        return {"repo": repo, "path": rel, "start_line": start, "end_line": end, "total_lines": len(lines),
                "content": body}

    def search_code(self, repo: str, query: str, glob: str | None = None, regex: bool = False,
                    max_results: int = 50) -> dict[str, Any]:
        r = self.repo(repo)
        if not query or len(query) > 300:
            raise GuardError(INVALID_ARGUMENT, "query must be 1-300 characters")
        limit = max(1, min(int(max_results), self.policy.limits.max_search_results))
        if regex:
            try:
                re.compile(query)
            except re.error as err:
                raise GuardError(INVALID_ARGUMENT, f"bad regex: {err}") from None
        deadline = time.monotonic() + self.policy.limits.search_timeout_s
        search = self._search_rg if self._rg else self._search_py
        hits, timed_out = search(r, query, glob, regex, limit, deadline)
        hits = [h for h in hits if self._safe_hit(r, h["path"]) and not excluded(h["path"], r.exclude)][:limit]
        out = {"repo": repo, "query": query, "engine": "ripgrep" if self._rg else "python",
               "count": len(hits), "results": hits, "timed_out": timed_out}
        if timed_out:
            out["note"] = (f"search stopped after {self.policy.limits.search_timeout_s}s; results are partial. "
                           "Narrow it with `glob`, or add noisy folders to the repo's `exclude` in policy.")
        return out

    def _safe_hit(self, r: RepoPolicy, rel: str) -> bool:
        """Defence in depth: re-check every hit by name *and* by resolved target (symlinks can point at secrets)."""
        if is_denied(rel, self.policy.deny_globs):
            return False
        try:
            resolve_in_repo(r.root, rel, self.policy.deny_globs)
        except GuardError:
            return False
        return True

    def _search_rg(self, r: RepoPolicy, query: str, glob: str | None, regex: bool, limit: int,
                   deadline: float) -> tuple[list[dict], bool]:
        argv = [self._rg, "--line-number", "--no-heading", "--color", "never", "--max-columns", "400",
                "--max-count", "20", "--max-filesize", "2M", "--path-separator", "/"]
        if not regex:
            argv.append("--fixed-strings")
        for g in self.policy.deny_globs + r.exclude:
            argv += ["--glob", f"!{g}"]
        if glob:
            argv += ["--glob", glob]
        argv += ["-e", query, "--", "."]
        proc = subprocess.Popen(argv, cwd=r.root, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True,
                                encoding="utf-8", errors="replace", env=scrub_env(), stdin=subprocess.DEVNULL)
        hits: list[dict] = []
        finished = threading.Event()

        def reader() -> None:
            assert proc.stdout is not None
            for line in proc.stdout:
                m = re.match(r"^(.*?):(\d+):(.*)$", line.rstrip("\n"))
                if m:
                    path = m.group(1)[2:] if m.group(1).startswith("./") else m.group(1)
                    hits.append({"path": path, "line": int(m.group(2)), "text": m.group(3).strip()[:300]})
                    if len(hits) >= limit * 2:  # headroom for hits the post-filter drops
                        break
            finished.set()

        thread = threading.Thread(target=reader, daemon=True)
        thread.start()
        completed = finished.wait(max(0.0, deadline - time.monotonic()))
        if proc.poll() is None:
            proc.kill()
        with contextlib.suppress(subprocess.TimeoutExpired):
            proc.wait(timeout=5)
        thread.join(timeout=2)
        if proc.returncode == 2 and not hits:
            err = proc.stderr.read() if proc.stderr else ""
            if "regex" in err.lower() or "parse" in err.lower():
                raise GuardError(INVALID_ARGUMENT, err.strip()[:300])
        return list(hits), not completed

    def _search_py(self, r: RepoPolicy, query: str, glob: str | None, regex: bool, limit: int,
                   deadline: float) -> tuple[list[dict], bool]:
        pattern = re.compile(query if regex else re.escape(query))
        hits: list[dict] = []
        for dirpath, dirnames, filenames in os.walk(r.root):
            rel_dir = Path(dirpath).relative_to(r.root).as_posix()
            dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS and not d.startswith(".")
                                 and not excluded(_child(rel_dir, d), r.exclude))
            if time.monotonic() >= deadline:
                return hits, True
            for name in sorted(filenames):
                full = Path(dirpath) / name
                rel = full.relative_to(r.root).as_posix()
                if full.is_symlink() or is_denied(rel, self.policy.deny_globs) or name.startswith("."):
                    continue
                if glob and not (fnmatch.fnmatch(rel, glob) or fnmatch.fnmatch(name, glob)):
                    continue
                try:
                    if full.stat().st_size > 1_000_000:
                        continue
                    data = full.read_bytes()
                except OSError:
                    continue
                if b"\x00" in data[:8192]:
                    continue
                for i, line in enumerate(data.decode("utf-8", errors="replace").splitlines(), 1):
                    if pattern.search(line):
                        hits.append({"path": rel, "line": i, "text": line.strip()[:300]})
                        if len(hits) >= limit:
                            return hits, False
        return hits, False

    def agents_md(self, repo: str) -> str:
        r = self.repo(repo)
        for name in ("AGENTS.md", "CLAUDE.md"):
            path = r.root / name
            if path.is_file():
                return read_text_file(path, self.policy.limits.max_file_bytes)
        return f"{repo} has no AGENTS.md or CLAUDE.md."

    # ------------------------------------------------------------------ execution
    def _resolve_exe(self, root: Path, exe: str) -> str:
        if os.path.isabs(exe):
            return exe
        if "/" in exe or "\\" in exe:
            return str((root / exe).resolve())
        return shutil.which(exe) or exe

    def run_check(self, repo: str, check: str) -> dict[str, Any]:
        r = self.repo(repo)
        if check not in r.checks:
            raise GuardError(UNKNOWN_CHECK, f"{check!r} is not an approved check for {repo}; "
                                            f"approved: {sorted(r.checks)}")
        argv = list(r.checks[check])
        argv[0] = self._resolve_exe(r.root, argv[0])
        start = time.perf_counter()
        try:
            env = {**baseline_env(scrub_env()), **dict(r.env)}
            proc = subprocess.run(argv, cwd=r.root, capture_output=True, text=True, encoding="utf-8",
                                  errors="replace", timeout=self.policy.limits.check_timeout_s,
                                  env=env, stdin=subprocess.DEVNULL, check=False)
        except subprocess.TimeoutExpired:
            raise GuardError(TIMEOUT, f"{check} exceeded {self.policy.limits.check_timeout_s}s and was killed") \
                from None
        except FileNotFoundError:
            raise GuardError(COMMAND_FAILED, f"executable for {check!r} not found: {argv[0]}") from None
        return {
            "repo": repo, "check": check, "command": " ".join(r.checks[check]),
            "exit_code": proc.returncode, "passed": proc.returncode == 0,
            "duration_s": round(time.perf_counter() - start, 2),
            "stdout_tail": _tail(proc.stdout), "stderr_tail": _tail(proc.stderr),
        }

    def ci_runs(self, repo: str, limit: int = 5) -> dict[str, Any]:
        r = self.repo(repo)
        if not r.github:
            raise GuardError(INVALID_ARGUMENT, f"{repo} has no github = 'owner/repo' in policy")
        limit = max(1, min(int(limit), 20))
        fields = "databaseId,displayTitle,workflowName,status,conclusion,headBranch,event,createdAt,url"
        argv = [*self.policy.gh_command, "run", "list", "-R", r.github, "--limit", str(limit), "--json", fields]
        try:
            proc = subprocess.run(argv, capture_output=True, text=True, encoding="utf-8", errors="replace",
                                  timeout=60, env=scrub_env(passthrough=("GH_TOKEN", "GITHUB_TOKEN")),
                                  stdin=subprocess.DEVNULL, check=False)
        except FileNotFoundError:
            raise GuardError(GH_UNAVAILABLE, "GitHub CLI `gh` is not installed") from None
        if proc.returncode != 0:
            raise GuardError(GH_UNAVAILABLE, (proc.stderr or proc.stdout).strip()[:300])
        runs = json.loads(proc.stdout or "[]")
        return {"repo": repo, "github": r.github, "runs": runs}

    # ------------------------------------------------------------------ approvals
    def request_action(self, kind: str, repo: str, params: dict[str, Any], reason: str) -> dict[str, Any]:
        if not self.policy.allow_writes:
            raise GuardError(WRITES_DISABLED, "this policy is read-only (allow_writes = false)")
        r = self.repo(repo)
        clean = validate_action(kind, r, params or {})
        rec = self.approvals.request(kind, repo, clean, reason, self.ledger.session_id)
        policy_flag = f' --policy "{self.policy.source}"' if self.policy.source else ""
        return {"id": rec["id"], "status": rec["status"], "kind": kind, "repo": repo, "params": clean,
                "next_step": f"A human must approve it: foreman{policy_flag} approve {rec['id']}"}

    def action_status(self, action_id: str) -> dict[str, Any]:
        rec = self.approvals.get(action_id)
        return {k: rec.get(k) for k in ("id", "kind", "repo", "params", "status", "requested_at", "decided_by",
                                        "decided_at", "executed_at", "result", "note")}

    def execute_action(self, action_id: str) -> dict[str, Any]:
        if not self.policy.allow_writes:
            raise GuardError(WRITES_DISABLED, "this policy is read-only (allow_writes = false)")
        rec = self.approvals.execute(action_id, self._runner)
        return {"id": rec["id"], "status": rec["status"], "result": rec["result"]}

    def usage_report(self) -> dict[str, Any]:
        return self.ledger.report()
