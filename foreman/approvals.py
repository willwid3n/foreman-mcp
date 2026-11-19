"""Human-in-the-loop approvals for anything that writes.

An agent can only *request* a write. A human approves it out-of-band (`foreman approve <id>`),
and the agent then executes exactly what was approved - once. The approved parameters are
hashed at request time, so editing the queue file after approval is detected as tampering.
"""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
import uuid
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foreman.errors import (
    ALREADY_EXECUTED,
    COMMAND_FAILED,
    GH_UNAVAILABLE,
    INVALID_ARGUMENT,
    NOT_APPROVED,
    NOT_FOUND,
    TAMPERED,
    UNKNOWN_ACTION,
    GuardError,
)
from foreman.guard import redact, scrub_env
from foreman.policy import Policy, RepoPolicy

BRANCH_RE = re.compile(r"^(?!-)(?!.*\.\.)(?!.*//)[A-Za-z0-9._/-]{1,100}(?<!\.lock)(?<!/)$")


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def digest(kind: str, repo: str, params: dict[str, Any]) -> str:
    canonical = json.dumps({"kind": kind, "repo": repo, "params": params}, sort_keys=True, separators=(",", ":"))
    return hashlib.sha256(canonical.encode()).hexdigest()


def validate_action(kind: str, repo: RepoPolicy, params: dict[str, Any]) -> dict[str, Any]:
    if kind == "git_branch":
        name = str(params.get("name", ""))
        base = str(params.get("from_ref", "HEAD"))
        if not BRANCH_RE.match(name):
            raise GuardError(INVALID_ARGUMENT, f"invalid branch name {name!r}")
        if not BRANCH_RE.match(base) and base != "HEAD":
            raise GuardError(INVALID_ARGUMENT, f"invalid from_ref {base!r}")
        return {"name": name, "from_ref": base}
    if kind == "github_issue":
        if not repo.github:
            raise GuardError(INVALID_ARGUMENT, f"repo {repo.name!r} has no github = 'owner/repo' in policy")
        title = str(params.get("title", "")).strip()
        body = str(params.get("body", ""))
        if not 3 <= len(title) <= 200:
            raise GuardError(INVALID_ARGUMENT, "title must be 3-200 characters")
        if len(body) > 20_000:
            raise GuardError(INVALID_ARGUMENT, "body is limited to 20,000 characters")
        body, _ = redact(body)
        title, _ = redact(title)
        return {"title": title, "body": body}
    raise GuardError(UNKNOWN_ACTION, f"unknown action kind {kind!r}; allowed: git_branch, github_issue")


class ApprovalStore:
    def __init__(self, state_dir: Path):
        self.path = state_dir / "approvals.json"
        state_dir.mkdir(parents=True, exist_ok=True)

    def _load(self) -> dict[str, dict[str, Any]]:
        if not self.path.exists():
            return {}
        return json.loads(self.path.read_text(encoding="utf-8") or "{}")

    def _save(self, data: dict[str, dict[str, Any]]) -> None:
        tmp = self.path.with_suffix(".tmp")
        tmp.write_text(json.dumps(data, indent=2), encoding="utf-8")
        os.replace(tmp, self.path)

    def get(self, action_id: str) -> dict[str, Any]:
        data = self._load()
        if action_id not in data:
            raise GuardError(NOT_FOUND, f"no action with id {action_id!r}")
        return data[action_id]

    def list(self, status: str | None = None) -> list[dict[str, Any]]:
        items = list(self._load().values())
        return [a for a in items if status is None or a["status"] == status]

    def request(self, kind: str, repo: str, params: dict[str, Any], reason: str, session: str) -> dict[str, Any]:
        data = self._load()
        action_id = uuid.uuid4().hex[:8]
        record = {
            "id": action_id,
            "kind": kind,
            "repo": repo,
            "params": params,
            "reason": redact(reason)[0][:1000],
            "status": "pending",
            "digest": digest(kind, repo, params),
            "requested_at": _now(),
            "requested_by_session": session,
        }
        data[action_id] = record
        self._save(data)
        return record

    def decide(self, action_id: str, approve: bool, by: str, note: str = "") -> dict[str, Any]:
        data = self._load()
        if action_id not in data:
            raise GuardError(NOT_FOUND, f"no action with id {action_id!r}")
        record = data[action_id]
        if record["status"] != "pending":
            raise GuardError(INVALID_ARGUMENT, f"action {action_id} is already {record['status']}")
        record["status"] = "approved" if approve else "denied"
        record["decided_by"] = by
        record["decided_at"] = _now()
        if note:
            record["note"] = note
        self._save(data)
        return record

    def execute(self, action_id: str, runner: Callable[[dict[str, Any]], dict[str, Any]]) -> dict[str, Any]:
        data = self._load()
        if action_id not in data:
            raise GuardError(NOT_FOUND, f"no action with id {action_id!r}")
        record = data[action_id]
        if record["status"] == "executed":
            raise GuardError(ALREADY_EXECUTED, f"action {action_id} already ran at {record.get('executed_at')}")
        if record["status"] != "approved":
            raise GuardError(NOT_APPROVED, f"action {action_id} is {record['status']}; a human must run "
                                           f"`foreman approve {action_id}` first")
        if digest(record["kind"], record["repo"], record["params"]) != record["digest"]:
            record["status"] = "tampered"
            self._save(data)
            raise GuardError(TAMPERED, f"action {action_id} parameters changed after it was requested")
        result = runner(record)
        record["status"] = "executed"
        record["executed_at"] = _now()
        record["result"] = result
        self._save(data)
        return record


def make_runner(policy: Policy) -> Callable[[dict[str, Any]], dict[str, Any]]:
    def run(record: dict[str, Any]) -> dict[str, Any]:
        repo = policy.repos[record["repo"]]
        params = record["params"]
        if record["kind"] == "git_branch":
            # BRANCH_RE forbids a leading "-", so neither value can be parsed as a git option.
            argv = [policy.git_command, "-C", str(repo.root), "branch", params["name"], params["from_ref"]]
            proc = subprocess.run(argv, capture_output=True, text=True, timeout=policy.limits.git_timeout_s,
                                  env=scrub_env(), stdin=subprocess.DEVNULL, check=False)
            if proc.returncode != 0:
                raise GuardError(COMMAND_FAILED, (proc.stderr or proc.stdout).strip()[:500])
            return {"created_branch": params["name"], "from_ref": params["from_ref"]}
        if record["kind"] == "github_issue":
            argv = [*policy.gh_command, "issue", "create", "-R", repo.github or "", "--title", params["title"],
                    "--body", params["body"]]
            if policy.dry_run_external:
                return {"dry_run": True, "argv": argv[:-4] + ["--title", params["title"], "--body", "<body>"]}
            try:
                proc = subprocess.run(argv, capture_output=True, text=True, timeout=60,
                                      env=scrub_env(passthrough=("GH_TOKEN", "GITHUB_TOKEN")),
                                      stdin=subprocess.DEVNULL, check=False)
            except FileNotFoundError:
                raise GuardError(GH_UNAVAILABLE, "GitHub CLI `gh` is not installed") from None
            if proc.returncode != 0:
                raise GuardError(COMMAND_FAILED, (proc.stderr or proc.stdout).strip()[:500])
            return {"issue_url": proc.stdout.strip()}
        raise GuardError(UNKNOWN_ACTION, record["kind"])

    return run
