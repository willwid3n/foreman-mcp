import json

import pytest

from foreman.approvals import ApprovalStore, digest, validate_action
from foreman.errors import (
    ALREADY_EXECUTED,
    INVALID_ARGUMENT,
    NOT_APPROVED,
    TAMPERED,
    UNKNOWN_ACTION,
    WRITES_DISABLED,
    GuardError,
)
from foreman.policy import RepoPolicy, parse_policy


def _repo(tmp_path, github: str | None = "me/demo"):
    return RepoPolicy(name="demo", root=tmp_path, checks={}, github=github)


@pytest.mark.parametrize("name", ["--upload-pack=x", "-x", "a..b", "a//b", "feature.lock", "ends/", "has space", ""])
def test_rejects_unsafe_branch_names(tmp_path, name):
    with pytest.raises(GuardError) as err:
        validate_action("git_branch", _repo(tmp_path), {"name": name})
    assert err.value.code == INVALID_ARGUMENT


def test_accepts_normal_branch_and_defaults_base(tmp_path):
    assert validate_action("git_branch", _repo(tmp_path), {"name": "agent/fix-1"}) == {
        "name": "agent/fix-1", "from_ref": "HEAD"}


def test_issue_requires_github_and_redacts_body(tmp_path):
    with pytest.raises(GuardError):
        validate_action("github_issue", _repo(tmp_path, github=None), {"title": "Bug", "body": ""})
    clean = validate_action("github_issue", _repo(tmp_path), {"title": "Bug", "body": "token ghp_" + "x" * 36})
    assert "[REDACTED:github-token]" in clean["body"]


def test_unknown_kind(tmp_path):
    with pytest.raises(GuardError) as err:
        validate_action("shell", _repo(tmp_path), {})
    assert err.value.code == UNKNOWN_ACTION


def test_lifecycle_is_one_shot_and_tamper_evident(tmp_path):
    store = ApprovalStore(tmp_path)
    calls = []
    runner = lambda rec: calls.append(rec["params"]) or {"ok": True}  # noqa: E731

    rec = store.request("git_branch", "demo", {"name": "a", "from_ref": "HEAD"}, "why", "sess")
    with pytest.raises(GuardError) as err:
        store.execute(rec["id"], runner)
    assert err.value.code == NOT_APPROVED

    store.decide(rec["id"], approve=True, by="william")
    assert store.execute(rec["id"], runner)["status"] == "executed"
    with pytest.raises(GuardError) as err:
        store.execute(rec["id"], runner)
    assert err.value.code == ALREADY_EXECUTED
    assert calls == [{"name": "a", "from_ref": "HEAD"}]

    rec2 = store.request("git_branch", "demo", {"name": "b", "from_ref": "HEAD"}, "why", "sess")
    store.decide(rec2["id"], approve=True, by="william")
    data = json.loads(store.path.read_text())
    data[rec2["id"]]["params"]["name"] = "evil"
    store.path.write_text(json.dumps(data))
    with pytest.raises(GuardError) as err:
        store.execute(rec2["id"], runner)
    assert err.value.code == TAMPERED
    assert len(calls) == 1


def test_digest_is_order_independent():
    assert digest("k", "r", {"a": 1, "b": 2}) == digest("k", "r", {"b": 2, "a": 1})


def test_read_only_policy_blocks_requests(workspace, tmp_path):
    from foreman.policy import load_policy
    from foreman.service import Foreman

    fm = Foreman(load_policy(workspace.policy_readonly))
    with pytest.raises(GuardError) as err:
        fm.request_action("git_branch", "demo", {"name": "x"}, "why")
    assert err.value.code == WRITES_DISABLED


def test_policy_validation(tmp_path):
    with pytest.raises(GuardError, match="no \\[repos"):
        parse_policy({}, tmp_path)
    with pytest.raises(GuardError, match="must be a non-empty list"):
        parse_policy({"repos": {"demo": {"path": str(tmp_path), "checks": {"test": "pytest -q"}}}}, tmp_path)
    with pytest.raises(GuardError, match="not a directory"):
        parse_policy({"repos": {"demo": {"path": str(tmp_path / "missing")}}}, tmp_path)
    with pytest.raises(GuardError, match="unknown limits"):
        parse_policy({"limits": {"max_cals": 3}, "repos": {"demo": {"path": str(tmp_path)}}}, tmp_path)
    with pytest.raises(GuardError, match="repo name"):
        parse_policy({"repos": {"../evil": {"path": str(tmp_path)}}}, tmp_path)
