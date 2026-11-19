import sys
from pathlib import Path

import pytest

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "evals"))

from workspace import build_workspace  # noqa: E402

from foreman.policy import load_policy  # noqa: E402
from foreman.service import Foreman  # noqa: E402


@pytest.fixture(scope="session")
def workspace(tmp_path_factory):
    return build_workspace(tmp_path_factory.mktemp("ws"))


@pytest.fixture
def foreman(workspace, tmp_path):
    policy = load_policy(workspace.policy)
    # Fresh state dir per test so approvals and budgets don't leak between tests.
    from dataclasses import replace

    return Foreman(replace(policy, state_dir=tmp_path / "state"))
