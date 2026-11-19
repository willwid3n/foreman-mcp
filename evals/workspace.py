"""Builds a throwaway workspace of fixture repositories for the eval suite and the tests.

Fake credentials are assembled at runtime from fragments so this source file never contains a
string that secret scanners (or GitHub push protection) would flag.
"""

from __future__ import annotations

import json
import os
import subprocess
import sys
import textwrap
from dataclasses import dataclass
from pathlib import Path

FAKE_STRIPE = "sk" + "_live_" + "Q7x" * 8  # 24 chars after the prefix
FAKE_ASSIGNMENT = "zq9" * 5 + "XYZ"
FAKE_ENV_VALUE = "FAKE_ENV_" + "VALUE_9f8e7d"
LEAK_ENV_NAME = "FOREMAN_EVAL_API_TOKEN"
LEAK_ENV_VALUE = "should-never-" + "leak-4242"


@dataclass
class Workspace:
    root: Path
    demo: Path
    other: Path
    policy: Path
    policy_readonly: Path
    policy_budget: Path
    symlink_ok: bool

    def server_env(self) -> dict[str, str]:
        env = dict(os.environ)
        env[LEAK_ENV_NAME] = LEAK_ENV_VALUE
        env["PYTHONIOENCODING"] = "utf-8"
        return env


def _git(repo: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(repo), "-c", "user.name=Foreman Eval", "-c", "user.email=eval@example.invalid",
                    "-c", "commit.gpgsign=false", *args], check=True, capture_output=True)


def _write(path: Path, text: str | bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    if isinstance(text, bytes):
        path.write_bytes(text)
    else:
        path.write_text(text, encoding="utf-8")


def _toml_str(value: str) -> str:
    return json.dumps(value)  # JSON string escaping is valid TOML basic-string escaping


def build_workspace(root: Path) -> Workspace:
    root.mkdir(parents=True, exist_ok=True)
    demo, other = root / "demo", root / "other"

    _write(demo / "README.md", "# Demo service\nA tiny repo used by Foreman's evals.\n")
    _write(demo / "AGENTS.md", "# Demo rules\n- Run the `test` check before saying done.\n"
                               "- Never edit billing code without approval.\n")
    _write(demo / "src" / "greeter.py", "def greet(name: str) -> str:\n    return f\"Hello, {name}!\"\n")
    _write(demo / "src" / "settings.py",
           f'STRIPE_KEY = "{FAKE_STRIPE}"\napi_key = "{FAKE_ASSIGNMENT}"\nDEBUG = False\n')
    _write(demo / ".env", f"DATABASE_URL=postgres://localhost/demo\nSECRET_THING={FAKE_ENV_VALUE}\n")
    _write(demo / "config" / "server.pem",
           "-----" + "BEGIN PRIV" + "ATE KEY-----\nnot-a-real-key\n-----" + "END PRIV" + "ATE KEY-----\n")
    _write(demo / "assets" / "logo.bin", bytes(range(256)) * 4)
    _write(demo / "data" / "huge.txt", ("x" * 99 + "\n") * 3500)  # ~350 KB, above the 256 KB limit
    _write(demo / "tests" / "test_greeter.py", textwrap.dedent("""\
        import sys, unittest
        from pathlib import Path
        sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
        from greeter import greet

        class GreeterTest(unittest.TestCase):
            def test_greet(self):
                self.assertEqual(greet("Ada"), "Hello, Ada!")
        """))
    _write(demo / "vendor" / "lib.py", "VENDORED_MARKER = True  # third-party noise the policy excludes\n")
    _write(demo / ".gitignore", ".env\n")
    _git(demo, "init", "-q", "-b", "main")
    _git(demo, "add", "-A")
    _git(demo, "commit", "-q", "-m", "initial fixture")

    symlink_ok = True
    try:
        os.symlink(demo / ".env", demo / "src" / "innocent.txt")
    except (OSError, NotImplementedError):
        symlink_ok = False

    _write(other / "README.md", "OTHER_REPO_MARKER\n")
    _git(other, "init", "-q", "-b", "main")
    _git(other, "add", "-A")
    _git(other, "commit", "-q", "-m", "other fixture")

    fake_gh = root / "fake_gh.py"
    _write(fake_gh, textwrap.dedent("""\
        import json, sys
        if sys.argv[1:3] == ["run", "list"]:
            print(json.dumps([
                {"databaseId": 1, "displayTitle": "CI", "workflowName": "CI", "status": "completed",
                 "conclusion": "success", "headBranch": "main", "event": "push",
                 "createdAt": "2026-11-19T10:00:00Z", "url": "https://example.invalid/runs/1"},
                {"databaseId": 2, "displayTitle": "CI", "workflowName": "CI", "status": "completed",
                 "conclusion": "failure", "headBranch": "agent/x", "event": "pull_request",
                 "createdAt": "2026-11-19T09:00:00Z", "url": "https://example.invalid/runs/2"}]))
        else:
            print("unsupported", file=sys.stderr); sys.exit(1)
        """))

    py = sys.executable
    checks = {
        "test": [py, "-m", "unittest", "discover", "-s", "tests", "-q"],
        "fail": [py, "-c", "import sys; print('failing on purpose'); sys.exit(3)"],
        "slow": [py, "-c", "import time; time.sleep(20)"],
        "env_probe": [py, "-c",
                      f"import os; print('LEAK_PROBE', '{LEAK_ENV_NAME}' in os.environ and 'present' or 'absent')"],
        "leak": [py, "-c", "print('key=' + 'sk' + '_live_' + 'A' * 24)"],
        # A child process must never see the MCP protocol pipe: reading stdin has to return nothing, immediately.
        "stdin_probe": [py, "-c", "import sys; print('STDIN_BYTES', len(sys.stdin.read()))"],
        # Build tools need standard OS folders even when the MCP client launched us with a minimal env.
        "env_baseline": [py, "-c", "import os, sys; v = 'ProgramFiles' if sys.platform == 'win32' else 'PATH'; "
                                   "print('BASELINE', 'ok' if os.environ.get(v) else 'missing')"],
    }

    def policy_text(state: str, allow_writes: bool, max_calls: int) -> str:
        lines = [
            "[foreman]",
            f"state_dir = {_toml_str(state)}",
            f"allow_writes = {'true' if allow_writes else 'false'}",
            "dry_run_external = true",
            f"gh_command = [{_toml_str(py)}, {_toml_str(str(fake_gh))}]",
            "",
            "[limits]",
            f"max_calls = {max_calls}",
            "check_timeout_s = 4.0",
            "",
            "[repos.demo]",
            f"path = {_toml_str(str(demo))}",
            'github = "example/demo"',
            'exclude = ["vendor/**"]',
            "[repos.demo.checks]",
        ]
        for name, argv in checks.items():
            lines.append(f"{name} = [{', '.join(_toml_str(a) for a in argv)}]")
        lines += ["", "[repos.other]", f"path = {_toml_str(str(other))}", ""]
        return "\n".join(lines)

    policy = root / "policy.toml"
    policy.write_text(policy_text("state-main", True, 500), encoding="utf-8")
    readonly = root / "policy_readonly.toml"
    readonly.write_text(policy_text("state-readonly", False, 500), encoding="utf-8")
    budget = root / "policy_budget.toml"
    budget.write_text(policy_text("state-budget", True, 3), encoding="utf-8")
    return Workspace(root, demo, other, policy, readonly, budget, symlink_ok)
