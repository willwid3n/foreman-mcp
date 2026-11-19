"""Policy: which repositories an agent may touch, which commands it may run, and its budget.

Everything an agent can do is declared here. There is no shell: a check is a fixed argv list,
so an agent can choose *which* approved check to run but never *what* it runs.
"""

from __future__ import annotations

import re
import sys
import tomllib
from dataclasses import dataclass, field
from pathlib import Path

from foreman.errors import INVALID_ARGUMENT, GuardError

NAME_RE = re.compile(r"^[a-z0-9][a-z0-9._-]{0,63}$")

DEFAULT_DENY_GLOBS: tuple[str, ...] = (
    ".env",
    ".env.*",
    "*.env",
    "*.pem",
    "*.key",
    "*.pfx",
    "*.p12",
    "*.keystore",
    "*.kdbx",
    "*.tfstate",
    "id_rsa*",
    "id_ed25519*",
    "id_ecdsa*",
    ".netrc",
    ".npmrc",
    ".pypirc",
    "credentials*",
    "secrets.*",
    ".git",
)


@dataclass(frozen=True)
class Limits:
    max_calls: int = 300
    max_session_output_chars: int = 2_000_000
    max_result_chars: int = 24_000
    max_file_bytes: int = 256_000
    max_search_results: int = 200
    check_timeout_s: float = 900.0
    search_timeout_s: float = 20.0
    git_timeout_s: float = 30.0


@dataclass(frozen=True)
class RepoPolicy:
    name: str
    root: Path
    checks: dict[str, tuple[str, ...]]
    github: str | None = None
    exclude: tuple[str, ...] = ()
    env: tuple[tuple[str, str], ...] = ()


@dataclass(frozen=True)
class Policy:
    repos: dict[str, RepoPolicy]
    limits: Limits = field(default_factory=Limits)
    deny_globs: tuple[str, ...] = DEFAULT_DENY_GLOBS
    allow_writes: bool = False
    dry_run_external: bool = False
    state_dir: Path = Path(".foreman")
    gh_command: tuple[str, ...] = ("gh",)
    git_command: str = "git"
    source: Path | None = None


def _expand(token: str) -> str:
    return token.replace("{python}", sys.executable)


def _command_prefix(value: str | list[str]) -> tuple[str, ...]:
    if isinstance(value, str):
        return (_expand(value),)
    if isinstance(value, list) and value and all(isinstance(v, str) for v in value):
        return tuple(_expand(v) for v in value)
    raise _bad("gh_command must be a string or a non-empty list of strings")


def _bad(msg: str) -> GuardError:
    return GuardError(INVALID_ARGUMENT, f"policy: {msg}")


def parse_policy(data: dict, base_dir: Path, source: Path | None = None) -> Policy:
    core = data.get("foreman", {})
    raw_limits = data.get("limits", {})
    known = set(Limits.__dataclass_fields__)
    unknown = set(raw_limits) - known
    if unknown:
        raise _bad(f"unknown limits {sorted(unknown)}")
    limits = Limits(**raw_limits)

    repos: dict[str, RepoPolicy] = {}
    for name, spec in (data.get("repos") or {}).items():
        if not NAME_RE.match(name):
            raise _bad(f"repo name {name!r} must match {NAME_RE.pattern}")
        root = Path(spec.get("path", "")).expanduser()
        if not root.is_absolute():
            root = base_dir / root
        root = root.resolve()
        if not root.is_dir():
            raise _bad(f"repo {name!r}: path {root} is not a directory")
        checks: dict[str, tuple[str, ...]] = {}
        for check_name, argv in (spec.get("checks") or {}).items():
            if not NAME_RE.match(check_name):
                raise _bad(f"check name {check_name!r} in {name!r} is invalid")
            if not isinstance(argv, list) or not argv or not all(isinstance(a, str) for a in argv):
                raise _bad(f"check {name}.{check_name} must be a non-empty list of strings (no shell)")
            checks[check_name] = tuple(_expand(a) for a in argv)
        github = spec.get("github")
        if github is not None and not re.match(r"^[A-Za-z0-9-]+/[A-Za-z0-9._-]+$", github):
            raise _bad(f"repo {name!r}: github must look like owner/repo")
        exclude = spec.get("exclude", [])
        if not isinstance(exclude, list) or not all(isinstance(g, str) for g in exclude):
            raise _bad(f"repo {name!r}: exclude must be a list of glob strings")
        env = spec.get("env", {})
        if not isinstance(env, dict) or not all(
            isinstance(k, str) and re.match(r"^[A-Za-z_][A-Za-z0-9_()]*$", k) and isinstance(v, str)
            for k, v in env.items()
        ):
            raise _bad(f"repo {name!r}: env must be a table of NAME = \"value\" strings")
        repos[name] = RepoPolicy(name=name, root=root, checks=checks, github=github, exclude=tuple(exclude),
                                 env=tuple(sorted(env.items())))

    if not repos:
        raise _bad("no [repos.<name>] entries")

    state_dir = Path(core.get("state_dir", ".foreman")).expanduser()
    if not state_dir.is_absolute():
        state_dir = base_dir / state_dir
    extra_deny = tuple(core.get("extra_deny_globs", ()))
    return Policy(
        repos=repos,
        limits=limits,
        deny_globs=DEFAULT_DENY_GLOBS + extra_deny,
        allow_writes=bool(core.get("allow_writes", False)),
        dry_run_external=bool(core.get("dry_run_external", False)),
        state_dir=state_dir.resolve(),
        gh_command=_command_prefix(core.get("gh_command", "gh")),
        git_command=core.get("git_command", "git"),
        source=source,
    )


def load_policy(path: str | Path) -> Policy:
    path = Path(path).expanduser().resolve()
    with path.open("rb") as fh:
        data = tomllib.load(fh)
    return parse_policy(data, base_dir=path.parent, source=path)
