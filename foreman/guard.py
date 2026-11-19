"""Path sandboxing, secret redaction and environment scrubbing.

Defence in depth: paths are confined to the repo root after symlink resolution, secret-bearing
files are refused by name, and anything that still looks like a credential is redacted from
every result before it reaches the model.
"""

from __future__ import annotations

import fnmatch
import os
import re
import sys
from pathlib import Path, PurePosixPath

from foreman.errors import (
    BINARY_FILE,
    INVALID_ARGUMENT,
    NOT_FOUND,
    OUTSIDE_REPO,
    SECRET_PATH,
    TOO_LARGE,
    GuardError,
)

# (kind, pattern). Order matters: specific token formats first, generic assignments last.
_SECRET_PATTERNS: list[tuple[str, re.Pattern[str]]] = [
    ("private-key", re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S)),
    ("aws-key", re.compile(r"\b(?:AKIA|ASIA)[0-9A-Z]{16}\b")),
    ("github-token", re.compile(r"\b(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})\b")),
    ("stripe-key", re.compile(r"\b(?:sk|rk|pk)_(?:live|test)_[A-Za-z0-9]{16,}\b")),
    ("stripe-webhook", re.compile(r"\bwhsec_[A-Za-z0-9]{16,}\b")),
    ("anthropic-key", re.compile(r"\bsk-ant-[A-Za-z0-9_-]{20,}")),
    ("openai-key", re.compile(r"\bsk-(?:proj-)?[A-Za-z0-9_-]{20,}")),
    ("google-key", re.compile(r"\bAIza[0-9A-Za-z_-]{35}\b")),
    ("slack-token", re.compile(r"\bxox[abprs]-[A-Za-z0-9-]{10,}")),
    ("jwt", re.compile(r"\beyJ[A-Za-z0-9_-]{8,}\.eyJ[A-Za-z0-9_-]{8,}\.[A-Za-z0-9_-]{8,}")),
    (
        "assignment",
        re.compile(
            r"(?i)\b((?:api[_-]?key|secret(?:[_-]?key)?|access[_-]?token|auth[_-]?token|token|"
            r"password|passwd|pwd|client[_-]?secret)\s*[\"']?\s*[:=]\s*[\"']?)([^\s\"';,]{8,})"
        ),
    ),
]

_ENV_SECRET_RE = re.compile(r"(?i)(KEY|TOKEN|SECRET|PASSW|CREDENTIAL|PRIVATE|AUTH|COOKIE|SESSION)")
_ENV_KEEP = {"PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "HOME",
             "USERPROFILE", "LOCALAPPDATA", "APPDATA", "PROGRAMDATA", "PROGRAMFILES", "PROGRAMFILES(X86)",
             "LANG", "LC_ALL", "TERM", "USER", "USERNAME", "SHELL", "PYTHONIOENCODING", "DOTNET_ROOT",
             "NUMBER_OF_PROCESSORS", "PROCESSOR_ARCHITECTURE", "OS"}


def redact(text: str) -> tuple[str, int]:
    """Replace credential-looking substrings. Returns (clean_text, number_of_redactions)."""
    total = 0
    for kind, pattern in _SECRET_PATTERNS:
        if kind == "assignment":
            text, n = pattern.subn(lambda m, k=kind: f"{m.group(1)}[REDACTED:{k}]", text)
        else:
            text, n = pattern.subn(f"[REDACTED:{kind}]", text)
        total += n
    return text, total


def scrub_env(env: dict[str, str] | None = None, passthrough: tuple[str, ...] = ()) -> dict[str, str]:
    """Copy of the environment without credential-looking variables (passthrough keys survive)."""
    env = dict(os.environ if env is None else env)
    clean: dict[str, str] = {}
    for key, value in env.items():
        upper = key.upper()
        if upper in _ENV_KEEP or key in passthrough or not _ENV_SECRET_RE.search(upper):
            clean[key] = value
    clean["PYTHONIOENCODING"] = "utf-8"
    return clean


def baseline_env(env: dict[str, str]) -> dict[str, str]:
    """Restore standard, non-secret OS variables a client may have stripped.

    MCP clients often launch servers with a minimal environment (the Python SDK keeps ~12 variables on
    Windows). Build tools then break in confusing ways: NuGet throws "Value cannot be null (path1)"
    without ProgramFiles. Only missing keys are filled; nothing here is a credential.
    """
    out = dict(env)
    present = {k.upper() for k in out}
    if sys.platform == "win32":
        drive = out.get("SystemDrive") or out.get("SYSTEMDRIVE") or "C:"
        root = out.get("SystemRoot") or out.get("SYSTEMROOT") or f"{drive}\\Windows"
        pf = f"{drive}\\Program Files"
        defaults = {
            "ProgramFiles": pf, "ProgramW6432": pf, "ProgramFiles(x86)": f"{drive}\\Program Files (x86)",
            "CommonProgramFiles": f"{pf}\\Common Files", "ProgramData": f"{drive}\\ProgramData",
            "ALLUSERSPROFILE": f"{drive}\\ProgramData", "windir": root, "ComSpec": f"{root}\\System32\\cmd.exe",
        }
        if "TEMP" in present and "TMP" not in present:
            defaults["TMP"] = out.get("TEMP") or out.get("Temp", "")
    else:
        defaults = {"LANG": "C.UTF-8", "PATH": "/usr/local/bin:/usr/bin:/bin"}
    for key, value in defaults.items():
        if key.upper() not in present and value:
            out[key] = value
    return out


def is_denied(rel_posix: str, deny_globs: tuple[str, ...]) -> bool:
    parts = PurePosixPath(rel_posix).parts
    for part in parts:
        for pattern in deny_globs:
            if fnmatch.fnmatch(part.lower(), pattern.lower()):
                return True
    return any(fnmatch.fnmatch(rel_posix.lower(), p.lower()) for p in deny_globs)


def resolve_in_repo(root: Path, rel: str, deny_globs: tuple[str, ...]) -> tuple[Path, str]:
    """Resolve `rel` inside `root`. Returns (absolute_path, repo_relative_posix_path)."""
    if not isinstance(rel, str) or not rel.strip() or "\x00" in rel:
        raise GuardError(INVALID_ARGUMENT, "path must be a non-empty relative path")
    candidate = rel.strip().replace("\\", "/")
    if candidate.startswith("/") or re.match(r"^[A-Za-z]:", candidate) or candidate.startswith("~"):
        raise GuardError(OUTSIDE_REPO, f"absolute paths are not allowed: {rel!r}")
    root_real = root.resolve()
    target = (root_real / candidate).resolve()
    try:
        rel_posix = target.relative_to(root_real).as_posix()
    except ValueError:
        raise GuardError(OUTSIDE_REPO, f"{rel!r} resolves outside the repository") from None
    # Check the name the agent asked for *and* what it resolved to (a symlink can rename a secret).
    if is_denied(candidate, deny_globs) or is_denied(rel_posix, deny_globs):
        raise GuardError(SECRET_PATH, f"{rel!r} matches a protected-file rule")
    return target, rel_posix


def read_text_file(path: Path, max_bytes: int) -> str:
    if not path.exists():
        raise GuardError(NOT_FOUND, "file does not exist")
    if not path.is_file():
        raise GuardError(INVALID_ARGUMENT, "path is a directory; use search_code or list files via repo_status")
    size = path.stat().st_size
    if size > max_bytes:
        raise GuardError(TOO_LARGE, f"file is {size} bytes; limit is {max_bytes}")
    data = path.read_bytes()
    if b"\x00" in data[:8192]:
        raise GuardError(BINARY_FILE, "binary files are not returned")
    return data.decode("utf-8", errors="replace")
