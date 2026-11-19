from pathlib import Path

import pytest
from workspace import FAKE_STRIPE

from foreman.errors import BINARY_FILE, OUTSIDE_REPO, SECRET_PATH, TOO_LARGE, GuardError
from foreman.guard import baseline_env, is_denied, read_text_file, redact, resolve_in_repo, scrub_env
from foreman.policy import DEFAULT_DENY_GLOBS


@pytest.mark.parametrize(
    "text,kind",
    [
        ("AKIA" + "ABCDEFGHIJKLMNOP", "aws-key"),
        ("ghp_" + "a" * 36, "github-token"),
        ("github_pat_" + "B" * 50, "github-token"),
        (FAKE_STRIPE, "stripe-key"),
        ("whsec_" + "c" * 24, "stripe-webhook"),
        ("sk-ant-" + "d" * 30, "anthropic-key"),
        ("sk-proj-" + "e" * 30, "openai-key"),
        ("AIza" + "f" * 35, "google-key"),
        ("xoxb-" + "1234567890-abc", "slack-token"),
        ("eyJ" + "g" * 10 + ".eyJ" + "h" * 10 + "." + "i" * 10, "jwt"),
        ("-----" + "BEGIN RSA PRIV" + "ATE KEY-----\nabc\n-----" + "END RSA PRIV" + "ATE KEY-----", "private-key"),
    ],
)
def test_redacts_known_token_formats(text, kind):
    clean, n = redact(f"before {text} after")
    assert n == 1
    assert f"[REDACTED:{kind}]" in clean
    assert "before" in clean and "after" in clean


@pytest.mark.parametrize("line", ['password = "hunter2hunter2"', "API_KEY: abcdefgh12345", "client_secret=xyz12345678"])
def test_redacts_generic_assignments_but_keeps_the_key_name(line):
    clean, n = redact(line)
    assert n == 1 and "[REDACTED:assignment]" in clean
    assert clean.split("[")[0].strip().rstrip("=:\"' ")  # the variable name survives for context


def test_redaction_leaves_ordinary_code_alone():
    code = "def greet(name):\n    return f'Hello, {name}!'\nkey = cache_key(user)\n"
    assert redact(code) == (code, 0)


def test_scrub_env_drops_credentials_and_keeps_essentials():
    env = {"PATH": "/bin", "GITHUB_TOKEN": "x", "AWS_SECRET_ACCESS_KEY": "y", "DB_PASSWORD": "z",
           "STRIPE_API_KEY": "w", "HOME": "/home/w", "EDITOR": "vim"}
    clean = scrub_env(env)
    assert {"PATH", "HOME", "EDITOR"} <= set(clean)
    assert not {"GITHUB_TOKEN", "AWS_SECRET_ACCESS_KEY", "DB_PASSWORD", "STRIPE_API_KEY"} & set(clean)
    assert "GITHUB_TOKEN" in scrub_env(env, passthrough=("GITHUB_TOKEN",))


@pytest.mark.parametrize("path", [".env", "app/.env.local", "certs/server.pem", ".git/config", "deploy/prod.tfstate",
                                  "home/.npmrc", "id_rsa", "id_ed25519.pub", "config/credentials.json", ".ENV"])
def test_denied_paths(path):
    assert is_denied(path, DEFAULT_DENY_GLOBS)


@pytest.mark.parametrize("path", ["src/env.py", "docs/keys.md", "environment.yml", "src/token_utils.py", "README.md"])
def test_ordinary_paths_allowed(path):
    assert not is_denied(path, DEFAULT_DENY_GLOBS)


REFUSALS = [("../x", OUTSIDE_REPO), ("a/../../x", OUTSIDE_REPO), ("/etc/passwd", OUTSIDE_REPO),
            ("C:/Windows/win.ini", OUTSIDE_REPO), ("~/.ssh/id_rsa", OUTSIDE_REPO),
            ("src/../.env", SECRET_PATH), (".git/HEAD", SECRET_PATH)]


@pytest.mark.parametrize("rel,code", REFUSALS)
def test_resolve_refuses(tmp_path: Path, rel, code):
    with pytest.raises(GuardError) as err:
        resolve_in_repo(tmp_path, rel, DEFAULT_DENY_GLOBS)
    assert err.value.code == code


def test_resolve_accepts_normal_paths(tmp_path: Path):
    (tmp_path / "src").mkdir()
    target, rel = resolve_in_repo(tmp_path, "src\\..\\src\\app.py", DEFAULT_DENY_GLOBS)
    assert rel == "src/app.py" and target == (tmp_path / "src" / "app.py").resolve()


def test_read_text_file_limits(tmp_path: Path):
    big = tmp_path / "big.txt"
    big.write_text("x" * 2000)
    with pytest.raises(GuardError) as err:
        read_text_file(big, 1000)
    assert err.value.code == TOO_LARGE
    binary = tmp_path / "b.bin"
    binary.write_bytes(b"\x00\x01\x02")
    with pytest.raises(GuardError) as err:
        read_text_file(binary, 1000)
    assert err.value.code == BINARY_FILE


def test_baseline_env_fills_only_missing_standard_folders():
    import sys

    minimal = {"PATH": "x", "SYSTEMDRIVE": "D:", "SYSTEMROOT": "D:\\Windows", "TEMP": "t"}
    out = baseline_env(minimal)
    if sys.platform == "win32":
        assert out["ProgramFiles"] == "D:\\Program Files" and out["ProgramData"] == "D:\\ProgramData"
        assert out["TMP"] == "t"
    assert out["PATH"] == "x"  # never overrides what the client passed
    assert baseline_env({"PATH": "y", "ProgramFiles": "E:\\PF"}).get("ProgramFiles", "E:\\PF") == "E:\\PF"
