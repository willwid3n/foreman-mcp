# Foreman

**A least-privilege MCP server that gives coding agents audited, budgeted access to your repositories, tests and CI, with a human approval step for anything that writes.**

Coding agents such as Claude Code, Codex and Hermes are most useful when they can read the code, run the tests and check CI. They are most dangerous when that access is a raw shell. Foreman sits between the two.

- Through MCP the agent gets eleven narrow tools.
- The *policy* decides which repositories exist, which commands count as "the tests", what the agent may never read, and how much it may do in a session.
- Every call lands in an audit log, whether it was allowed or refused.

```
agent ──MCP/stdio──▶ Foreman ──▶ policy check ──▶ sandboxed path / named command / gh (read-only)
                        │                              │
                        ├── redaction of every result ◀┘
                        ├── audit.jsonl + usage telemetry + budgets
                        └── approvals.json ◀── human: `foreman approve <id>`
```

## Tools

| Tool | What it does | MCP annotations |
|---|---|---|
| `list_repos` | Lists the repositories in policy, their approved checks, and whether writes are enabled | read-only |
| `repo_status` | Reports the branch, HEAD, ahead/behind, uncommitted files, local branches and last 5 commits | read-only |
| `list_files` | Lists tracked and untracked (non-ignored) files, with an optional sub-folder or glob | read-only |
| `read_file` | Returns line-numbered text, with an optional line range | read-only |
| `search_code` | Searches with ripgrep, falling back to pure Python. Supports literal or regex queries, a glob filter and a time budget | read-only |
| `run_check` | Runs a **named** check from policy (tests, lint, build) and returns the exit code and the tail of the output | not read-only, idempotent |
| `ci_runs` | Lists recent GitHub Actions runs via `gh` | read-only, open-world |
| `request_action` | Asks for a write: `git_branch` or `github_issue` | not idempotent |
| `action_status` | Reports whether an action is pending, approved, denied or executed | read-only |
| `execute_action` | Runs a human-approved action exactly once | open-world |
| `usage_report` | Reports calls, errors, denials by code, p50/p95 latency, redactions and remaining budget | read-only |

Resource: `foreman://repos/{name}/agents` serves the repo's `AGENTS.md` (or `CLAUDE.md`), so the agent can read the house rules before it touches anything.

## Security model

1. **Allow-listed execution, no shell.** A check is a fixed argv list in policy, for example `test = [".venv/Scripts/python.exe", "-m", "pytest", "-q"]`. The agent picks a check *by name*, so `"test; curl evil"` is just an unknown name.
2. **Path sandbox.** Every path is resolved, symlinks included, and must stay inside the repo root.
   - Protected files are refused by name *and* by resolved target: `.env*`, keys and certificates, `.git/`, `.npmrc`, `.pypirc`, `.netrc`, `*.tfstate` and `credentials*`, plus any globs you add.
   - Absolute paths, `~` and `..` escapes are refused.
3. **Redaction everywhere.** Results, the audit log and the approval queue are scrubbed of credential formats:
   - private keys
   - AWS keys
   - GitHub tokens
   - Stripe keys and webhook secrets
   - Anthropic, OpenAI and Google keys
   - Slack tokens
   - JWTs
   - generic `password=` / `api_key:` assignments
4. **Clean child processes.**
   - Checks run with credential-looking environment variables removed.
   - If the client launched Foreman with a stripped environment, a standard non-secret OS baseline (such as `ProgramFiles`) is restored.
   - `stdin` is null, so a child process can never read the MCP protocol stream.
5. **Budgets.**
   - Calls and output are limited per session.
   - Each check has a timeout.
   - Search has a time budget and returns partial results instead of hanging.
6. **Human-in-the-loop writes.**
   - The agent can only *request* a write. A human approves it from the CLI.
   - Parameters are SHA-256 digested at request time, so editing the queue after approval is detected (`TAMPERED`).
   - An approved action runs only once (`ALREADY_EXECUTED`).
   - A read-only policy (`allow_writes = false`) refuses requests outright.
7. **Stable error codes.** Every refusal starts with a code such as `SECRET_PATH`, `OUTSIDE_REPO`, `UNKNOWN_CHECK`, `NOT_APPROVED` or `BUDGET_EXCEEDED`. The server instructions tell the agent these are final.

## Evaluation

`evals/run_evals.py` builds a throwaway workspace of fixture repos. The workspace contains:
- planted fake credentials, a `.env` and a private key
- a symlink to the secret
- binary and oversized files
- vendored noise
- a fake `gh`

It then drives the real server **over stdio, the same way an agent connects**. The 62 scenarios fall into six categories: capability, secrets, sandbox, execution, approvals and telemetry. Multi-step flows cover:
- the approval lifecycle, queue tampering and replay
- a read-only policy and call budgets
- scanning the audit log for secrets
- launching Foreman with the MCP SDK's minimal client environment

The fake secrets are assembled at runtime, so no scanner-tripping literal exists in the source.

```
$ python evals/run_evals.py
...
  approvals   13 passed, 0 failed, 0 skipped
  capability  13 passed, 0 failed, 0 skipped
  execution   8 passed, 0 failed, 0 skipped
  sandbox     11 passed, 0 failed, 0 skipped
  secrets     13 passed, 0 failed, 0 skipped
  telemetry   4 passed, 0 failed, 0 skipped

62/62 scenarios passed (100%), 0 skipped, 12.2s on win32
```

There are also 67 unit tests (`pytest -q`). The CI workflow runs lint, the unit tests and the eval suite on Ubuntu and Windows. Ubuntu exercises the ripgrep engine; Windows exercises the Python fallback and Windows path handling. Each run uploads the JSON scorecard as an artifact, and a guardrail regression fails the build.

### Bugs the evals and live runs caught during development
| Finding | Fix |
|---|---|
| The pure-Python search fallback followed a symlink to `.env` and returned its contents | Skip symlinks; re-check every hit against its *resolved* target |
| Child processes inherited the server's stdin, which is the JSON-RPC pipe | `stdin=DEVNULL` for every subprocess, plus the `exec.stdin-isolated-from-protocol` eval |
| `dotnet build` failed only when an MCP client launched it, with NuGet reporting `Value cannot be null (path1)`. The cause: clients pass a minimal environment that lacks `ProgramFiles` | Restore a non-secret OS baseline for checks. An eval now launches Foreman with the SDK's default client environment |
| Searching a game repo with ~100k files on disk timed out at 60 s | Stream results under a time budget, return partial results flagged `timed_out`, and add per-repo `exclude` globs. The same search now takes about 2.5 s |

## Live run against real repositories (19 Nov 2026, Windows 11)

`scripts/live_smoke.py`, over stdio:

| Call | Result |
|---|---|
| `repo_status` on a Godot game repo (13,404 tracked files) | Branch, HEAD, 192 uncommitted files and last commit, in 0.44 s |
| `search_code` on the same repo | 5 hits in 2.5 s with `exclude = ["tmp/**", ...]` |
| `run_check granite-rag test` / `lint` | 22 tests passed; ruff clean |
| `run_check james-brandel build` | The .NET 10 solution built through the stdio server in 4.1 s |
| `ci_runs granite-rag` | The last runs on `main` succeeded |
| `read_file granite-rag .env` | Refused with `SECRET_PATH`; 0 characters returned |

**With a real agent:** a headless Claude Code 2.1.318 session verified the Granite RAG repo end to end. The session used `--strict-mcp-config` and was restricted to `mcp__foreman__*` tools. It:
1. read the agent rules
2. reported the branch and HEAD
3. ran the tests (22 passed) and lint
4. read the last 2 CI runs
5. was refused `.env` with `SECRET_PATH`, and did not retry
6. reported its own usage: 7 tool calls, 1 denial and 293 calls remaining

The audit log shows the same calls plus the resource read.

## Quick start

```bash
uv venv --python 3.12 .venv && uv pip install --python .venv/Scripts/python.exe -e ".[dev]"
cp foreman.example.toml foreman.toml        # edit repos, checks, limits
.venv/Scripts/python.exe -m foreman check-policy
```

**Claude Code:** `claude mcp add foreman -- <path>/.venv/Scripts/python.exe -m foreman --policy <path>/foreman.toml serve`
(or for a one-off session: `claude -p "..." --mcp-config examples/claude-code.mcp.json --strict-mcp-config`)

**Codex** (`~/.codex/config.toml`):
```toml
[mcp_servers.foreman]
command = "C:/path/to/foreman-mcp/.venv/Scripts/python.exe"
args = ["-m", "foreman", "--policy", "C:/path/to/foreman-mcp/foreman.toml", "serve"]
```

**The human side:**
```bash
foreman pending                 # what agents are asking to do
foreman approve 3f9a1c2e        # or: foreman deny 3f9a1c2e --note "not on main"
foreman audit --tail 20         # every call, allowed or refused
foreman report                  # usage across sessions: calls, errors, p50/p95, denials by code
```

## Limits (by design, for now)
- Checks run as your user, so the allow-list *is* the control. For untrusted repos, run Foreman inside a container or VM.
- Redaction is pattern-based defence in depth, not a data-loss-prevention guarantee. The real protection is that protected files are never read.
- The approval queue is a local file, so it supports a single host and a single human.
- A timed-out check kills its direct child process. Build servers that detach can outlive it.

## Development
See `AGENTS.md`. The definition of done is that `ruff check .`, `pytest -q` and `python evals/run_evals.py` all pass.

## License
MIT
