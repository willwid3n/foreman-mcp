"""Command line: run the server, and the human side of approvals and auditing."""

from __future__ import annotations

import argparse
import getpass
import json
import os
import sys
from pathlib import Path

from foreman import __version__
from foreman.approvals import ApprovalStore
from foreman.errors import GuardError
from foreman.policy import load_policy
from foreman.telemetry import load_audit, summarize


def _policy_path(arg: str | None) -> Path:
    return Path(arg or os.environ.get("FOREMAN_POLICY") or "foreman.toml")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(prog="foreman", description="Least-privilege MCP server for coding agents.")
    parser.add_argument("--policy", help="path to foreman.toml (default: $FOREMAN_POLICY or ./foreman.toml)")
    parser.add_argument("--version", action="version", version=f"foreman {__version__}")
    sub = parser.add_subparsers(dest="cmd", required=True)
    sub.add_parser("serve", help="run the MCP server over stdio")
    sub.add_parser("check-policy", help="validate the policy and print a summary")
    sub.add_parser("pending", help="list actions waiting for a human decision")
    p_ok = sub.add_parser("approve", help="approve a pending action")
    p_ok.add_argument("id")
    p_no = sub.add_parser("deny", help="deny a pending action")
    p_no.add_argument("id")
    p_no.add_argument("--note", default="")
    p_audit = sub.add_parser("audit", help="print the most recent audit records")
    p_audit.add_argument("--tail", type=int, default=20)
    sub.add_parser("report", help="usage report across all sessions in the audit log")
    args = parser.parse_args(argv)

    try:
        policy = load_policy(_policy_path(args.policy))
    except (GuardError, FileNotFoundError) as err:
        print(f"foreman: {err}", file=sys.stderr)
        return 2

    if args.cmd == "serve":
        from foreman.server import build_server

        server, _ = build_server(policy)
        server.run("stdio")
        return 0

    store = ApprovalStore(policy.state_dir)
    if args.cmd == "check-policy":
        summary = {
            "repos": {n: {"root": str(r.root), "checks": sorted(r.checks), "github": r.github}
                      for n, r in policy.repos.items()},
            "allow_writes": policy.allow_writes,
            "state_dir": str(policy.state_dir),
            "limits": policy.limits.__dict__,
        }
        print(json.dumps(summary, indent=2))
    elif args.cmd == "pending":
        items = store.list("pending")
        if not items:
            print("No pending actions.")
        for a in items:
            print(f"{a['id']}  {a['kind']:<13} {a['repo']:<20} {json.dumps(a['params'])[:120]}")
            print(f"          reason: {a['reason']}")
    elif args.cmd in ("approve", "deny"):
        try:
            rec = store.decide(args.id, approve=args.cmd == "approve", by=getpass.getuser(),
                               note=getattr(args, "note", ""))
        except GuardError as err:
            print(f"foreman: {err}", file=sys.stderr)
            return 1
        print(f"{rec['id']} {rec['status']} by {rec['decided_by']}: {rec['kind']} {json.dumps(rec['params'])}")
    elif args.cmd == "audit":
        for rec in load_audit(policy.state_dir)[-args.tail:]:
            status = "ok " if rec["ok"] else f"DENY {rec['error_code']}"
            print(f"{rec['ts']}  {rec['session']}  {rec['tool']:<15} {status:<22} {rec['duration_ms']:>8} ms  "
                  f"{json.dumps(rec['args'])[:100]}")
    elif args.cmd == "report":
        print(json.dumps(summarize(load_audit(policy.state_dir)), indent=2))
    return 0
