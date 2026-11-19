"""Audit log, usage telemetry and per-session budgets.

Every tool call - allowed or denied - becomes one JSON line in `<state_dir>/audit.jsonl`
(arguments redacted). The same records drive the budget and the usage report, so what the
agent sees in `usage_report` is exactly what a human sees in the audit file.
"""

from __future__ import annotations

import json
import math
import uuid
from collections import Counter, defaultdict
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from foreman.errors import BUDGET_EXCEEDED, GuardError
from foreman.guard import redact
from foreman.policy import Limits


def _clip_args(args: dict[str, Any]) -> dict[str, Any]:
    clipped: dict[str, Any] = {}
    for key, value in args.items():
        text = value if isinstance(value, str) else json.dumps(value, default=str)
        text, _ = redact(text)
        clipped[key] = text if len(text) <= 300 else text[:300] + "...[clipped]"
    return clipped


def percentile(values: list[float], pct: float) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    k = max(0, math.ceil(pct / 100 * len(ordered)) - 1)
    return round(ordered[k], 1)


@dataclass
class Ledger:
    state_dir: Path
    limits: Limits
    session_id: str = field(default_factory=lambda: uuid.uuid4().hex[:12])
    calls: int = 0
    output_chars: int = 0
    _records: list[dict[str, Any]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.state_dir.mkdir(parents=True, exist_ok=True)
        self.audit_path = self.state_dir / "audit.jsonl"

    def check_budget(self) -> None:
        if self.calls >= self.limits.max_calls:
            raise GuardError(BUDGET_EXCEEDED, f"session call budget of {self.limits.max_calls} is used up")
        if self.output_chars >= self.limits.max_session_output_chars:
            raise GuardError(
                BUDGET_EXCEEDED, f"session output budget of {self.limits.max_session_output_chars} chars is used up"
            )

    def record(
        self,
        tool: str,
        args: dict[str, Any],
        *,
        ok: bool,
        duration_ms: float,
        out_chars: int = 0,
        error_code: str | None = None,
        redactions: int = 0,
    ) -> dict[str, Any]:
        self.calls += 1
        self.output_chars += out_chars
        entry = {
            "ts": datetime.now(UTC).isoformat(timespec="milliseconds"),
            "session": self.session_id,
            "tool": tool,
            "repo": args.get("repo"),
            "args": _clip_args(args),
            "ok": ok,
            "error_code": error_code,
            "duration_ms": round(duration_ms, 1),
            "out_chars": out_chars,
            "redactions": redactions,
        }
        self._records.append(entry)
        with self.audit_path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(entry) + "\n")
        return entry

    def report(self) -> dict[str, Any]:
        return summarize(self._records, self.limits, self.calls, self.output_chars, self.session_id)


def summarize(
    records: list[dict[str, Any]],
    limits: Limits | None = None,
    calls: int | None = None,
    output_chars: int | None = None,
    session_id: str | None = None,
) -> dict[str, Any]:
    by_tool: dict[str, dict[str, Any]] = {}
    durations: dict[str, list[float]] = defaultdict(list)
    counts: Counter[str] = Counter()
    errors: Counter[str] = Counter()
    chars: Counter[str] = Counter()
    denials: Counter[str] = Counter()
    redactions = 0
    for r in records:
        tool = r["tool"]
        counts[tool] += 1
        durations[tool].append(r.get("duration_ms", 0.0))
        chars[tool] += r.get("out_chars", 0)
        redactions += r.get("redactions", 0)
        if not r.get("ok"):
            errors[tool] += 1
            denials[r.get("error_code") or "UNKNOWN"] += 1
    for tool in sorted(counts):
        by_tool[tool] = {
            "calls": counts[tool],
            "errors": errors[tool],
            "p50_ms": percentile(durations[tool], 50),
            "p95_ms": percentile(durations[tool], 95),
            "out_chars": chars[tool],
        }
    report: dict[str, Any] = {
        "calls": len(records) if calls is None else calls,
        "errors": sum(errors.values()),
        "redactions": redactions,
        "denials_by_code": dict(denials.most_common()),
        "tools": by_tool,
    }
    if session_id:
        report["session"] = session_id
    if limits is not None:
        used_calls = report["calls"]
        used_chars = sum(chars.values()) if output_chars is None else output_chars
        report["budget"] = {
            "calls_used": used_calls,
            "calls_limit": limits.max_calls,
            "calls_remaining": max(0, limits.max_calls - used_calls),
            "output_chars_used": used_chars,
            "output_chars_limit": limits.max_session_output_chars,
        }
    return report


def load_audit(state_dir: Path) -> list[dict[str, Any]]:
    path = state_dir / "audit.jsonl"
    if not path.exists():
        return []
    out = []
    for line in path.read_text(encoding="utf-8").splitlines():
        if line.strip():
            try:
                out.append(json.loads(line))
            except json.JSONDecodeError:
                continue
    return out
