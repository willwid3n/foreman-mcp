"""Stable error codes. Agents and the eval suite match on the code prefix, never on prose."""

from __future__ import annotations

OUTSIDE_REPO = "OUTSIDE_REPO"
SECRET_PATH = "SECRET_PATH"
NOT_FOUND = "NOT_FOUND"
TOO_LARGE = "TOO_LARGE"
BINARY_FILE = "BINARY_FILE"
UNKNOWN_REPO = "UNKNOWN_REPO"
UNKNOWN_CHECK = "UNKNOWN_CHECK"
INVALID_ARGUMENT = "INVALID_ARGUMENT"
BUDGET_EXCEEDED = "BUDGET_EXCEEDED"
TIMEOUT = "TIMEOUT"
WRITES_DISABLED = "WRITES_DISABLED"
NOT_APPROVED = "NOT_APPROVED"
ALREADY_EXECUTED = "ALREADY_EXECUTED"
TAMPERED = "TAMPERED"
UNKNOWN_ACTION = "UNKNOWN_ACTION"
GH_UNAVAILABLE = "GH_UNAVAILABLE"
COMMAND_FAILED = "COMMAND_FAILED"


class GuardError(Exception):
    """A request Foreman refuses or cannot complete. `code` is one of the constants above."""

    def __init__(self, code: str, message: str):
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message
