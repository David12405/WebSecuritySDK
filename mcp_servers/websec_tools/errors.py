"""Shared error and envelope helpers for the standalone L6 tools."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any


STABLE_ERROR_CODES = frozenset(
    {
        "E_INVALID_TARGET",
        "E_CONNECT",
        "E_TIMEOUT",
        "E_TLS",
        "E_REDIRECT_LOOP",
        "E_HTTP",
        "E_INTERNAL",
        "E_INVALID_ARGUMENT",
        "E_TOOL_UNAVAILABLE",
        "E_TOOL_FAILED",
        "E_PARSE",
        "E_UNSUPPORTED_INPUT",
        "E_SCOPE",
    }
)


@dataclass(slots=True)
class ToolError(Exception):
    """An expected, safe error that can be exposed by an L6 tool."""

    code: str
    message: str

    def __post_init__(self) -> None:
        if self.code not in STABLE_ERROR_CODES:
            self.code = "E_INTERNAL"
            self.message = "tool failed"
        Exception.__init__(self, self.message)

    @property
    def public_message(self) -> str:
        return f"{self.code}: {self.message}"


def envelope(summary: str, data: dict[str, Any], truncated: bool = False) -> dict[str, Any]:
    """Build the common structured response shape."""

    return {"summary": summary, "data": data, "truncated": bool(truncated)}


def safe_message(exc: BaseException, fallback: str = "tool failed") -> str:
    """Return a short message without exposing arbitrary subprocess/API details."""

    message = str(exc).replace("\r", " ").replace("\n", " ").strip()
    if not message:
        return fallback
    return message[:256]
