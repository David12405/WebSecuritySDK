"""The stable `E_*` code table, and how to read one off a tool failure.

A failure has to be classifiable without reading prose: the retry hook
decides whether to try again, and "did this fail in a way worth retrying"
cannot depend on matching an English sentence that a tool author may
reword.

**The contract said "the text begins with the code". It cannot.** The MCP
SDK prefixes every tool error with `Error executing tool <name>: `, even for
a deliberate `ToolError` whose message the server chose. So the rule that
actually holds is the weaker one implemented here: the text *contains* the
code as a word, and `code_of` finds the first one. See `docs/ARCHITECTURE.md`
section 5.3 - this is a contract amendment the partner has to confirm.

The weaker rule is still strong enough. `E_TIMEOUT` is not a word that
appears in prose by accident, and a tool that does not emit one at all is
classified `E_INTERNAL` - unretryable - which is the safe direction: a
failure nobody can classify is not one to repeat.
"""

from __future__ import annotations

import re

#: code -> retry?
#:
#: The server half must stay equal to `mcp_servers.websec_tools.errors
#: .STABLE_ERROR_CODES`, which is the tool layer's own list and the one a
#: partner's server is written against. A test asserts the two agree, because
#: a code the server emits and this table has never heard of is silently
#: demoted to `E_INTERNAL` - unretryable - and a ZAP that was merely not
#: started yet never gets a second chance.
ERROR_CODES: dict[str, bool] = {
    # Transport, declared in ARCHITECTURE.md section 5.3
    "E_INVALID_TARGET": False,  # not a URL, wrong scheme, https-only tool on http
    "E_CONNECT": True,  # DNS or TCP failure
    "E_TIMEOUT": True,  # exceeded the tool timeout
    "E_TLS": False,  # handshake failed
    "E_REDIRECT_LOOP": False,  # more than the declared redirect limit
    "E_HTTP": True,  # other transport-level HTTP error
    "E_INTERNAL": False,  # bug in the tool
    # The recon tools, which shell out to nmap, ZAP and WhatWeb. Added with
    # the Layer 6 tools; the split below is what the retry hook acts on.
    "E_TOOL_UNAVAILABLE": True,  # the binary or daemon is not up *yet*
    "E_TOOL_FAILED": True,  # the subprocess died part-way
    "E_PARSE": False,  # a malformed document parses the same way twice
    "E_INVALID_ARGUMENT": False,  # the caller's mistake
    "E_UNSUPPORTED_INPUT": False,  # likewise
    # Raised by this SDK rather than by a tool.
    "E_SERVER_UNAVAILABLE": True,  # MCP server did not start
    "E_TOOL_MISSING": False,  # a check declares a tool no server provides
}

#: What a code looks like. Matched as a whole word so `E_TIMEOUT_MS` in some
#: unrelated sentence cannot be mistaken for `E_TIMEOUT`.
CODE_PATTERN = re.compile(r"\bE_[A-Z][A-Z_]*\b")

UNKNOWN_CODE = "E_INTERNAL"


def code_of(text: str) -> str:
    """The first contract code in `text`, or `E_INTERNAL` if there is none.

    Unknown `E_*` spellings are *not* accepted. A server that invents
    `E_RATELIMIT` has stepped outside the contract, and guessing what it
    meant would hide that; it is reported as an internal error, which is
    unretryable and visible.
    """
    for match in CODE_PATTERN.finditer(text or ""):
        if match.group() in ERROR_CODES:
            return match.group()
    return UNKNOWN_CODE


def is_retryable(code: str) -> bool:
    """Should a failure with this code be tried again?

    Unknown codes are not retryable. Repeating a call that failed for a
    reason nobody understands spends the target's bandwidth and the
    developer's money to learn nothing.
    """
    return ERROR_CODES.get(code, False)


def message_of(text: str) -> str:
    """Just the human half of a failure.

    Strips the SDK's `Error executing tool <name>: ` prefix and the code
    that follows it. `code_of` already reports the code, and an
    `ErrorInfo` that repeats it in `message` reads like a stutter in every
    report it reaches.
    """
    stripped = re.sub(r"^Error executing tool [\w.-]+:\s*", "", (text or "").strip())
    return re.sub(r"^E_[A-Z][A-Z_]*:\s*", "", stripped)


# --------------------------------------------------------------------------
# Internal exceptions
# --------------------------------------------------------------------------


class WebSecurityCheckError(Exception):
    """Base class, so a caller can catch everything this SDK raises."""


class ScopeViolationError(WebSecurityCheckError):
    """A call was refused because its target is outside the developer's scope."""


class ToolCallError(WebSecurityCheckError):
    """A tool failed. Carries the contract code so the retry hook can classify it."""

    def __init__(self, message: str, code: str = UNKNOWN_CODE, tool: str | None = None) -> None:
        super().__init__(message)
        self.code = code
        self.tool = tool

    @classmethod
    def from_text(cls, text: str, tool: str | None = None) -> ToolCallError:
        return cls(message_of(text), code_of(text), tool)

    @property
    def retryable(self) -> bool:
        return is_retryable(self.code)


class OutputValidationError(WebSecurityCheckError):
    """The model's structured output did not match the schema, N times."""
