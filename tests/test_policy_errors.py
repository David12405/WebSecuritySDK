"""Reading an `E_*` code off a tool failure, and classifying it.

The tools themselves are the partner's, tested in `test_l6_*.py`. What is
tested here is our side of the seam: that a failure crossing from Layer 6
into the policy layer keeps a code we recognise, and that the code decides
retry the way the contract says.
"""

from __future__ import annotations

import pytest

from mcp_servers.websec_tools.errors import STABLE_ERROR_CODES
from websecuritycheck.policy.errors import (
    ERROR_CODES,
    ToolCallError,
    code_of,
    is_retryable,
    message_of,
)

# --------------------------------------------------------------------------
# The two tables have to agree
# --------------------------------------------------------------------------


def test_every_code_the_tools_emit_is_classified() -> None:
    """The seam between the tool layer and the policy layer.

    A code the server emits and this table has never heard of is demoted to
    `E_INTERNAL` and never retried - so `E_TOOL_UNAVAILABLE`, meaning "ZAP
    is not up yet", would be treated as a permanent failure.
    """
    assert set(ERROR_CODES) >= STABLE_ERROR_CODES


def test_the_sdk_adds_only_codes_the_tools_cannot_raise() -> None:
    """Our extras are failures of the SDK, not of a tool, so the server has no use for them."""
    assert set(ERROR_CODES) - STABLE_ERROR_CODES == {
        "E_SERVER_UNAVAILABLE",
        "E_TOOL_MISSING",
    }


# --------------------------------------------------------------------------
# Reading the code
# --------------------------------------------------------------------------


def test_the_code_survives_the_sdk_prefix() -> None:
    """The MCP SDK prefixes every tool error, so the code is not first.

    This is the contract amendment in `policy/errors.py`: the text contains
    the code rather than beginning with it.
    """
    text = "Error executing tool get_tls_info: E_TIMEOUT: handshake timed out after 10.0s"
    assert code_of(text) == "E_TIMEOUT"
    assert message_of(text) == "handshake timed out after 10.0s"


def test_a_bare_code_still_reads() -> None:
    assert code_of("E_CONNECT: getaddrinfo failed") == "E_CONNECT"


@pytest.mark.parametrize("code", sorted(ERROR_CODES))
def test_every_declared_code_is_recognised(code: str) -> None:
    assert code_of(f"Error executing tool t: {code}: something happened") == code


def test_an_invented_code_is_not_guessed_at() -> None:
    """A server emitting `E_RATELIMIT` has left the contract; hiding that helps nobody."""
    assert code_of("E_RATELIMIT: slow down") == "E_INTERNAL"
    assert not is_retryable(code_of("E_RATELIMIT: slow down"))


def test_text_with_no_code_is_internal_and_terminal() -> None:
    """Safe direction: a failure nobody can classify is not one to repeat."""
    assert code_of("something went wrong") == "E_INTERNAL"
    assert not is_retryable("E_INTERNAL")


def test_a_code_is_matched_as_a_whole_word() -> None:
    assert code_of("E_TIMEOUT_MS was 10000") == "E_INTERNAL"


# --------------------------------------------------------------------------
# Classifying it
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "code", ["E_TIMEOUT", "E_CONNECT", "E_HTTP", "E_TOOL_UNAVAILABLE", "E_TOOL_FAILED"]
)
def test_transient_failures_are_retryable(code: str) -> None:
    assert is_retryable(code)


@pytest.mark.parametrize(
    "code", ["E_INVALID_TARGET", "E_TLS", "E_PARSE", "E_INVALID_ARGUMENT", "E_UNSUPPORTED_INPUT"]
)
def test_terminal_failures_are_not(code: str) -> None:
    assert not is_retryable(code)


def test_a_tool_that_is_not_up_yet_gets_a_second_chance() -> None:
    """`E_TOOL_UNAVAILABLE` is the reason this table had to be widened.

    nmap, ZAP and WhatWeb are external processes. "Not started yet" is a
    different statement from "will never work", and only the second one
    deserves to end the check.
    """
    assert is_retryable("E_TOOL_UNAVAILABLE")
    assert not is_retryable("E_UNSUPPORTED_INPUT")


def test_tool_call_error_carries_the_classification() -> None:
    error = ToolCallError.from_text(
        "Error executing tool get_cookies: E_TIMEOUT: timed out", tool="get_cookies"
    )
    assert error.code == "E_TIMEOUT"
    assert error.retryable
    assert str(error) == "timed out"
    assert error.tool == "get_cookies"
