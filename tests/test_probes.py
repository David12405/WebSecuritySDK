"""The analysis half of the probes, and the error-code table.

No network. Everything here takes plain dicts, which is the reason the
probes keep `analyse_*` apart from `probe_*` in the first place - the
security knowledge is the half worth testing, and it does not need a socket.
"""

from __future__ import annotations

from datetime import UTC, datetime, timedelta

import pytest

from mcp_servers.websec_tools.probes import (
    PROBE_ORIGIN,
    SECURITY_HEADERS,
    analyse_cookies,
    analyse_cors,
    analyse_headers,
    parse_set_cookie,
)
from websecuritycheck.policy.errors import (
    ERROR_CODES,
    ToolCallError,
    code_of,
    is_retryable,
    message_of,
)

# --------------------------------------------------------------------------
# Headers
# --------------------------------------------------------------------------


def test_a_bare_response_is_missing_every_security_header() -> None:
    analysis = analyse_headers({"Content-Type": "text/html"})
    assert analysis["security_headers_missing"] == list(SECURITY_HEADERS)
    assert analysis["security_headers_present"] == {}


def test_header_names_are_matched_case_insensitively() -> None:
    """HTTP header names are case-insensitive, and servers disagree about case."""
    analysis = analyse_headers({"Strict-Transport-Security": "max-age=31536000"})
    assert "strict-transport-security" in analysis["security_headers_present"]
    assert "strict-transport-security" not in analysis["security_headers_missing"]


def test_disclosure_headers_are_reported_separately() -> None:
    """`Server: nginx/1.18.0` is not a missing security header; it is a different finding."""
    analysis = analyse_headers({"Server": "nginx/1.18.0", "X-Powered-By": "PHP/7.4"})
    assert analysis["information_disclosure"] == {
        "server": "nginx/1.18.0",
        "x-powered-by": "PHP/7.4",
    }
    assert "server" not in analysis["security_headers_missing"]


def test_the_reported_order_is_the_declared_order() -> None:
    """A report that leads with a legacy header reads badly."""
    missing = analyse_headers({})["security_headers_missing"]
    assert missing.index("strict-transport-security") < missing.index("referrer-policy")


# --------------------------------------------------------------------------
# Cookies
# --------------------------------------------------------------------------


def test_a_cookie_value_is_never_returned() -> None:
    """The rule this parser exists to enforce.

    A cookie value is a live session credential. A probe that returns one
    has handed the model something it can quote into a report by accident.
    """
    cookie = parse_set_cookie("sid=super-secret-session-token; Path=/; Secure")
    assert "super-secret-session-token" not in str(cookie)
    assert cookie["value_length"] == len("super-secret-session-token")


def test_cookie_attributes_are_parsed() -> None:
    cookie = parse_set_cookie(
        "sid=abc; Path=/app; Domain=myapp.com; Secure; HttpOnly; SameSite=Lax; Max-Age=3600"
    )
    assert cookie["name"] == "sid"
    assert cookie["secure"] and cookie["httponly"]
    assert cookie["samesite"] == "Lax"
    assert cookie["domain"] == "myapp.com"
    assert cookie["path"] == "/app"
    assert cookie["max_age"] == "3600"


def test_attribute_names_are_case_insensitive() -> None:
    assert parse_set_cookie("a=b; secure; httponly")["secure"]
    assert parse_set_cookie("a=b; SECURE; HTTPONLY")["httponly"]


def test_a_cookie_with_no_attributes_is_weak_on_every_count() -> None:
    weak = analyse_cookies([parse_set_cookie("sid=abc")], https=True)["weak_cookies"]
    assert len(weak["sid"]) == 3  # Secure, HttpOnly, SameSite


def test_secure_is_not_demanded_of_an_http_response() -> None:
    """On http the flag cannot help; demanding it would be noise, not a finding."""
    cookie = parse_set_cookie("sid=abc; HttpOnly; SameSite=Lax")
    assert analyse_cookies([cookie], https=False)["weak_cookies"] == {}
    assert "sid" in analyse_cookies([cookie], https=True)["weak_cookies"]


def test_samesite_none_without_secure_is_called_out() -> None:
    """Browsers reject the combination outright, so the cookie simply does not work."""
    cookie = parse_set_cookie("sid=abc; HttpOnly; SameSite=None")
    reasons = analyse_cookies([cookie], https=True)["weak_cookies"]["sid"]
    assert any("SameSite=None without Secure" in reason for reason in reasons)


def test_a_sound_cookie_is_not_reported() -> None:
    cookie = parse_set_cookie("sid=abc; Secure; HttpOnly; SameSite=Strict")
    assert analyse_cookies([cookie], https=True)["weak_cookies"] == {}


# --------------------------------------------------------------------------
# Certificate
# --------------------------------------------------------------------------


def test_certificate_fields_are_read(self_signed_cert) -> None:
    from mcp_servers.websec_tools.probes import analyse_certificate

    analysis = analyse_certificate(self_signed_cert)
    assert "myapp.com" in analysis["subject"]
    assert analysis["sans"] == ["myapp.com", "www.myapp.com"]
    assert not analysis["expired"]
    assert 28 <= analysis["expires_in_days"] <= 30


def test_an_expired_certificate_is_flagged(expired_cert) -> None:
    from mcp_servers.websec_tools.probes import analyse_certificate

    analysis = analyse_certificate(expired_cert)
    assert analysis["expired"]
    assert analysis["expires_in_days"] < 0


def test_expiry_is_measured_against_a_given_moment(self_signed_cert) -> None:
    """Pure, so a test does not depend on what day it runs."""
    from mcp_servers.websec_tools.probes import analyse_certificate

    later = datetime.now(UTC) + timedelta(days=40)
    assert analyse_certificate(self_signed_cert, now=later)["expired"]


# --------------------------------------------------------------------------
# CORS
# --------------------------------------------------------------------------


def test_no_cors_headers_means_no_cross_origin_reads() -> None:
    analysis = analyse_cors({}, {})
    assert analysis["allow_origin"] is None
    assert not analysis["wildcard"]
    assert not analysis["reflects_arbitrary_origin"]


def test_a_reflected_probe_origin_means_any_origin_is_trusted() -> None:
    """The point of sending an origin no target should be configured to trust."""
    analysis = analyse_cors({"Access-Control-Allow-Origin": PROBE_ORIGIN}, {})
    assert analysis["reflects_arbitrary_origin"]


def test_a_wildcard_with_credentials_is_singled_out() -> None:
    """Browsers refuse the combination, so the site is broken as well as wrong."""
    analysis = analyse_cors(
        {"Access-Control-Allow-Origin": "*", "Access-Control-Allow-Credentials": "true"}, {}
    )
    assert analysis["credentialed_wildcard"]


def test_a_wildcard_without_credentials_is_not() -> None:
    assert not analyse_cors({"Access-Control-Allow-Origin": "*"}, {})["credentialed_wildcard"]


def test_vary_origin_is_detected_however_it_is_written() -> None:
    assert analyse_cors({"Vary": "Accept-Encoding, Origin"}, {})["vary_includes_origin"]
    assert not analyse_cors({"Vary": "Accept-Encoding"}, {})["vary_includes_origin"]


def test_the_preflight_answer_is_reported() -> None:
    analysis = analyse_cors({}, {"Access-Control-Allow-Methods": "GET, POST"})
    assert analysis["preflight_allow_methods"] == "GET, POST"


# --------------------------------------------------------------------------
# The error-code table
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


def test_transient_failures_are_retryable_and_terminal_ones_are_not() -> None:
    assert is_retryable("E_TIMEOUT") and is_retryable("E_CONNECT")
    assert not is_retryable("E_INVALID_TARGET") and not is_retryable("E_TLS")


def test_tool_call_error_carries_the_classification() -> None:
    error = ToolCallError.from_text(
        "Error executing tool get_cookies: E_TIMEOUT: timed out", tool="get_cookies"
    )
    assert error.code == "E_TIMEOUT"
    assert error.retryable
    assert str(error) == "timed out"
    assert error.tool == "get_cookies"
