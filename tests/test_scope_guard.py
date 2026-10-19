"""The six scope rules, their order, and the tool allowlist.

No network, no model. Rule numbers refer to ARCHITECTURE.md section 6.
"""

from __future__ import annotations

import pytest

from websecuritycheck.memory.context import FRAMEWORK_TOOLS, framework_tools_for
from websecuritycheck.policy.scope_guard import (
    MAX_QUOTED_CHARS,
    ScopeEntry,
    guard_tool_call,
    in_scope,
    normalize_scope,
    tool_allowed,
)

SCOPE = ["https://myapp.com"]


# --------------------------------------------------------------------------
# Rule 1 - scheme
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    "target",
    [
        "ftp://myapp.com/x",
        "file:///etc/passwd",
        "javascript:alert(1)",
        "data:text/html,<script>",
        "myapp.com",  # no scheme at all
    ],
)
def test_only_http_and_https(target: str) -> None:
    decision = in_scope(target, SCOPE)
    assert not decision
    assert decision.rule == 1


def test_the_guard_decides_the_scheme_itself() -> None:
    """Not left to the tool.

    The guard makes the decision, so it must not depend on something else
    having validated the target first - there is no ordering that guarantees
    the tool ran its own check before the guard was asked.
    """
    assert not in_scope("ftp://myapp.com", SCOPE)


def test_a_target_with_no_host_is_refused() -> None:
    decision = in_scope("https:///path", SCOPE)
    assert not decision
    assert decision.rule == 1


# --------------------------------------------------------------------------
# Rule 2 - host
# --------------------------------------------------------------------------


def test_the_host_must_match() -> None:
    assert in_scope("https://myapp.com/any/path", SCOPE)
    assert not in_scope("https://evil.com", SCOPE)


def test_subdomains_are_off_by_default() -> None:
    decision = in_scope("https://api.myapp.com", SCOPE)
    assert not decision
    assert decision.rule == 2
    assert in_scope("https://api.myapp.com", SCOPE, allow_subdomains=True)


def test_a_subdomain_is_not_a_suffix_match() -> None:
    """`notmyapp.com` ends with `myapp.com` as a string. It is a different site."""
    assert not in_scope("https://notmyapp.com", SCOPE, allow_subdomains=True)


def test_the_scope_host_itself_still_matches_with_subdomains_on() -> None:
    assert in_scope("https://myapp.com", SCOPE, allow_subdomains=True)


def test_host_comparison_ignores_case_and_a_trailing_dot() -> None:
    assert in_scope("https://MyApp.COM", SCOPE)
    assert in_scope("https://myapp.com./x", SCOPE)


def test_userinfo_does_not_smuggle_a_host() -> None:
    """`https://myapp.com@evil.com` is a request to evil.com, not to myapp.com."""
    assert not in_scope("https://myapp.com@evil.com", SCOPE)
    assert in_scope("https://evil.com@myapp.com", SCOPE)


# --------------------------------------------------------------------------
# Rule 3 - downgrade, and its order against rule 4
# --------------------------------------------------------------------------


def test_https_to_http_is_refused() -> None:
    decision = in_scope("http://myapp.com", SCOPE)
    assert not decision
    assert decision.rule == 3


def test_the_downgrade_is_refused_for_the_right_reason() -> None:
    """Rule 3 runs before rule 4, and the order is the whole point.

    http and https have different default ports, so comparing ports first
    would refuse this for "port 80 is not the scope port 443" - true, but it
    sends the developer to fix a port that was never the problem. The reason
    string goes into `ErrorInfo.message` and from there into a report.
    """
    decision = in_scope("http://myapp.com", SCOPE)
    assert decision.rule == 3
    assert "downgrade" in decision.reason
    assert "port" not in decision.reason


def test_http_to_https_upgrade_passes() -> None:
    """Two scheme defaults are compatible, so rule 4 does not block an upgrade."""
    assert in_scope("https://myapp.com", ["http://myapp.com"])


def test_an_http_scope_still_allows_http() -> None:
    assert in_scope("http://myapp.com", ["http://myapp.com"])


# --------------------------------------------------------------------------
# Rule 4 - port
# --------------------------------------------------------------------------


def test_a_different_port_is_a_different_service() -> None:
    decision = in_scope("https://myapp.com:8443/", SCOPE)
    assert not decision
    assert decision.rule == 4


def test_an_explicit_default_port_matches_an_implicit_one() -> None:
    assert in_scope("https://myapp.com:443/x", SCOPE)
    assert in_scope("https://myapp.com/x", ["https://myapp.com:443"])


def test_a_scope_port_pins_the_target_port() -> None:
    scope = ["https://myapp.com:8443"]
    assert in_scope("https://myapp.com:8443/admin", scope)
    assert not in_scope("https://myapp.com", scope)


# --------------------------------------------------------------------------
# Rule 5 - path prefix
# --------------------------------------------------------------------------


def test_a_scope_path_is_a_required_prefix() -> None:
    scope = ["https://myapp.com/api"]
    assert in_scope("https://myapp.com/api", scope)
    assert in_scope("https://myapp.com/api/v1/users", scope)
    decision = in_scope("https://myapp.com/admin", scope)
    assert not decision
    assert decision.rule == 5


def test_a_path_prefix_stops_at_a_segment_boundary() -> None:
    """`/api` must not cover `/apiary` - a prefix match on raw text would."""
    assert not in_scope("https://myapp.com/apiary", ["https://myapp.com/api"])


def test_a_bare_host_scope_covers_every_path() -> None:
    assert in_scope("https://myapp.com/anything/at/all", SCOPE)
    assert in_scope("https://myapp.com/anything", ["https://myapp.com/"])


def test_a_trailing_slash_does_not_change_the_scope() -> None:
    assert in_scope("https://myapp.com/api/v1", ["https://myapp.com/api/"])


# --------------------------------------------------------------------------
# Rule 6 - empty scope
# --------------------------------------------------------------------------


def test_an_empty_scope_matches_nothing() -> None:
    """There is no "scan anything" mode. Not even for a plainly valid URL."""
    decision = in_scope("https://myapp.com", [])
    assert not decision
    assert decision.rule == 6


# --------------------------------------------------------------------------
# Several entries
# --------------------------------------------------------------------------


def test_any_entry_may_allow_the_target() -> None:
    scope = ["https://myapp.com", "https://api.myapp.com"]
    assert in_scope("https://api.myapp.com/v1", scope)
    assert not in_scope("https://evil.com", scope)


def test_the_reason_comes_from_the_entry_that_got_furthest() -> None:
    """ "port 8443 is not the scope port" sends the developer to the right place.

    "host is not in scope", about a host plainly listed in the scope, sends
    them to the wrong one.
    """
    scope = ["https://other.com", "https://myapp.com"]
    decision = in_scope("https://myapp.com:8443", scope)
    assert decision.rule == 4
    assert "8443" in decision.reason


# --------------------------------------------------------------------------
# Scope configuration is the developer's, and a bad one is loud
# --------------------------------------------------------------------------


def test_a_scope_entry_without_a_scheme_is_rejected() -> None:
    """The mistake worth being loud about.

    `"myapp.com"` parses as a path with no host, so it would match nothing
    and every check would fail with "host is not in scope" while the scope
    plainly contains the host.
    """
    with pytest.raises(ValueError, match="no scheme"):
        normalize_scope(["myapp.com"])


@pytest.mark.parametrize(
    ("entry", "match"),
    [
        ("ftp://myapp.com", "http or https"),
        ("https://", "no host"),
        ("https://myapp.com:notaport", "invalid port"),
    ],
)
def test_bad_scope_entries_raise(entry: str, match: str) -> None:
    with pytest.raises(ValueError, match=match):
        normalize_scope([entry])


def test_a_bad_scope_raises_rather_than_refusing_the_target() -> None:
    """A wrong scope is a bug in the caller's code, not a scope decision."""
    with pytest.raises(ValueError):
        in_scope("https://myapp.com", ["myapp.com"])


def test_normalize_scope_keeps_an_unstated_port_unstated() -> None:
    entry = normalize_scope(["https://myapp.com/api/"])[0]
    assert entry == ScopeEntry(scheme="https", host="myapp.com", port=None, path="/api")
    assert entry.effective_port == 443


def test_a_parsed_scope_can_be_passed_straight_back() -> None:
    """The hook parses once per run, not once per tool call."""
    entries = normalize_scope(SCOPE)
    assert in_scope("https://myapp.com/x", entries)
    assert not in_scope("https://evil.com", entries)


# --------------------------------------------------------------------------
# Reasons end up in reports
# --------------------------------------------------------------------------


def test_a_huge_target_does_not_end_up_whole_in_a_reason() -> None:
    """A target can be model-invented, and a reason goes into ErrorInfo.message."""
    decision = in_scope("https://" + "a" * 5000 + ".com", SCOPE)
    assert not decision
    assert len(decision.reason) < MAX_QUOTED_CHARS + 60


def test_an_allowed_decision_carries_no_reason() -> None:
    decision = in_scope("https://myapp.com", SCOPE)
    assert decision
    assert decision.reason == ""
    assert decision.rule is None


# --------------------------------------------------------------------------
# Tool allowlist
# --------------------------------------------------------------------------


def test_only_the_checks_own_tools_are_allowed() -> None:
    allowlist = ["get_response_headers"]
    assert tool_allowed("get_response_headers", allowlist)
    assert not tool_allowed("get_cookies", allowlist)


def test_framework_tools_are_exempt() -> None:
    """Cancelling these does not make a run safer, it makes it impossible.

    `retrieve_context` is the model's only way to read back offloaded tool
    output; the structured-output tool is its only way to answer at all.
    """
    exempt = framework_tools_for("CheckOutput")
    assert tool_allowed("retrieve_context", [], exempt)
    assert tool_allowed("CheckOutput", [], exempt)
    assert not tool_allowed("retrieve_context", [])


def test_the_exempt_set_is_per_check() -> None:
    """The structured-output tool is named after the check's own output model."""
    headers = framework_tools_for("HeadersOutput")
    cookies = framework_tools_for("CookiesOutput")
    assert "HeadersOutput" in headers and "HeadersOutput" not in cookies
    assert headers & cookies >= FRAMEWORK_TOOLS


def test_framework_tools_for_accepts_a_class() -> None:
    class CheckOutput:
        pass

    assert "CheckOutput" in framework_tools_for(CheckOutput)


def test_a_refused_tool_says_which_tool() -> None:
    decision = tool_allowed("get_cookies", ["get_response_headers"])
    assert "get_cookies" in decision.reason


# --------------------------------------------------------------------------
# One proposed tool call - the arguments come from the model
# --------------------------------------------------------------------------


def guard(tool_input, name: str = "get_response_headers", **kw):
    kw.setdefault("allowlist", ["get_response_headers"])
    kw.setdefault("scope", SCOPE)
    return guard_tool_call(name, tool_input, **kw)


def test_a_well_formed_in_scope_call_is_allowed() -> None:
    assert guard({"target": "https://myapp.com/login"})


def test_an_out_of_scope_call_is_refused_with_the_scope_reason() -> None:
    decision = guard({"target": "https://evil.com"})
    assert not decision
    assert decision.rule == 2


def test_a_tool_off_the_allowlist_is_refused_before_its_target_matters() -> None:
    """An in-scope target does not buy a tool its way onto the allowlist."""
    decision = guard({"target": "https://myapp.com"}, name="get_cookies")
    assert not decision
    assert "allowlist" in decision.reason


@pytest.mark.parametrize(
    "tool_input",
    [
        {},  # the model forgot it
        {"url": "https://myapp.com"},  # the tool breaks the naming contract
        {"target": ["https://a", "https://b"]},  # a list of targets
        {"target": {"href": "https://myapp.com"}},
        {"target": 443},
        {"target": None},
        {"target": ""},
        {"target": "   "},
    ],
)
def test_a_malformed_target_is_refused_not_raised(tool_input) -> None:
    """The guard never raises on model input.

    A guard that throws partway through behaves however the framework
    happens to treat an exception inside a hook, and that is not a question
    to leave open in the component whose job is to stop a request reaching a
    host.
    """
    decision = guard(tool_input)
    assert not decision
    assert decision.reason


def test_a_missing_target_says_so_rather_than_blaming_the_scope() -> None:
    decision = guard({})
    assert "'target'" in decision.reason
    assert "scope-checked" in decision.reason


def test_a_framework_tool_passes_without_a_target() -> None:
    """`retrieve_context` takes no target, so every check above would refuse it."""
    exempt = framework_tools_for("CheckOutput")
    assert guard({}, name="retrieve_context", exempt=exempt)
    assert guard({"findings": []}, name="CheckOutput", exempt=exempt)


def test_a_framework_tool_is_exempt_from_the_scope_too() -> None:
    """Not just from the allowlist. It has no target to be in or out of scope."""
    assert guard({}, name="retrieve_context", exempt=FRAMEWORK_TOOLS, scope=[])


def test_extra_arguments_are_not_scope_checked() -> None:
    """`origin` on get_cors_policy names an origin the probe claims to be.

    It is sent as a header; no request is made to it, so there is nothing to
    scope. Scope-checking it would make the CORS check impossible to run -
    the whole point is to send an origin the target does not expect.
    """
    assert guard(
        {"target": "https://myapp.com", "origin": "https://evil.com"},
        name="get_cors_policy",
        allowlist=["get_cors_policy"],
    )


def test_subdomains_reach_the_scope_decision() -> None:
    call = {"target": "https://api.myapp.com"}
    assert not guard(call)
    assert guard(call, allow_subdomains=True)
