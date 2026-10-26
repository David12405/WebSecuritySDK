"""The three soft rules, and the two ways each one goes wrong.

No network, no model. That is the point of the module being pure functions:
a rule nobody can test is a rule nobody can rely on.

Every rule is tested twice - once that it fires on the failure it was
written for, and once that it stays quiet on a correct answer. The second
half matters more. A rule with false positives sends good answers back for
revision, spends the check's turns, and makes the model rewrite something
that was already right.
"""

from __future__ import annotations

from _builders import draft
from websecuritycheck.checks import TLS, get
from websecuritycheck.policy.steering import (
    SteeringIssue,
    check_coverage,
    check_evidence,
    check_grounding,
    message_for,
    review,
    tokens,
)
from websecuritycheck.results.models import CheckOutput

# A real probe result, trimmed. Grounding is matched against the raw tool
# output, so a made-up corpus would test the rule against a world that does
# not exist.
TLS_CORPUS = """
{"chain_valid": true, "cipher": "TLS_AES_256_GCM_SHA384", "days_to_expiry": 64,
 "hostname": "example.com", "not_after": "2026-12-25T22:56:35Z", "port": 443,
 "protocol": "TLSv1.3", "subject": "CN=example.com"}
"""

HEADERS_CORPUS = """
{"headers": {"server": "cloudflare"}, "security_headers_missing":
 ["strict-transport-security", "content-security-policy", "x-frame-options"]}
"""


def output(*drafts, notes: str = "") -> CheckOutput:
    return CheckOutput(findings=list(drafts), notes=notes)


# --------------------------------------------------------------------------
# tokens
# --------------------------------------------------------------------------


def test_short_tokens_are_dropped() -> None:
    """`a`, `is` and `80` match almost anything, which is not a rule."""
    assert tokens("a is 80 cookie") == {"cookie"}


def test_a_location_is_split_the_way_a_tool_result_spells_it() -> None:
    """The reason matching is token-based at all.

    The `tls` skill writes `example.com:443`; the probe returns `hostname`
    and `port` in separate fields. Substring matching calls a perfectly good
    finding ungrounded.
    """
    assert "example.com:443" not in TLS_CORPUS
    assert tokens("example.com:443") <= tokens(TLS_CORPUS)


# --------------------------------------------------------------------------
# coverage
# --------------------------------------------------------------------------


def test_coverage_fires_on_the_topic_nobody_mentioned() -> None:
    """The failure that actually happens: two of three topics answered."""
    answer = output(notes="Negotiated TLSv1.3. The chain is trusted.")
    issues = check_coverage(answer, TLS.required_coverage)
    assert [issue.subject for issue in issues] == ["expiry"]


def test_coverage_is_satisfied_from_notes_alone() -> None:
    """A clean check addresses its topics without a finding for each.

    Reading only findings would demand a finding per topic, which is a
    demand for findings that do not exist.
    """
    answer = output(notes="Negotiated TLSv1.3, chain is trusted, expires in 64 days.")
    assert check_coverage(answer, TLS.required_coverage) == []


def test_coverage_accepts_any_declared_alias() -> None:
    """No model writes the word `expiry`. It writes `not_after`."""
    answer = output(notes="protocol TLSv1.3; chain verification passed; not_after 2026-12-25")
    assert check_coverage(answer, TLS.required_coverage) == []


def test_a_check_with_no_declared_topics_is_never_steered_for_coverage() -> None:
    assert check_coverage(output(notes=""), {}) == []


# --------------------------------------------------------------------------
# grounding
# --------------------------------------------------------------------------


def test_grounding_fires_on_a_finding_about_something_no_tool_saw() -> None:
    """The remembered finding - what sites like this usually get wrong."""
    invented = draft(title="Weak cipher on the admin panel", location="admin.example.net:8443")
    issues = check_grounding([invented], TLS_CORPUS)
    assert [issue.rule for issue in issues] == ["grounding"]


def test_one_shared_token_does_not_ground_a_finding() -> None:
    """Why the rule asks for every token rather than any.

    `admin.example.net:8443` and a result about `example.com` share the
    word `example`. Under any-token matching an entirely invented host
    passes, which is the finding grounding exists to catch - and the first
    version of this rule did exactly that.
    """
    invented = draft(location="admin.example.net:8443")
    assert tokens("admin.example.net:8443") & tokens(TLS_CORPUS)  # they do share one
    assert check_grounding([invented], TLS_CORPUS)  # and it is still refused


def test_a_missing_header_is_grounded_by_the_result_that_says_it_is_missing() -> None:
    """The case a careless rule gets wrong.

    `headers` reports what is absent, so the location cannot be quoted from
    a value - but the probe names it in `security_headers_missing`, and that
    is the measurement.
    """
    real = draft(title="Missing CSP header", location="content-security-policy")
    assert check_grounding([real], HEADERS_CORPUS) == []


def test_grounding_abstains_when_nothing_was_archived() -> None:
    """ "No tool ran" is the status rule's job.

    Two mechanisms reporting one problem in different words helps nobody,
    and failing every finding here would bury the real message.
    """
    assert check_grounding([draft()], "") == []
    assert check_grounding([draft()], "   \n ") == []


# --------------------------------------------------------------------------
# evidence
# --------------------------------------------------------------------------


def test_evidence_fires_when_it_only_repeats_the_title() -> None:
    restated = draft(title="Missing CSP header", evidence="CSP header missing")
    issues = check_evidence([restated])
    assert [issue.rule for issue in issues] == ["evidence"]


def test_evidence_accepts_a_quoted_absence() -> None:
    """Lenient on purpose.

    For a missing header the absence *is* the measurement, and there is
    nothing else to quote. A stricter rule would reject every correct
    `headers` finding.
    """
    real = draft(
        title="Missing Content-Security-Policy header",
        evidence='"security_headers_missing" lists "content-security-policy"',
    )
    assert check_evidence([real]) == []


# --------------------------------------------------------------------------
# review and the message
# --------------------------------------------------------------------------


def test_a_good_answer_is_not_steered_at_all() -> None:
    """The whole suite in one: a correct run must cost no extra round."""
    answer = output(
        draft(
            title="Certificate expires soon",
            location="example.com:443",
            evidence='"days_to_expiry": 64',
        ),
        notes="Negotiated TLSv1.3 with a strong cipher; chain trusted.",
    )
    assert review(answer, TLS, TLS_CORPUS) == []


def test_review_reports_every_rule_at_once() -> None:
    """One message per round, not one problem per round.

    Each round costs a model call and a turn from the check's budget, so a
    model that fixes one problem per round runs out of budget first.
    """
    bad = draft(
        title="Weak cipher on admin panel",
        location="admin.example.net:8443",
        evidence="Weak cipher admin panel",
    )
    issues = review(output(bad), TLS, TLS_CORPUS)
    assert {issue.rule for issue in issues} == {"coverage", "grounding", "evidence"}


def test_the_message_names_every_issue_and_restates_the_contract() -> None:
    text = message_for(
        [
            SteeringIssue(rule="coverage", detail="You did not address expiry.", subject="expiry"),
            SteeringIssue(rule="grounding", detail="No tool result mentions it.", subject="x"),
        ]
    )
    assert "[coverage]" in text and "[grounding]" in text
    assert "structured output" in text
    # A model asked to revise tends to send only what changed.
    assert "every finding you" in text


def test_every_registered_check_declares_topics_steering_can_act_on() -> None:
    """`required_coverage` was declared on all five checks and read by none.

    This keeps the two ends connected: a topic with no aliases is matched on
    its own name alone, which for an underscored name no model ever writes
    means a rule that fires on every correct answer.
    """
    for name in ("headers", "tls", "cookies", "cors", "fingerprint"):
        check = get(name)
        assert check.required_coverage, f"{name} declares no coverage topics"
        for topic, aliases in check.required_coverage.items():
            assert "_" not in topic or aliases, f"{name}: {topic!r} needs an alias a model writes"
