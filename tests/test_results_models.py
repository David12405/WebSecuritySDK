"""The status table, the no-tool rule, and the limits on what the model may say.

No network, no model.
"""

from __future__ import annotations

import pytest
from pydantic import ValidationError

from _builders import draft, finding, tool_step
from websecuritycheck.results import (
    MAX_SUMMARY_CHARS,
    CheckOutput,
    CheckResult,
    ErrorInfo,
    Finding,
    FindingDraft,
    RunDiff,
    TraceStep,
    decide_status,
    stable_id,
)

# --------------------------------------------------------------------------
# The status table
# --------------------------------------------------------------------------


@pytest.mark.parametrize(
    ("n_findings", "n_errors", "expected"),
    [
        (0, 0, "passed"),
        (1, 0, "issues_found"),
        (1, 1, "partial"),
        (0, 1, "failed"),
    ],
)
def test_status_table(n_findings: int, n_errors: int, expected: str) -> None:
    findings = [finding(title=f"issue {i}") for i in range(n_findings)]
    errors = [ErrorInfo(kind="tool", message="boom") for _ in range(n_errors)]
    assert decide_status(findings, errors, tools_ran=1) == expected


# --------------------------------------------------------------------------
# A run that measured nothing
# --------------------------------------------------------------------------


def test_no_tool_ran_is_never_passed() -> None:
    """The rule the whole module exists to make unbreakable."""
    assert decide_status([], [], tools_ran=0) == "failed"


def test_findings_without_a_tool_are_not_partial() -> None:
    """They were remembered, not observed. `partial` would imply half-measured."""
    assert decide_status([finding()], [ErrorInfo(kind="tool", message="boom")], tools_ran=0) == (
        "failed"
    )


def test_build_adds_an_error_when_no_tool_ran() -> None:
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(),
        errors=[],
        trace=[TraceStep(id="s1", kind="model_call", name="gemini")],
    )
    assert result.status == "failed"
    assert [e.kind for e in result.errors] == ["model"]
    assert "without calling a tool" in result.errors[0].message


def test_a_failed_tool_call_did_not_measure() -> None:
    """An errored probe obtained nothing, so it cannot rescue `passed`."""
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(),
        errors=[ErrorInfo(kind="tool", message="timed out", code="E_TIMEOUT")],
        trace=[tool_step(status="error", code="E_TIMEOUT")],
    )
    assert result.tools_ran == 0
    assert result.status == "failed"


def test_a_cancelled_call_did_not_measure() -> None:
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(),
        errors=[ErrorInfo(kind="scope", message="out of scope")],
        trace=[TraceStep(id="s1", kind="cancelled", name="get_response_headers")],
    )
    assert result.status == "failed"


# --------------------------------------------------------------------------
# What the model is not allowed to say
# --------------------------------------------------------------------------


def test_the_model_cannot_set_a_status() -> None:
    with pytest.raises(ValidationError):
        CheckOutput.model_validate({"findings": [], "status": "passed"})


def test_the_model_cannot_set_a_finding_id() -> None:
    with pytest.raises(ValidationError):
        FindingDraft.model_validate({**draft().model_dump(), "id": "made-up"})


def test_check_output_schema_hides_id_and_tool_refs() -> None:
    """What the model is shown, not just what it is allowed to send."""
    properties = CheckOutput.model_json_schema()["$defs"]["FindingDraft"]["properties"]
    assert "id" not in properties
    assert "tool_refs" not in properties


def test_notes_reach_the_developer() -> None:
    """The half of the model's output that is not a finding.

    The prompt asks for `notes` in five places and the skills in four more,
    and for a while nothing carried it past `CheckOutput` - so a run that
    inventoried nine technologies returned two unrelated findings and read
    like a check that had not done the work.
    """
    result = CheckResult.build(
        check="fingerprint",
        target="https://example.com",
        output=CheckOutput(findings=[], notes="nginx, no version. Cloudflare in front."),
        errors=[],
        trace=[tool_step()],
    )
    assert result.notes == "nginx, no version. Cloudflare in front."
    assert result.status == "passed"


def test_notes_are_not_scored() -> None:
    """`notes` says what is there; only findings say what is wrong."""
    result = CheckResult.build(
        check="fingerprint",
        target="https://example.com",
        output=CheckOutput(findings=[], notes="Apache 2.4.29 and PHP 7.2 are both ancient."),
        errors=[],
        trace=[tool_step()],
    )
    assert result.status == "passed"
    assert result.findings == []


def test_a_finding_carries_no_remediation() -> None:
    """This SDK reports what a target does; it does not advise a change.

    Both halves are asserted because they fail differently. The schema check
    is what the model is *shown* - a `remediation` property would invite the
    advice whatever the prompt says. The validation check is what the model
    is *allowed to send* - and it only holds while `extra="forbid"` does, so
    a refactor that relaxes the config fails here rather than silently
    reopening the field.
    """
    properties = CheckOutput.model_json_schema()["$defs"]["FindingDraft"]["properties"]
    assert "remediation" not in properties

    with pytest.raises(ValidationError):
        FindingDraft.model_validate({**draft().model_dump(), "remediation": "Send a CSP header."})


def test_a_finding_must_quote_something() -> None:
    with pytest.raises(ValidationError):
        draft(evidence="")


# --------------------------------------------------------------------------
# Identity and the diff
# --------------------------------------------------------------------------


def test_stable_id_survives_rewording_that_is_only_punctuation() -> None:
    assert stable_id("headers", "Content-Security-Policy", "CSP header missing") == stable_id(
        "headers", "content-security-policy ", "CSP header, missing!"
    )


def test_stable_id_separates_two_findings_on_one_location() -> None:
    a = stable_id("headers", "Content-Security-Policy", "CSP missing")
    b = stable_id("headers", "Content-Security-Policy", "CSP allows unsafe-inline")
    assert a != b


def test_same_finding_from_two_runs_gets_one_id() -> None:
    first = Finding.from_draft(draft(), "headers", ["s1"])
    second = Finding.from_draft(draft(), "headers", ["s4"])
    assert first.id == second.id


def test_diff_keeps_unverified_apart_from_fixed() -> None:
    """A finding whose tool failed this run is not a finding that was fixed."""
    diff = RunDiff(previous_run_id="r1", unverified=["abc123"])
    assert not diff.fixed
    assert not diff.is_empty


# --------------------------------------------------------------------------
# Assembly
# --------------------------------------------------------------------------


def test_findings_are_ordered_by_what_they_are_about() -> None:
    """With no severity to rank by, the useful order groups a target's
    findings about the same header or cookie together."""
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(
            findings=[
                draft(title="Server header discloses version", location="Server"),
                draft(title="HSTS missing", location="Strict-Transport-Security"),
                draft(title="No CSP", location="Content-Security-Policy"),
            ]
        ),
        errors=[],
        trace=[tool_step()],
    )
    assert [f.location for f in result.findings] == [
        "Content-Security-Policy",
        "Server",
        "Strict-Transport-Security",
    ]
    assert result.status == "issues_found"


def test_a_finding_cannot_carry_a_severity() -> None:
    """Removed rather than forbidden, the same move `status` gets.

    Measured before it was dropped: severities moved between identical
    runs, a reviewing model argued them on every finding and invented a
    premise to justify itself, and the pressure to defend a rating pushed
    four specific findings into one vague one.
    """
    properties = CheckOutput.model_json_schema()["$defs"]["FindingDraft"]["properties"]
    assert "severity" not in properties

    with pytest.raises(ValidationError):
        FindingDraft.model_validate({**draft().model_dump(), "severity": "critical"})


def test_tool_refs_follow_the_named_tool() -> None:
    result = CheckResult.build(
        check="cookies",
        target="https://example.com",
        output=CheckOutput(findings=[draft(source_tool="get_cookies")]),
        errors=[],
        trace=[tool_step("s1", "get_response_headers"), tool_step("s2", "get_cookies")],
    )
    assert result.findings[0].tool_refs == ["s2"]


def test_tool_refs_fall_back_to_the_whole_run() -> None:
    """No named tool means unattributed, not unevidenced - grounding judges that."""
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(findings=[draft()]),
        errors=[],
        trace=[tool_step("s1"), tool_step("s2", "get_tls_info")],
    )
    assert result.findings[0].tool_refs == ["s1", "s2"]


def test_by_location_groups_what_a_reader_reads_together() -> None:
    result = CheckResult.build(
        check="cookies",
        target="https://example.com",
        output=CheckOutput(
            findings=[
                draft(title="sid has no HttpOnly", location="sid"),
                draft(title="sid has no Secure", location="sid"),
                draft(title="_ga has no SameSite", location="_ga"),
            ]
        ),
        errors=[],
        trace=[tool_step()],
    )
    grouped = result.by_location()
    assert list(grouped) == ["_ga", "sid"]
    assert len(grouped["sid"]) == 2


# --------------------------------------------------------------------------
# The trace
# --------------------------------------------------------------------------


def test_trace_summaries_are_capped() -> None:
    step = tool_step(summary="x" * (MAX_SUMMARY_CHARS * 2))
    assert len(step.summary) == MAX_SUMMARY_CHARS
    assert step.summary.endswith("…")


def test_trace_detail_is_capped_too() -> None:
    step = TraceStep(id="s1", kind="steering", detail="y" * 1000)
    assert len(step.detail) == MAX_SUMMARY_CHARS


def test_result_round_trips_through_json() -> None:
    """A report is written to disk and read by CI, so this has to hold."""
    result = CheckResult.build(
        check="headers",
        target="https://example.com",
        output=CheckOutput(findings=[draft()], notes="Checked all four required headers."),
        errors=[ErrorInfo(kind="tool", message="timed out", code="E_TIMEOUT", tool="get_tls_info")],
        trace=[tool_step()],
        run_id="r2",
    )
    assert CheckResult.model_validate_json(result.model_dump_json()) == result
    assert result.status == "partial"
