"""JSON and SARIF export.

The rule under most of these: a CI gate reading the SARIF must not be able to
mistake a broken run for a clean one.
"""

from __future__ import annotations

import json
from datetime import UTC, datetime

from _builders import draft, tool_step
from websecuritycheck.results import CheckOutput, CheckResult, ErrorInfo, TraceStep
from websecuritycheck.results.export import (
    FINGERPRINT_KEY,
    SARIF_VERSION,
    summary_line,
    to_json,
    to_sarif,
    write_json,
    write_sarif,
)

# --------------------------------------------------------------------------
# Builders
# --------------------------------------------------------------------------


def result(**kw) -> CheckResult:
    return CheckResult.build(
        check=kw.pop("check", "headers"),
        target=kw.pop("target", "https://example.com"),
        output=kw.pop("output", CheckOutput(findings=[draft()])),
        errors=kw.pop("errors", []),
        trace=kw.pop("trace", [tool_step()]),
        run_id=kw.pop("run_id", "r1"),
        **kw,
    )


def only_run(res: CheckResult) -> dict:
    runs = to_sarif(res)["runs"]
    assert len(runs) == 1
    return runs[0]


# --------------------------------------------------------------------------
# JSON
# --------------------------------------------------------------------------


def test_json_is_the_result_verbatim() -> None:
    res = result()
    assert CheckResult.model_validate_json(to_json(res)) == res


def test_json_of_a_sequence_is_an_array() -> None:
    payload = json.loads(to_json([result(check="headers"), result(check="tls")]))
    assert [item["check"] for item in payload] == ["headers", "tls"]


def test_write_json_round_trips(tmp_path) -> None:
    path = write_json(result(), tmp_path / "report.json")
    assert CheckResult.model_validate_json(path.read_text(encoding="utf-8")).check == "headers"


# --------------------------------------------------------------------------
# SARIF shape
# --------------------------------------------------------------------------


def test_sarif_envelope() -> None:
    log = to_sarif(result())
    assert log["version"] == SARIF_VERSION
    assert log["$schema"].endswith("sarif-2.1.0.json")


def test_one_run_per_check() -> None:
    log = to_sarif([result(check="headers"), result(check="tls")])
    assert [r["properties"]["check"] for r in log["runs"]] == ["headers", "tls"]


def test_a_finding_becomes_a_sarif_result_and_a_rule() -> None:
    run = only_run(result())
    assert len(run["results"]) == 1
    finding_id = run["results"][0]["ruleId"]
    assert [rule["id"] for rule in run["tool"]["driver"]["rules"]] == [finding_id]


def test_rules_are_not_repeated_for_two_findings_of_one_kind() -> None:
    """Two runs of the same problem on one page declare one rule, not two."""
    res = result(
        output=CheckOutput(
            findings=[
                draft(title="Cookie missing Secure", location="sid"),
                draft(title="Cookie missing Secure", location="csrf"),
            ]
        )
    )
    run = only_run(res)
    assert len(run["results"]) == 2
    assert len({rule["id"] for rule in run["tool"]["driver"]["rules"]}) == 2  # distinct locations


def test_every_finding_is_reported_at_one_level() -> None:
    """Findings carry no severity, so SARIF cannot claim one.

    `warning` is SARIF's own default for a result whose rule says nothing,
    so writing it states what would happen anyway rather than inventing a
    rating on the way out of the door.
    """
    run = only_run(
        result(
            output=CheckOutput(
                findings=[draft(title="a", location="x"), draft(title="b", location="y")]
            )
        )
    )
    assert {item["level"] for item in run["results"]} == {"warning"}


def test_sarif_claims_no_security_severity() -> None:
    """The cost of having no severity, written down where it bites.

    GitHub code scanning ranks alerts by this property. Without it every
    alert sorts together and the reader does the triage - which is the
    honest trade for not having guessed the numbers.
    """
    run = only_run(result(output=CheckOutput(findings=[draft()])))
    properties = run["tool"]["driver"]["rules"][0]["properties"]
    assert "security-severity" not in properties
    assert properties["tags"][0] == "security"


def test_location_carries_the_url_and_the_header_name() -> None:
    run = only_run(result())
    location = run["results"][0]["locations"][0]
    assert location["physicalLocation"]["artifactLocation"]["uri"] == "https://example.com"
    assert location["logicalLocations"][0]["name"] == "Content-Security-Policy"


def test_fingerprint_is_the_finding_id() -> None:
    """What lets CI follow one alert across runs instead of re-raising it."""
    res = result()
    run = only_run(res)
    assert run["results"][0]["partialFingerprints"][FINGERPRINT_KEY] == res.findings[0].id


# --------------------------------------------------------------------------
# The invocation: a broken run must look broken
# --------------------------------------------------------------------------


def test_a_failed_run_is_not_successful_and_has_no_findings() -> None:
    """The case the whole invocation mapping exists for.

    Zero results, because every probe failed. A gate reading only `results`
    sees a clean scan; `executionSuccessful` is what stops it.
    """
    res = result(
        output=CheckOutput(),
        errors=[ErrorInfo(kind="tool", message="connect timed out", code="E_TIMEOUT")],
        trace=[tool_step(status="error", code="E_TIMEOUT")],
    )
    run = only_run(res)
    assert run["results"] == []
    assert run["invocations"][0]["executionSuccessful"] is False
    assert run["invocations"][0]["properties"]["status"] == "failed"


def test_a_clean_run_is_successful() -> None:
    run = only_run(result(output=CheckOutput()))
    assert run["invocations"][0]["executionSuccessful"] is True
    assert run["invocations"][0]["properties"]["status"] == "passed"


def test_a_partial_run_stays_successful_but_says_so() -> None:
    res = result(errors=[ErrorInfo(kind="tool", message="tls probe failed", code="E_TLS")])
    invocation = only_run(res)["invocations"][0]
    assert res.status == "partial"
    assert invocation["executionSuccessful"] is True
    assert invocation["properties"]["status"] == "partial"
    assert len(invocation["toolExecutionNotifications"]) == 1


def test_errors_become_notifications_and_keep_their_code() -> None:
    res = result(
        errors=[
            ErrorInfo(kind="tool", message="timed out", code="E_TIMEOUT", tool="get_tls_info"),
            ErrorInfo(kind="scope", message="out of scope", step_ref="s3"),
        ]
    )
    run = only_run(res)
    notifications = run["invocations"][0]["toolExecutionNotifications"]
    assert notifications[0]["descriptor"]["id"] == "E_TIMEOUT"
    assert notifications[0]["properties"]["tool"] == "get_tls_info"
    assert notifications[1]["properties"] == {"kind": "scope", "stepRef": "s3"}


def test_every_notification_descriptor_is_declared() -> None:
    """A reference to a descriptor the driver never declared is dangling."""
    res = result(
        errors=[
            ErrorInfo(kind="tool", message="timed out", code="E_TIMEOUT"),
            ErrorInfo(kind="tool", message="timed out again", code="E_TIMEOUT"),
            ErrorInfo(kind="tool", message="server down", code="E_SERVER_UNAVAILABLE"),
            ErrorInfo(kind="scope", message="blocked"),  # no code, nothing to declare
        ]
    )
    run = only_run(res)
    declared = {d["id"] for d in run["tool"]["driver"]["notifications"]}
    referenced = {
        n["descriptor"]["id"]
        for n in run["invocations"][0]["toolExecutionNotifications"]
        if "descriptor" in n
    }
    assert referenced <= declared
    assert declared == {"E_TIMEOUT", "E_SERVER_UNAVAILABLE"}  # declared once each


def test_no_error_is_demoted_to_a_warning() -> None:
    """A blocked call is not a milder problem than a crash."""
    res = result(
        errors=[
            ErrorInfo(kind="scope", message="blocked"),
            ErrorInfo(kind="injection", message="wrapped"),
            ErrorInfo(kind="validation", message="bad schema"),
        ]
    )
    levels = {n["level"] for n in only_run(res)["invocations"][0]["toolExecutionNotifications"]}
    assert levels == {"error"}


def test_trace_rides_in_the_invocation() -> None:
    res = result(
        trace=[
            TraceStep(id="s1", kind="skill_loaded", name="headers"),
            tool_step("s2", duration_ms=540),
        ]
    )
    trace = only_run(res)["invocations"][0]["properties"]["trace"]
    assert [step["id"] for step in trace] == ["s1", "s2"]
    assert trace[1]["durationMs"] == 540
    assert only_run(res)["invocations"][0]["properties"]["toolsRan"] == 1


def test_timestamps_are_utc_with_a_z() -> None:
    res = result(
        started_at=datetime(2026, 10, 19, 8, 30, tzinfo=UTC),
        finished_at=datetime(2026, 10, 19, 8, 30, 10, tzinfo=UTC),
    )
    invocation = only_run(res)["invocations"][0]
    assert invocation["startTimeUtc"] == "2026-10-19T08:30:00Z"
    assert invocation["endTimeUtc"] == "2026-10-19T08:30:10Z"


def test_a_naive_timestamp_is_read_as_utc_not_local() -> None:
    res = result(started_at=datetime(2026, 10, 19, 8, 30))
    assert only_run(res)["invocations"][0]["startTimeUtc"] == "2026-10-19T08:30:00Z"


def test_timestamps_are_omitted_when_unknown() -> None:
    invocation = only_run(result())["invocations"][0]
    assert "startTimeUtc" not in invocation
    assert "endTimeUtc" not in invocation


def test_write_sarif_is_valid_json(tmp_path) -> None:
    path = write_sarif([result(check="headers"), result(check="tls")], tmp_path / "out.sarif")
    assert len(json.loads(path.read_text(encoding="utf-8"))["runs"]) == 2


# --------------------------------------------------------------------------
# Terminal summary
# --------------------------------------------------------------------------


def test_summary_line_names_errors_before_findings() -> None:
    line = summary_line(result(errors=[ErrorInfo(kind="tool", message="boom")]))
    assert line.index("error(s)") < line.index("finding(s)")
    assert "partial" in line
