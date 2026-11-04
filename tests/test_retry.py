"""The retry hook: a blip gets another chance, a real failure becomes an error.

No network, no model. The hook is driven with hand-built `AfterToolCall`
events, which is the whole point of it being a watcher: what it decides
depends only on the result it is shown and the count it keeps.

Every rule is checked from both sides - that a transient failure is retried
and that it records nothing until it is final, and that a failure which
stands becomes an error and never a finding.
"""

from __future__ import annotations

from typing import Any

from strands.hooks import AfterToolCallEvent

from websecuritycheck.policy.retry import RetryGuard


def after_event(
    *,
    name: str = "get_tls_info",
    tool_use_id: str = "tu-1",
    error: bool = True,
    text: str = "E_TIMEOUT: connection timed out",
) -> Any:
    return AfterToolCallEvent(
        agent=None,
        selected_tool=None,
        tool_use={"name": name, "input": {}, "toolUseId": tool_use_id},
        invocation_state={},
        result={
            "content": [{"text": text}],
            "status": "error" if error else "success",
            "toolUseId": tool_use_id,
        },
        duration=0.1,
    )


def test_a_retryable_failure_asks_for_another_attempt_and_records_nothing_yet() -> None:
    """E_TIMEOUT is a blip. Retry, and do not poison the run with an error
    for a failure that may not last."""
    guard = RetryGuard()
    event = after_event(text="E_TIMEOUT: timed out")
    guard._after_tool(event)
    assert event.retry is True
    assert guard.errors == []


def test_an_unretryable_failure_is_not_retried_and_becomes_an_error() -> None:
    """Repeating a call that failed for a reason nobody understands learns
    nothing. It stands at once, as a tool error."""
    guard = RetryGuard()
    event = after_event(text="E_INTERNAL: the tool exploded")
    guard._after_tool(event)
    assert event.retry is False
    assert [(e.kind, e.code) for e in guard.errors] == [("tool", "E_INTERNAL")]


def test_attempts_are_capped_then_the_failure_stands() -> None:
    """Two retries, then give up - a service that is genuinely down must not
    become a long wait."""
    guard = RetryGuard(max_attempts=3)
    outcomes = []
    for _ in range(3):  # the same call (tu-1) failing three times
        event = after_event(text="E_TIMEOUT: timed out")
        guard._after_tool(event)
        outcomes.append(event.retry)
    assert outcomes == [True, True, False]
    assert [e.code for e in guard.errors] == ["E_TIMEOUT"]


def test_a_recovered_retry_records_no_error() -> None:
    """The point of the whole hook: a transient failure that is recovered
    leaves the run clean, not `partial`."""
    guard = RetryGuard()
    guard._after_tool(after_event(text="E_TIMEOUT: timed out"))  # fails, retry asked
    guard._after_tool(after_event(error=False, text="ok"))  # same call, now succeeds
    assert guard.errors == []


def test_a_success_is_left_alone() -> None:
    guard = RetryGuard()
    event = after_event(error=False, text="ok")
    guard._after_tool(event)
    assert event.retry is False
    assert guard.errors == []


def test_a_framework_tool_is_never_retried() -> None:
    """Retrying the structured-output tool would retry the model's own
    answer, not a probe of the target."""
    guard = RetryGuard(exempt=frozenset({"CheckOutput"}))
    event = after_event(name="CheckOutput", text="E_TIMEOUT: timed out")
    guard._after_tool(event)
    assert event.retry is False
    assert guard.errors == []


def test_each_call_keeps_its_own_budget() -> None:
    """The counter is keyed by toolUseId, so one exhausted call does not
    spend another call's retries."""
    guard = RetryGuard(max_attempts=2)
    for _ in range(2):  # tu-1 exhausts its budget
        guard._after_tool(after_event(tool_use_id="tu-1", text="E_TIMEOUT: x"))
    fresh = after_event(tool_use_id="tu-2", text="E_TIMEOUT: x")
    guard._after_tool(fresh)
    assert fresh.retry is True  # a different call, full budget


def test_the_recorded_message_drops_the_code_prefix() -> None:
    """`code` already carries the code; a message that repeats it stutters."""
    guard = RetryGuard()
    guard._after_tool(after_event(text="E_INTERNAL: the tool exploded"))
    assert guard.errors[0].message == "the tool exploded"
    assert guard.errors[0].tool == "get_tls_info"
