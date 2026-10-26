"""Builds and drives the agent for one check.  Steps 2 to 7 of the diagram.

Step 2  assemble the Agent from the `Check`: prompt, skill text, tool
        allowlist, structured-output schema, hooks.
Step 3  start the run - the trace opens, the servers come up.
Steps 4-6  the loop, owned by Strands, with our hooks riding along.
Step 7  finish: assemble a `CheckResult` from what actually happened.

The runner owns `status`, `errors`, `diff` and `trace`. The model produces
`CheckOutput` - findings and notes - and nothing else, so it cannot declare
a check passed when a tool failed.

**Why the agent is invoked rather than asked for structured output
directly.** `Agent.structured_output()` calls the model once with no loop:
no tool call, no `BeforeToolCall` event, no evidence. The system prompt
forbids unevidenced findings, so the model correctly returns nothing - and
"nothing was measured" would become "passed". Declaring
`structured_output_model` on the Agent and invoking it normally runs the
loop with tools and forces the structured-output tool at the end.
"""

from __future__ import annotations

import time
from datetime import UTC, datetime
from uuid import uuid4

from strands import Agent

from ..checks.base import Check
from ..config import Settings
from ..memory.context import framework_tools_for
from ..policy.injection_guard import InjectionGuard
from ..policy.scope_guard import ScopeGuard, in_scope
from ..policy.steering import MAX_ROUNDS, message_for, review
from ..results.models import CheckOutput, CheckResult, ErrorInfo
from ..telemetry.trace import TraceCollector
from ..tools.mcp import ToolProvider, load_server_specs
from .models import build_model
from .prompts import opening_message, system_prompt


def run_check(check: Check, target: str, settings: Settings) -> CheckResult:
    """One check, end to end, returning a typed result and never raising.

    A failure of the SDK is reported in `errors`, not thrown at the caller:
    a check that cannot run is a result with `status="failed"`, which the
    caller handles the same way as any other outcome.
    """
    run_id = uuid4().hex[:12]
    started = datetime.now(UTC)
    # All three hooks take the same exempt set: the guard must not cancel
    # these tools, the injection guard must not wrap them, and the trace
    # must not count them.
    trace = TraceCollector(
        level=settings.trace_level, exempt=framework_tools_for(check.output_model)
    )

    # Step 1 of the diagram, repeated here because `checker.py` is not the
    # only caller: the target is checked before an agent exists, so an
    # out-of-scope call never reaches a model or a server.
    decision = in_scope(target, settings.entries, settings.allow_subdomains)
    if not decision:
        return _failed(
            check,
            target,
            run_id,
            started,
            [ErrorInfo(kind="scope", message=decision.reason)],
            trace,
        )

    try:
        return _run(check, target, settings, run_id, started, trace)
    except Exception as exc:  # the SDK itself broke; the caller still gets a result
        return _failed(
            check,
            target,
            run_id,
            started,
            [ErrorInfo(kind="model", message=f"{type(exc).__name__}: {exc}")],
            trace,
        )


def _run(
    check: Check,
    target: str,
    settings: Settings,
    run_id: str,
    started: datetime,
    trace: TraceCollector,
) -> CheckResult:
    errors: list[ErrorInfo] = []
    exempt = framework_tools_for(check.output_model)

    scope_guard = ScopeGuard(
        allowlist=check.tools,
        scope=settings.entries,
        exempt=exempt,
        allow_subdomains=settings.allow_subdomains,
    )
    injection_guard = InjectionGuard(output_tool=check.output_model.__name__)

    specs = load_server_specs(settings.servers_config)
    with ToolProvider(specs) as provider:
        tools = provider.tools_for(check.tools)
        errors.extend(provider.errors)

        # A check with none of its tools cannot measure anything, and
        # spending a model call to find that out teaches nobody anything.
        if not tools:
            return _failed(check, target, run_id, started, errors, trace)

        trace.record("skill_loaded", name=check.skill_name, summary=f"{check.skill_name}/SKILL.md")

        agent = Agent(
            model=build_model(
                settings.model, api_key=settings.api_key, temperature=settings.temperature
            ),
            tools=tools,
            system_prompt=system_prompt(check),
            structured_output_model=check.output_model,
            hooks=[scope_guard, injection_guard, trace],
            callback_handler=None,  # the trace is the record; stdout is not
        )

        began = time.perf_counter()
        result = agent(
            opening_message(check, target),
            limits={"turns": check.max_turns},
        )
        elapsed = int((time.perf_counter() - began) * 1000)

        output = result.structured_output
        if not isinstance(output, CheckOutput):
            errors.append(
                ErrorInfo(
                    kind="validation",
                    message=(
                        "the model ended the run without producing a structured answer "
                        f"(stop reason: {result.stop_reason})"
                    ),
                )
            )
            output = CheckOutput()
        else:
            trace.record("output", name=check.output_model.__name__, duration_ms=elapsed)
            # Inside the `with`, because a steering round is another model
            # turn and the model may call a tool during it - which needs the
            # servers still running.
            output = _steer(agent, output, check, injection_guard, trace, errors)

    # The guards collected their own refusals while the loop ran.
    errors.extend(scope_guard.errors)
    errors.extend(injection_guard.errors)

    return CheckResult.build(
        check=check.name,
        target=target,
        output=output,
        errors=errors,
        trace=trace.steps,
        tools_ran=trace.tools_ran,
        run_id=run_id,
        started_at=started,
        finished_at=datetime.now(UTC),
    )


def _steer(
    agent: Agent,
    output: CheckOutput,
    check: Check,
    injection_guard: InjectionGuard,
    trace: TraceCollector,
    errors: list[ErrorInfo],
) -> CheckOutput:
    """Send the answer back while a rule is unmet, up to `MAX_ROUNDS`.

    The corpus is the archived *raw* tool output, not what the model was
    shown: grounding asks what the tools returned, and the wrapped copy
    carries our framing around it. The guard keeps both for this reason.

    An unmet rule that survives every round becomes a `validation` error
    rather than being dropped. A run whose findings could not be grounded,
    reported as a clean `issues_found`, is exactly the output this SDK
    exists not to produce - and the status table turns the error into
    `partial`, which is the honest word for "there is an answer and
    something is wrong with it".

    A round that fails to produce a structured answer keeps the previous
    one. The model had a valid answer a moment ago, and losing it because a
    revision went wrong would make steering more dangerous than the problem
    it is addressing.
    """
    corpus = injection_guard.corpus()
    issues = review(output, check, corpus)

    for _round in range(MAX_ROUNDS):
        if not issues:
            return output
        for issue in issues:
            trace.record("steering", name=issue.rule, summary=issue.subject or issue.rule)

        revised = agent(message_for(issues), limits={"turns": check.max_turns})
        if not isinstance(revised.structured_output, CheckOutput):
            break  # keep the answer we have
        output = revised.structured_output
        issues = review(output, check, injection_guard.corpus())

    for issue in issues:
        errors.append(
            ErrorInfo(
                kind="validation",
                code=f"E_STEERING_{issue.rule.upper()}",
                message=f"{issue.rule}: {issue.subject or issue.detail}",
            )
        )
    return output


def _failed(
    check: Check,
    target: str,
    run_id: str,
    started: datetime,
    errors: list[ErrorInfo],
    trace: TraceCollector,
) -> CheckResult:
    """A result for a run that never got far enough to have an answer."""
    return CheckResult.build(
        check=check.name,
        target=target,
        output=CheckOutput(),
        errors=errors,
        trace=trace.steps,
        tools_ran=trace.tools_ran,
        run_id=run_id,
        started_at=started,
        finished_at=datetime.now(UTC),
    )
