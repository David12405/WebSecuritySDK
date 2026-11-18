"""Human-readable rendering of an admitted test plan.

A plan is the Module 3 hand-off, so being able to print it in full - every test
case with its capability, bounded arguments, evidence requirements, and stop
conditions - is useful for review, logging, and the Module 3 team, not just the
example. Display only; it never changes a plan.
"""

from __future__ import annotations

from .models import StructuredTestPlan, TestCase


def _format_case(case: TestCase) -> list[str]:
    technique = f"/{case.technique.value}" if case.technique else ""
    flag = "optional" if case.optional else "mandatory"
    deps = ", ".join(case.dependencies) or "-"
    signals = ", ".join(s.value for s in case.expected_signals) or "-"
    evidence = "; ".join(case.evidence_requirements) or "-"
    stops = ", ".join(s.value for s in case.stop_conditions) or "-"
    args = ", ".join(f"{k}={v}" for k, v in case.capability_arguments.items()) or "-"
    return [
        f"    {case.test_case_id}  {case.capability_id}{technique}  "
        f"step={case.tactic_step_ref}  [{flag}]",
        f"        purpose:  {case.purpose}",
        f"        depends:  {deps}",
        f"        args:     {args}",
        f"        signals:  {signals}",
        f"        evidence: {evidence}",
        f"        stop if:  {stops}",
        f"        budget:   {case.max_requests} requests, {case.timeout_seconds}s timeout",
    ]


def format_test_plan(plan: StructuredTestPlan) -> str:
    """Render the whole plan - header, bindings, limits, and every test case."""
    binding = plan.target_binding
    outcomes = ", ".join(plan.expected_terminal_outcomes) or "-"
    lines = [
        f"{plan.plan_id}  for {plan.hypothesis_ref}  "
        f"(tactic {plan.tactic_ref.tactic_id} v{plan.tactic_ref.tactic_version}, "
        f"sha {plan.tactic_ref.content_sha256[:12]})",
        f"  correlation: {plan.correlation_ref}",
        f"  target:  endpoint {binding.endpoint_ref} / input {binding.input_ref} / "
        f"template {binding.request_template_ref} / auth {binding.auth_ref or 'none'}",
        f"  limits:  aggregate<={plan.execution_limits.aggregate_max_requests} requests, "
        f"detection timeout<={plan.execution_limits.detection_timeout_seconds}s",
        f"  expected terminal outcomes: {outcomes}",
        f"  test cases ({len(plan.test_cases)}):",
    ]
    for case in plan.test_cases:
        lines.extend(_format_case(case))
    if plan.limitations:
        lines.append("  limitations:")
        lines.extend(f"    - {item}" for item in plan.limitations)
    return "\n".join(lines)
