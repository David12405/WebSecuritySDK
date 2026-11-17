"""Assemble a draft into a canonical plan, then admit it through 12 gates.

`assemble_plan` is where a model's identifier-free draft becomes a plan: code
allocates `plan_id` and `test_case_id`, maps each dependency position to the id
of an earlier case (dropping any out-of-range position), copies the target
binding from the resolved context, derives per-capability arguments, and clamps
the execution limits to the policy ceilings. `validate_plan` then runs the
deterministic admission gates; a non-empty return means Module 3 must not run.
"""

from __future__ import annotations

from datetime import datetime

from ...policy.scope_guard import in_scope
from ..contracts import (
    CAPABILITY_CONTRACTS,
    SQLiTechnique,
    validate_capability_arguments,
)
from .models import (
    ExecutionLimits,
    PlanningContext,
    PlanProvenance,
    StructuredTestPlan,
    TacticRef,
    TargetBinding,
    TestCase,
    TestCaseDraft,
    TestPlanDraft,
)

_VALID_OUTCOMES = frozenset(
    {"CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE", "ERROR", "UNSUPPORTED", "POLICY_BLOCKED"}
)


def assemble_plan(
    draft: TestPlanDraft,
    context: PlanningContext,
    *,
    plan_index: int = 1,
    model_name: str,
    prompt_version: str,
    attempts: int,
    now: datetime,
) -> StructuredTestPlan:
    """Turn an identifier-free draft into a canonical, fully-bound plan."""
    plan_id = f"PLAN-{plan_index:03d}"
    case_ids = [f"TC-{i + 1:03d}" for i in range(len(draft.test_cases))]

    test_cases: list[TestCase] = []
    for position, (case_id, draft_case) in enumerate(zip(case_ids, draft.test_cases, strict=True)):
        dependencies = [
            case_ids[dep]
            for dep in draft_case.depends_on
            if isinstance(dep, int) and 0 <= dep < position  # earlier cases only
        ]
        test_cases.append(
            TestCase(
                test_case_id=case_id,
                tactic_step_ref=draft_case.tactic_step_ref,
                capability_id=draft_case.capability_id,
                technique=draft_case.technique,
                purpose=draft_case.purpose,
                dependencies=dependencies,
                capability_arguments=_capability_arguments(draft_case, context),
                expected_signals=list(draft_case.expected_signals),
                required_control_observations=draft_case.required_control_observations,
                evidence_requirements=list(draft_case.evidence_requirements),
                stop_conditions=list(draft_case.stop_conditions),
                max_requests=draft_case.max_requests,
                timeout_seconds=draft_case.timeout_seconds,
                optional=draft_case.optional,
            )
        )

    policy = context.safety_policy
    http_budget = context.execution_policy.http_policy.request_budget
    http_timeout = int(context.execution_policy.http_policy.timeout_seconds)
    limits = ExecutionLimits(
        aggregate_max_requests=min(policy.aggregate_max_requests, http_budget),
        detection_timeout_seconds=min(policy.detection_timeout_seconds, max(http_timeout, 1)),
    )

    meta = context.tactic.metadata
    return StructuredTestPlan(
        plan_id=plan_id,
        hypothesis_ref=context.hypothesis.hypothesis_id,
        correlation_ref=context.guarded.correlation_ref,
        tactic_ref=TacticRef(
            tactic_id=meta.tactic_id,
            tactic_version=meta.tactic_version,
            content_sha256=meta.content_sha256,
        ),
        target_binding=TargetBinding(
            endpoint_ref=context.endpoint.endpoint_id,
            input_ref=context.input_candidate.input_id,
            request_template_ref=context.request_template.request_template_ref,
            auth_ref=context.request_template.auth_ref,
        ),
        execution_limits=limits,
        test_cases=test_cases,
        expected_terminal_outcomes=list(draft.expected_terminal_outcomes),
        limitations=list(draft.limitations),
        provenance=PlanProvenance(
            planner_model=model_name,
            prompt_version=prompt_version,
            tactic_version=meta.tactic_version,
            attempts=attempts,
            created_at=now,
        ),
    )


def _capability_arguments(draft_case: TestCaseDraft, context: PlanningContext) -> dict:
    """Derive the per-capability arguments code owns; built as a plain dict so
    assembly never raises - validation catches an inadmissible shape."""
    if draft_case.capability_id == "HTTP_REQUEST":
        return {
            "sample_count": draft_case.sample_count,
            "timeout_seconds": draft_case.timeout_seconds,
        }
    if draft_case.capability_id == "SQLI_DETECTION":
        techniques = [draft_case.technique.value] if draft_case.technique is not None else []
        return {
            "techniques": techniques,
            "risk_profile": context.safety_policy.risk_profile.value,
            "max_requests": draft_case.max_requests,
            "timeout_seconds": draft_case.timeout_seconds,
            "dbms_hint": context.dbms_hint,
        }
    return {}


# --------------------------------------------------------------------------- #
# Admission gates
# --------------------------------------------------------------------------- #


def validate_plan(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    """Run every plan admission gate; return violations (empty = admissible)."""
    out: list[str] = []
    out.extend(_gate_references(plan, context))
    out.extend(_gate_tactic_match(plan, context))
    out.extend(_gate_steps_and_capabilities(plan, context))
    out.extend(_gate_capability_arguments(plan))
    out.extend(_gate_dependencies(plan))
    out.extend(_gate_scope(plan, context))
    out.extend(_gate_budgets(plan, context))
    out.extend(_gate_time_prerequisites(plan, context))
    out.extend(_gate_evidence_and_shape(plan, context))
    out.extend(_gate_outcomes(plan))
    return out


def _gate_references(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    if plan.hypothesis_ref != context.hypothesis.hypothesis_id:
        out.append("references: plan hypothesis_ref does not match the guarded hypothesis")
    if plan.correlation_ref != context.guarded.correlation_ref:
        out.append("references: plan correlation_ref does not match verified provenance")
    if plan.target_binding.endpoint_ref != context.endpoint.endpoint_id:
        out.append("references: target endpoint_ref does not match the hypothesis endpoint")
    if plan.target_binding.input_ref != context.input_candidate.input_id:
        out.append("references: target input_ref does not match the hypothesis input")
    if plan.target_binding.request_template_ref != context.request_template.request_template_ref:
        out.append("references: request_template_ref does not match the resolved template")
    return out


def _gate_tactic_match(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    meta = context.tactic.metadata
    ref = plan.tactic_ref
    if ref.tactic_id != meta.tactic_id or ref.tactic_version != meta.tactic_version:
        out.append("tactic: plan tactic_ref does not match the active tactic supplied")
    if ref.content_sha256 != meta.content_sha256:
        out.append("tactic: plan tactic content hash does not match the active tactic")
    return out


def _gate_steps_and_capabilities(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    step_ids = {step.id for step in context.tactic.document.steps}
    declared = {cap.id for cap in context.tactic.document.capabilities}
    for case in plan.test_cases:
        if case.tactic_step_ref not in step_ids:
            out.append(
                f"steps: {case.test_case_id} references unknown tactic step {case.tactic_step_ref}"
            )
        if case.capability_id not in declared:
            out.append(
                f"capability: {case.test_case_id} uses {case.capability_id}, "
                "not declared by the tactic"
            )
        if case.capability_id not in CAPABILITY_CONTRACTS:
            out.append(
                f"capability: {case.test_case_id} uses {case.capability_id}, "
                "not available in Module 3"
            )
    return out


def _gate_capability_arguments(plan: StructuredTestPlan) -> list[str]:
    out: list[str] = []
    for case in plan.test_cases:
        out.extend(
            f"{case.test_case_id}: {msg}"
            for msg in validate_capability_arguments(case.capability_id, case.capability_arguments)
        )
    return out


def _gate_dependencies(plan: StructuredTestPlan) -> list[str]:
    out: list[str] = []
    seen: set[str] = set()
    ids = {case.test_case_id for case in plan.test_cases}
    for case in plan.test_cases:
        for dep in case.dependencies:
            if dep not in ids:
                out.append(f"dependencies: {case.test_case_id} depends on unknown {dep}")
            elif dep not in seen:
                out.append(
                    f"dependencies: {case.test_case_id} depends on {dep}, "
                    "which is not an earlier case"
                )
        seen.add(case.test_case_id)
    return out


def _gate_scope(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    # Reuse the project's authoritative scope rules (host/port/path/subdomain).
    # Module 1 may record scope as a bare host; coerce it to https:// so the
    # normalizer, which requires a scheme, does not reject a legitimate config.
    target = f"{context.request_template.origin}{context.request_template.path}"
    scope = [
        entry if "://" in entry else f"https://{entry}" for entry in context.authorized_scope
    ]
    try:
        decision = in_scope(target, scope)
    except ValueError as exc:
        return [f"scope: authorized scope is malformed: {exc}"]
    if decision.allowed:
        return []
    return [f"scope: target {target} is not within the authorized scope ({decision.reason})"]


def _gate_budgets(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    policy = context.safety_policy
    total = sum(case.max_requests for case in plan.test_cases)
    aggregate_limit = plan.execution_limits.aggregate_max_requests
    if total > aggregate_limit:
        out.append(f"budget: aggregate {total} exceeds limit {aggregate_limit}")
    http_budget = context.execution_policy.http_policy.request_budget
    if total > http_budget:
        out.append(
            f"budget: aggregate {total} exceeds execution policy request_budget {http_budget}"
        )
    for case in plan.test_cases:
        if case.technique is not None:
            ceiling = policy.max_requests_for(case.technique)
            if case.max_requests > ceiling:
                out.append(
                    f"budget: {case.test_case_id} max_requests {case.max_requests} "
                    f"exceeds {case.technique.value} ceiling {ceiling}"
                )
        if case.timeout_seconds > policy.detection_timeout_seconds:
            out.append(
                f"budget: {case.test_case_id} timeout {case.timeout_seconds} "
                f"exceeds ceiling {policy.detection_timeout_seconds}"
            )
    return out


def _gate_time_prerequisites(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    baseline_ids = {
        case.test_case_id for case in plan.test_cases if case.capability_id == "HTTP_REQUEST"
    }
    allowed = set(context.safety_policy.allowed_techniques)
    for case in plan.test_cases:
        if case.technique == SQLiTechnique.TIME:
            if SQLiTechnique.TIME not in allowed:
                out.append(f"time: {case.test_case_id} uses TIME, which the policy disallows")
            if not case.optional:
                out.append(f"time: {case.test_case_id} TIME detection must be optional")
            if context.safety_policy.require_stable_baseline_for_time and not (
                set(case.dependencies) & baseline_ids
            ):
                out.append(
                    f"time: {case.test_case_id} TIME detection must depend on a baseline case"
                )
    return out


def _gate_evidence_and_shape(plan: StructuredTestPlan, context: PlanningContext) -> list[str]:
    out: list[str] = []
    allowed = {t.value for t in context.safety_policy.allowed_techniques}
    has_baseline = any(c.capability_id == "HTTP_REQUEST" for c in plan.test_cases)
    has_detection = any(c.capability_id == "SQLI_DETECTION" for c in plan.test_cases)
    if not has_baseline:
        out.append("shape: plan has no HTTP_REQUEST baseline case")
    if not has_detection:
        out.append("shape: plan has no SQLI_DETECTION case")
    for case in plan.test_cases:
        if case.capability_id == "SQLI_DETECTION":
            if case.technique is None:
                out.append(f"shape: {case.test_case_id} is a detection case with no technique")
            elif case.technique.value not in allowed:
                out.append(
                    f"shape: {case.test_case_id} technique {case.technique.value} "
                    "is outside the safety policy"
                )
            if not case.evidence_requirements:
                out.append(
                    f"evidence: {case.test_case_id} detection case needs evidence requirements"
                )
    return out


def _gate_outcomes(plan: StructuredTestPlan) -> list[str]:
    stray = [o for o in plan.expected_terminal_outcomes if o not in _VALID_OUTCOMES]
    if stray:
        return [f"outcomes: unknown terminal outcome(s) {stray}"]
    return []
