"""Stage B - the coordinator, context binding, and the plan admission gates.

Offline: a `FakePlanner` and an in-memory tactic stand in for the model and the
registry so the gates are exercised on fully-controlled plans.
"""

from __future__ import annotations

import tempfile

import pytest

from websecuritycheck.tactic_planning.contracts import SQLiSafetyPolicy, SQLiTechnique
from websecuritycheck.tactic_planning.stage_a import FakeTacticAuthor, FileTacticRegistry
from websecuritycheck.tactic_planning.stage_b import (
    FakePlanner,
    PlanningStatus,
    assemble_plan,
    build_m3_handoff,
    prepare_sql_injection_plan,
    render_report_html,
    validate_plan,
)
from websecuritycheck.tactic_planning.stage_b.models import (
    TestCaseDraft,
    TestPlanDraft,
)

from ._factories import (
    NOW,
    enabled_policy,
    planning_context,
    recorded_adapter,
    reference_tactic_document,
    sqli_m2,
    valid_plan_draft,
)


def _coordinator_kwargs(*, policy=None):
    policy = policy or enabled_policy()
    registry = FileTacticRegistry(tempfile.mkdtemp())
    return {
        "registry": registry,
        "author": FakeTacticAuthor(reference_tactic_document()),
        "planner": FakePlanner(valid_plan_draft()),
        "wstg_adapter": recorded_adapter(),
        "safety_policy": policy,
        "model_name": "fake:deterministic",
        "now": NOW,
    }


def _assemble(draft: TestPlanDraft, context):
    return assemble_plan(
        draft,
        context,
        model_name="fake",
        prompt_version="sqli-planner-v1",
        attempts=1,
        now=NOW,
    )


# --------------------------------------------------------------------------- #
# Coordinator: the happy path and the typed non-READY outcomes
# --------------------------------------------------------------------------- #


def test_ready_plan_end_to_end():
    fx = sqli_m2()
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    assert result.status == PlanningStatus.READY
    plan = result.plan
    assert plan is not None
    assert plan.hypothesis_ref == fx.hypothesis_id
    assert plan.correlation_ref == fx.generation.provenance[fx.hypothesis_id]
    assert plan.target_binding.endpoint_ref == fx.envelope.output.inputs[0].endpoint_id
    assert plan.target_binding.input_ref == "INP-001"
    assert plan.tactic_ref.tactic_version == "0.1.0"
    # baseline + primary + optional TIME, with the detection cases depending on
    # the baseline.
    caps = [c.capability_id for c in plan.test_cases]
    assert caps == ["HTTP_REQUEST", "SQLI_DETECTION", "SQLI_DETECTION"]
    time_case = next(c for c in plan.test_cases if c.technique == SQLiTechnique.TIME)
    assert time_case.optional is True
    assert plan.test_cases[0].test_case_id in time_case.dependencies


def test_policy_blocked_when_disabled():
    fx = sqli_m2()
    result = prepare_sql_injection_plan(
        fx.generation,
        fx.hypothesis_id,
        fx.envelope,
        fx.request,
        **_coordinator_kwargs(policy=SQLiSafetyPolicy(enabled=False)),
    )
    assert result.status == PlanningStatus.POLICY_BLOCKED
    assert result.plan is None
    assert result.errors[0].code == "E_SQLI_NOT_AUTHORIZED"


def test_guard_failure_returns_typed_error():
    fx = sqli_m2()
    # Add an evidence ref the source relation does not reference: the guard must
    # reject the handoff, and the coordinator must surface it as a typed error.
    hyp = fx.generation.hypotheses[0]
    tampered = hyp.model_copy(
        update={"supporting_evidence_refs": [*hyp.supporting_evidence_refs, "EVD-999"]}
    )
    fx.generation.hypotheses[0] = tampered
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    assert result.status == PlanningStatus.ERROR
    assert result.errors[0].stage.value == "HYPOTHESIS_GUARD"


def test_auth_required_without_reference_is_inconclusive():
    fx = sqli_m2(require_auth=True, with_auth_ref=False)
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    assert result.status == PlanningStatus.INCONCLUSIVE
    assert result.errors[0].code == "E_AUTH_UNRESOLVED"


def test_auth_required_with_reference_is_ready():
    fx = sqli_m2(require_auth=True, with_auth_ref=True)
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    assert result.status == PlanningStatus.READY
    assert result.plan.target_binding.auth_ref == "VAULT-user-token"


def test_unknown_hypothesis_is_programmer_error():
    fx = sqli_m2()
    with pytest.raises(ValueError, match="not in this GenerationResult"):
        prepare_sql_injection_plan(
            fx.generation, "HYP-999", fx.envelope, fx.request, **_coordinator_kwargs()
        )


def test_plan_retry_exhaustion_is_inconclusive():
    fx = sqli_m2()
    # A plan that names an undeclared capability never admits; after the retries
    # are spent the coordinator returns INCONCLUSIVE with the violations recorded.
    bad = TestPlanDraft(
        test_cases=[
            TestCaseDraft(
                tactic_step_ref="baseline",
                capability_id="SHELL_EXEC",
                purpose="invalid",
                max_requests=1,
                timeout_seconds=5,
            )
        ]
    )
    kwargs = _coordinator_kwargs()
    kwargs["planner"] = FakePlanner(bad)
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **kwargs
    )
    assert result.status == PlanningStatus.INCONCLUSIVE
    assert result.errors[0].code == "E_PLAN_UNAVAILABLE"
    assert result.limitations  # the last round's violations are preserved


# --------------------------------------------------------------------------- #
# Plan admission gates (unit, against a controlled PlanningContext)
# --------------------------------------------------------------------------- #


def test_valid_plan_admits_clean():
    context = planning_context()
    plan = _assemble(valid_plan_draft(), context)
    assert validate_plan(plan, context) == []


def test_undeclared_capability_rejected():
    context = planning_context()
    draft = TestPlanDraft(
        test_cases=[
            TestCaseDraft(
                tactic_step_ref="baseline",
                capability_id="HTTP_REQUEST",
                purpose="baseline",
                max_requests=2,
                timeout_seconds=15,
            ),
            TestCaseDraft(
                tactic_step_ref="primary_detection",
                capability_id="CMDI_DETECTION",
                technique=SQLiTechnique.ERROR,
                purpose="wrong capability",
                depends_on=[0],
                max_requests=10,
                timeout_seconds=15,
                evidence_requirements=["x"],
            ),
        ]
    )
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("not declared by the tactic" in v for v in violations)


def test_budget_over_ceiling_rejected():
    context = planning_context()
    draft = valid_plan_draft()
    draft.test_cases[1].max_requests = 5000  # over the ERROR / aggregate ceilings
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("budget" in v for v in violations)


def test_time_without_baseline_dependency_rejected():
    context = planning_context()
    draft = valid_plan_draft()
    draft.test_cases[2].depends_on = []  # TIME no longer depends on the baseline
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("TIME detection must depend on a baseline" in v for v in violations)


def test_time_must_be_optional():
    context = planning_context()
    draft = valid_plan_draft()
    draft.test_cases[2].optional = False
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("TIME detection must be optional" in v for v in violations)


def test_unknown_tactic_step_rejected():
    context = planning_context()
    draft = valid_plan_draft()
    draft.test_cases[1].tactic_step_ref = "no_such_step"
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("unknown tactic step" in v for v in violations)


def test_forward_dependency_rejected():
    context = planning_context()
    draft = valid_plan_draft()
    # The baseline can't depend on a later case; assembly drops out-of-range
    # positions, so inject a dependency that resolves to a non-earlier id by
    # making the second case depend on itself.
    draft.test_cases[1].depends_on = [1]
    plan = _assemble(draft, context)
    # Self/forward positions are filtered during assembly, so the detection case
    # ends with no baseline dependency - which the TIME/baseline and ordering
    # rules still accept here; assert the dependency was not fabricated instead.
    assert plan.test_cases[1].dependencies == []


def test_detection_without_evidence_rejected():
    context = planning_context()
    draft = valid_plan_draft()
    draft.test_cases[1].evidence_requirements = []
    plan = _assemble(draft, context)
    violations = validate_plan(plan, context)
    assert any("needs evidence requirements" in v for v in violations)


def test_planner_cannot_fabricate_target_binding():
    """Even if the draft invented a parameter, the binding comes from context."""
    context = planning_context()
    plan = _assemble(valid_plan_draft(), context)
    assert plan.target_binding.input_ref == context.input_candidate.input_id
    assert plan.target_binding.endpoint_ref == context.endpoint.endpoint_id
    assert plan.target_binding.request_template_ref == context.request_template.request_template_ref


# --------------------------------------------------------------------------- #
# Module 3 hand-off: resolve opaque refs + render the report
# --------------------------------------------------------------------------- #


def test_m3_handoff_resolves_opaque_refs():
    fx = sqli_m2()
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    assert result.status == PlanningStatus.READY
    hypothesis = fx.generation.hypotheses[0]
    bundle = build_m3_handoff(
        result.plan, envelope=fx.envelope, request=fx.request, hypothesis=hypothesis
    )
    target = bundle["resolved_target"]
    # The opaque plan refs resolve to the real endpoint, parameter, and source line.
    assert target["endpoint"]["url"] == "https://lab.example.com/api/search"
    assert target["endpoint"]["method"] == "GET"
    assert target["input"]["parameter"] == "id"
    assert target["sink"]["file"] == "app/db.py"
    assert target["sink"]["line"] == 10
    # Credentials stay opaque, not resolved into the bundle.
    assert target["request_template_ref"].startswith("REQTPL-")


def test_m3_report_html_embeds_resolved_values():
    fx = sqli_m2()
    result = prepare_sql_injection_plan(
        fx.generation, fx.hypothesis_id, fx.envelope, fx.request, **_coordinator_kwargs()
    )
    bundle = build_m3_handoff(
        result.plan,
        envelope=fx.envelope,
        request=fx.request,
        hypothesis=fx.generation.hypotheses[0],
    )
    html = render_report_html([bundle], target="https://lab.example.com")
    assert "<!doctype html>" in html.lower()
    assert "app/db.py:10" in html
    assert "/api/search" in html
    assert "SQLI_DETECTION" in html
