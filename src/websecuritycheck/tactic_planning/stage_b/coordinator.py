"""`prepare_sql_injection_plan` - the public Stage A + Stage B entry point.

It resolves one hypothesis inside a `GenerationResult`, re-runs the hypothesis
guard against the sealed Module 2 envelope, resolves or authors the global SQLi
tactic (Stage A), assembles a fully-bound planning context, drives the planner
and the plan admission gates (Stage B), and returns a single typed
`PlanningPreparationResult`. It never executes Module 3.

Expected operational outcomes are returned in the envelope; exceptions are
reserved for programmer invariants (an unknown hypothesis id, provenance the
caller never recorded) where continuing would mean API misuse.
"""

from __future__ import annotations

from datetime import UTC, datetime

from ...analysis.correlation import Module2CorrelationEnvelope
from ...domain.analysis_models import (
    CATEGORY_TO_CAPABILITY,
    Hypothesis,
    Module2AnalysisRequest,
    VulnerabilityCategory,
)
from ...domain.enums import TechnologyCategory
from ...hypothesis.generate import GenerationResult
from ...hypothesis.guard import HypothesisGuardError, enforce
from ..contracts import SQLiSafetyPolicy
from ..stage_a.author import TacticAuthor
from ..stage_a.registry import TacticRegistry
from ..stage_a.resolver import TacticResolutionError, resolve_tactic
from ..stage_a.wstg import WstgAdapter, WstgRetrievalError
from .models import (
    GuardedHypothesisContext,
    PlanningContext,
    PlanningPreparationError,
    PlanningPreparationResult,
    PlanningStage,
    PlanningStatus,
    TacticRef,
)
from .planner import (
    PROMPT_VERSION,
    DefaultRequestTemplateResolver,
    Planner,
    RequestTemplateResolver,
)
from .validation import assemble_plan, validate_plan

DEFAULT_MAX_PLAN_RETRIES = 2


def prepare_sql_injection_plan(
    generation: GenerationResult,
    hypothesis_id: str,
    envelope: Module2CorrelationEnvelope,
    request: Module2AnalysisRequest,
    *,
    registry: TacticRegistry,
    author: TacticAuthor,
    planner: Planner,
    wstg_adapter: WstgAdapter,
    safety_policy: SQLiSafetyPolicy,
    model_name: str,
    request_resolver: RequestTemplateResolver | None = None,
    max_tactic_retries: int = 2,
    max_plan_retries: int = DEFAULT_MAX_PLAN_RETRIES,
    now: datetime | None = None,
) -> PlanningPreparationResult:
    now = now or datetime.now(UTC)
    request_resolver = request_resolver or DefaultRequestTemplateResolver()
    trace: list[str] = []

    hypothesis = _require_hypothesis(generation, hypothesis_id)
    correlation_ref = _require_provenance(generation, hypothesis_id)

    # Re-run the guard against the sealed envelope: a hypothesis that no longer
    # survives its own provenance must never be planned.
    try:
        enforce(
            generation.hypotheses,
            envelope.output,
            list(envelope.correlation.records),
            generation.provenance,
        )
    except HypothesisGuardError as exc:
        return _fail(
            hypothesis_id,
            PlanningStatus.ERROR,
            PlanningStage.HYPOTHESIS_GUARD,
            "E_HYPOTHESIS_GUARD",
            f"hypothesis guard rejected the handoff: {exc}",
            trace,
        )
    trace.append("guard: hypothesis re-validated against the sealed envelope")

    if hypothesis.vulnerability_category != VulnerabilityCategory.SQL_INJECTION:
        return _fail(
            hypothesis_id,
            PlanningStatus.UNSUPPORTED,
            PlanningStage.CONTEXT_BINDING,
            "E_CATEGORY_UNSUPPORTED",
            f"the SQLi MVP does not support {hypothesis.vulnerability_category.value}",
            trace,
        )

    if not safety_policy.enabled:
        return _fail(
            hypothesis_id,
            PlanningStatus.POLICY_BLOCKED,
            PlanningStage.CONTEXT_BINDING,
            "E_SQLI_NOT_AUTHORIZED",
            "active SQLi testing is not authorized (SQLiSafetyPolicy.enabled is false)",
            trace,
        )

    # --- Stage A: resolve or author the tactic ------------------------------ #
    try:
        resolved = resolve_tactic(
            VulnerabilityCategory.SQL_INJECTION,
            registry=registry,
            author=author,
            adapter=wstg_adapter,
            safety_policy=safety_policy,
            model_name=model_name,
            max_retries=max_tactic_retries,
            now=now,
        )
    except WstgRetrievalError as exc:
        return _fail(
            hypothesis_id,
            PlanningStatus.INCONCLUSIVE,
            PlanningStage.WSTG_RETRIEVAL,
            "E_WSTG_UNAVAILABLE",
            f"WSTG retrieval failed: {exc}",
            trace,
            retryable=True,
        )
    except TacticResolutionError as exc:
        return _fail(
            hypothesis_id,
            PlanningStatus.INCONCLUSIVE,
            PlanningStage.TACTIC_AUTHORING,
            "E_TACTIC_UNAVAILABLE",
            f"tactic authoring failed: {exc}",
            trace,
            retryable=True,
            correlation_ref=correlation_ref,
        )
    trace.extend(resolved.trace)
    tactic = resolved.tactic
    tactic_ref = TacticRef(
        tactic_id=tactic.metadata.tactic_id,
        tactic_version=tactic.metadata.tactic_version,
        content_sha256=tactic.metadata.content_sha256,
    )

    # --- Context binding ---------------------------------------------------- #
    context, binding_error = _bind_context(
        hypothesis=hypothesis,
        correlation_ref=correlation_ref,
        envelope=envelope,
        request=request,
        tactic=tactic,
        safety_policy=safety_policy,
        request_resolver=request_resolver,
        trace=trace,
    )
    if binding_error is not None:
        binding_error.correlation_ref = correlation_ref
        binding_error.tactic_ref = tactic_ref
        return binding_error

    assert context is not None

    # --- Stage B: plan and admit -------------------------------------------- #
    feedback: list[str] = []
    last_violations: list[str] = []
    for attempt in range(max_plan_retries + 1):
        try:
            draft = planner.plan(context, attempt=attempt, feedback=feedback)
        except Exception as exc:
            trace.append(f"plan: attempt {attempt} raised {type(exc).__name__}")
            last_violations = [f"planner error: {exc}"]
            feedback = last_violations
            continue

        plan = assemble_plan(
            draft,
            context,
            model_name=model_name,
            prompt_version=PROMPT_VERSION,
            attempts=attempt + 1,
            now=now,
        )
        violations = validate_plan(plan, context)
        if not violations:
            trace.append(f"plan: admitted {plan.plan_id} with {len(plan.test_cases)} case(s)")
            return PlanningPreparationResult(
                status=PlanningStatus.READY,
                hypothesis_ref=hypothesis_id,
                correlation_ref=correlation_ref,
                tactic_ref=tactic_ref,
                plan=plan,
                trace=trace,
            )
        trace.append(f"plan: attempt {attempt} rejected ({len(violations)} violation(s))")
        last_violations = violations
        feedback = violations

    result = _fail(
        hypothesis_id,
        PlanningStatus.INCONCLUSIVE,
        PlanningStage.PLAN_VALIDATION,
        "E_PLAN_UNAVAILABLE",
        f"no admissible plan after {max_plan_retries + 1} attempt(s)",
        trace,
        retryable=True,
        correlation_ref=correlation_ref,
    )
    result.tactic_ref = tactic_ref
    result.limitations = last_violations
    return result


# --------------------------------------------------------------------------- #
# Helpers
# --------------------------------------------------------------------------- #


def _require_hypothesis(generation: GenerationResult, hypothesis_id: str) -> Hypothesis:
    for hypothesis in generation.hypotheses:
        if hypothesis.hypothesis_id == hypothesis_id:
            return hypothesis
    raise ValueError(f"hypothesis {hypothesis_id} is not in this GenerationResult")


def _require_provenance(generation: GenerationResult, hypothesis_id: str) -> str:
    correlation_ref = generation.provenance.get(hypothesis_id)
    if not correlation_ref:
        raise ValueError(
            f"hypothesis {hypothesis_id} has no recorded correlation provenance; "
            "refusing to infer it"
        )
    return correlation_ref


def _bind_context(
    *,
    hypothesis: Hypothesis,
    correlation_ref: str,
    envelope: Module2CorrelationEnvelope,
    request: Module2AnalysisRequest,
    tactic,
    safety_policy: SQLiSafetyPolicy,
    request_resolver: RequestTemplateResolver,
    trace: list[str],
) -> tuple[PlanningContext | None, PlanningPreparationResult | None]:
    output = envelope.output
    inputs = {item.input_id: item for item in output.inputs}
    sinks = {item.sink_id: item for item in output.sink_candidates}
    endpoints = {ep.endpoint_id: ep for ep in request.target_model.endpoints}

    input_candidate = inputs.get(hypothesis.input_ref or "")
    if input_candidate is None:
        return None, _fail(
            hypothesis.hypothesis_id,
            PlanningStatus.INCONCLUSIVE,
            PlanningStage.CONTEXT_BINDING,
            "E_INPUT_UNRESOLVED",
            "the hypothesis input could not be resolved in the envelope",
            trace,
        )
    endpoint = endpoints.get(hypothesis.target_endpoint_id or "")
    if endpoint is None:
        return None, _fail(
            hypothesis.hypothesis_id,
            PlanningStatus.INCONCLUSIVE,
            PlanningStage.CONTEXT_BINDING,
            "E_ENDPOINT_UNRESOLVED",
            "the hypothesis endpoint is not present in the Module 1 target model",
            trace,
        )

    assessment = request.target_model.scope_rules
    if assessment is None:
        return None, _fail(
            hypothesis.hypothesis_id,
            PlanningStatus.ERROR,
            PlanningStage.CONTEXT_BINDING,
            "E_NO_ASSESSMENT_CONFIG",
            "the target model carries no assessment configuration to scope the plan",
            trace,
        )

    sink = sinks.get(hypothesis.sink_ref) if hypothesis.sink_ref else None
    expected_signals = (
        hypothesis.validation_proposals[0].expected_signals
        if hypothesis.validation_proposals
        else []
    )
    dbms_hint = next(
        (
            tech.name
            for tech in request.target_model.technologies
            if tech.category == TechnologyCategory.DATABASE
        ),
        None,
    )

    template = request_resolver.resolve(
        endpoint=endpoint,
        input_candidate=input_candidate,
        auth_references=assessment.auth_references,
        request_artifact_ref=None,
    )
    if template.auth_required and not template.auth_available:
        return None, _fail(
            hypothesis.hypothesis_id,
            PlanningStatus.INCONCLUSIVE,
            PlanningStage.CONTEXT_BINDING,
            "E_AUTH_UNRESOLVED",
            "endpoint requires authentication but no AuthReferenceConfig resolves it",
            trace,
        )
    trace.append(f"bind: resolved request template {template.request_template_ref}")

    context = PlanningContext(
        guarded=GuardedHypothesisContext(
            hypothesis=hypothesis, correlation_ref=correlation_ref
        ),
        input_candidate=input_candidate,
        endpoint=endpoint,
        sink=sink,
        expected_signals=expected_signals,
        validation_capability=CATEGORY_TO_CAPABILITY[hypothesis.vulnerability_category],
        evidence_refs=list(hypothesis.supporting_evidence_refs),
        observation_refs=list(hypothesis.supporting_observation_refs),
        execution_policy=assessment.execution_policy,
        authorized_scope=list(assessment.authorized_scope),
        request_template=template,
        dbms_hint=dbms_hint,
        tactic=tactic,
        safety_policy=safety_policy,
    )
    return context, None


def _fail(
    hypothesis_id: str,
    status: PlanningStatus,
    stage: PlanningStage,
    code: str,
    message: str,
    trace: list[str],
    *,
    retryable: bool = False,
    correlation_ref: str | None = None,
) -> PlanningPreparationResult:
    return PlanningPreparationResult(
        status=status,
        hypothesis_ref=hypothesis_id,
        correlation_ref=correlation_ref,
        errors=[
            PlanningPreparationError(
                stage=stage, code=code, message=message, retryable=retryable
            )
        ],
        trace=list(trace),
    )