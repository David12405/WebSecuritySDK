"""Stage B domain models: context in, structured plan out, typed result envelope.

The planner is handed a `PlanningContext` whose every identifier code has already
resolved, and it answers with a `TestPlanDraft` that contains no identifiers at
all - dependencies are positions in its own list, never ids. Code then allocates
`plan_id`/`test_case_id`, copies the target binding from the resolved context, and
builds the canonical `StructuredTestPlan`. A model cannot express an id that does
not exist, so it cannot leak one into a plan.

`PlanningPreparationResult` is the single typed envelope the coordinator returns
for every expected operational outcome; exceptions are reserved for programmer
invariants.
"""

from __future__ import annotations

from datetime import datetime
from enum import StrEnum
from typing import Annotated, Literal

from pydantic import BaseModel, ConfigDict, Field, StringConstraints, model_validator

from ...domain.analysis_models import (
    ExpectedSignal,
    Hypothesis,
    InputCandidate,
    SinkCandidate,
    ValidationCapability,
)
from ...domain.enums import InputLocation
from ...domain.models import EndpointDefinition, ExecutionPolicy, StrictModel
from ..contracts import SQLiSafetyPolicy, SQLiTechnique
from ..stage_a.models import AdmittedTactic

PlanId = Annotated[str, StringConstraints(pattern=r"^PLAN-[0-9]{3,}$")]
TestCaseId = Annotated[str, StringConstraints(pattern=r"^TC-[0-9]{3,}$")]


class StopCondition(StrEnum):
    """Typed predicates Module 3 evaluates; never free text, never code."""

    AUTH_FAILURE = "AUTH_FAILURE"
    RATE_LIMITED = "RATE_LIMITED"
    WAF_OR_FILTER_DETECTED = "WAF_OR_FILTER_DETECTED"
    TARGET_UNSTABLE = "TARGET_UNSTABLE"
    BASELINE_NOT_READY = "BASELINE_NOT_READY"
    BUDGET_EXHAUSTED = "BUDGET_EXHAUSTED"
    VERIFIED_PROOF_FOUND = "VERIFIED_PROOF_FOUND"


# --------------------------------------------------------------------------- #
# Request/auth resolution (a trusted port, not an LLM tool)
# --------------------------------------------------------------------------- #


class ResolvedRequestTemplate(StrictModel):
    """Opaque request reference plus only the metadata safe to show a model."""

    request_template_ref: str = Field(min_length=1)
    method: str = Field(min_length=1)
    origin: str = Field(min_length=1)
    path: str = Field(min_length=1)
    input_location: InputLocation
    auth_required: bool = False
    auth_available: bool = False
    auth_ref: str | None = None


# --------------------------------------------------------------------------- #
# The immutable context code assembles for the planner
# --------------------------------------------------------------------------- #


class GuardedHypothesisContext(StrictModel):
    """A guarded hypothesis with its verified correlation provenance."""

    hypothesis: Hypothesis
    correlation_ref: str = Field(min_length=1)


class PlanningContext(StrictModel):
    """Everything the planner needs, with every id already resolved by code."""

    guarded: GuardedHypothesisContext
    input_candidate: InputCandidate
    endpoint: EndpointDefinition
    sink: SinkCandidate | None = None
    expected_signals: list[ExpectedSignal] = Field(default_factory=list)
    validation_capability: ValidationCapability
    evidence_refs: list[str] = Field(default_factory=list)
    observation_refs: list[str] = Field(default_factory=list)
    execution_policy: ExecutionPolicy
    authorized_scope: list[str] = Field(min_length=1)
    request_template: ResolvedRequestTemplate
    dbms_hint: str | None = None
    tactic: AdmittedTactic
    safety_policy: SQLiSafetyPolicy

    @property
    def hypothesis(self) -> Hypothesis:
        return self.guarded.hypothesis


# --------------------------------------------------------------------------- #
# The model's output: a plan draft with no identifiers
# --------------------------------------------------------------------------- #


class DraftModel(BaseModel):
    model_config = ConfigDict(extra="forbid")


class TestCaseDraft(DraftModel):
    """One test case as the model proposes it - positions, never ids."""

    __test__ = False  # not a pytest test class despite the name

    tactic_step_ref: str = Field(min_length=1)
    capability_id: str = Field(min_length=1)
    technique: SQLiTechnique | None = None
    purpose: str = Field(min_length=1)
    depends_on: list[int] = Field(
        default_factory=list,
        description="Positions of earlier test cases in this list this one depends on.",
    )
    # ge=1 here, not ge=2 like the HTTP_REQUEST contract: a single-sample draft is
    # accepted so validation can reject it with a readable budget violation instead
    # of a raw ValidationError. max_requests defaults high enough to cover the
    # default sample_count - a baseline case must afford every sample it asks for.
    sample_count: int = Field(default=2, ge=1, le=5)
    max_requests: int = Field(default=2, ge=1)
    timeout_seconds: int = Field(default=15, ge=1)
    expected_signals: list[ExpectedSignal] = Field(default_factory=list)
    required_control_observations: int = Field(default=1, ge=0)
    evidence_requirements: list[str] = Field(default_factory=list)
    stop_conditions: list[StopCondition] = Field(default_factory=list)
    optional: bool = False


class TestPlanDraft(DraftModel):
    """The whole plan as the model proposes it."""

    __test__ = False  # not a pytest test class despite the name

    test_cases: list[TestCaseDraft] = Field(default_factory=list)
    expected_terminal_outcomes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)


# --------------------------------------------------------------------------- #
# The canonical, admitted plan
# --------------------------------------------------------------------------- #


class TacticRef(StrictModel):
    tactic_id: str
    tactic_version: str
    content_sha256: str = Field(pattern=r"^[a-f0-9]{64}$")


class TargetBinding(StrictModel):
    endpoint_ref: str = Field(min_length=1)
    input_ref: str = Field(min_length=1)
    request_template_ref: str = Field(min_length=1)
    auth_ref: str | None = None


class ExecutionLimits(StrictModel):
    aggregate_max_requests: int = Field(ge=1)
    detection_timeout_seconds: int = Field(ge=1)


class TestCase(StrictModel):
    """One admitted test case; ids and bindings are code's, not the model's."""

    __test__ = False  # not a pytest test class despite the name

    test_case_id: TestCaseId
    tactic_step_ref: str = Field(min_length=1)
    capability_id: str = Field(min_length=1)
    technique: SQLiTechnique | None = None
    purpose: str = Field(min_length=1)
    dependencies: list[TestCaseId] = Field(default_factory=list)
    capability_arguments: dict = Field(default_factory=dict)
    expected_signals: list[ExpectedSignal] = Field(default_factory=list)
    required_control_observations: int = Field(default=1, ge=0)
    evidence_requirements: list[str] = Field(default_factory=list)
    stop_conditions: list[StopCondition] = Field(default_factory=list)
    max_requests: int = Field(ge=1)
    timeout_seconds: int = Field(ge=1)
    optional: bool = False


class PlanProvenance(StrictModel):
    planner_model: str
    prompt_version: str
    tactic_version: str
    attempts: int = Field(ge=1)
    created_at: datetime


class StructuredTestPlan(StrictModel):
    schema_version: Literal["0.1.0"] = "0.1.0"
    plan_id: PlanId
    hypothesis_ref: str = Field(min_length=1)
    correlation_ref: str = Field(min_length=1)
    tactic_ref: TacticRef
    target_binding: TargetBinding
    execution_limits: ExecutionLimits
    test_cases: list[TestCase] = Field(min_length=1)
    expected_terminal_outcomes: list[str] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    provenance: PlanProvenance


# --------------------------------------------------------------------------- #
# Typed preparation result
# --------------------------------------------------------------------------- #


class PlanningStatus(StrEnum):
    READY = "READY"
    UNSUPPORTED = "UNSUPPORTED"
    INCONCLUSIVE = "INCONCLUSIVE"
    POLICY_BLOCKED = "POLICY_BLOCKED"
    ERROR = "ERROR"


class PlanningStage(StrEnum):
    HYPOTHESIS_GUARD = "HYPOTHESIS_GUARD"
    TACTIC_RESOLUTION = "TACTIC_RESOLUTION"
    WSTG_RETRIEVAL = "WSTG_RETRIEVAL"
    TACTIC_AUTHORING = "TACTIC_AUTHORING"
    CONTEXT_BINDING = "CONTEXT_BINDING"
    PLAN_AUTHORING = "PLAN_AUTHORING"
    PLAN_VALIDATION = "PLAN_VALIDATION"
    STORAGE = "STORAGE"


class PlanningPreparationError(StrictModel):
    stage: PlanningStage
    code: str = Field(pattern=r"^E_[A-Z_]+$")
    message: str = Field(min_length=1)
    retryable: bool = False
    attempt_ref: str | None = None


class PlanningPreparationResult(StrictModel):
    status: PlanningStatus
    hypothesis_ref: str
    correlation_ref: str | None = None
    tactic_ref: TacticRef | None = None
    plan: StructuredTestPlan | None = None
    errors: list[PlanningPreparationError] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    trace: list[str] = Field(default_factory=list)

    @model_validator(mode="after")
    def plan_iff_ready(self) -> PlanningPreparationResult:
        if (self.status == PlanningStatus.READY) != (self.plan is not None):
            raise ValueError("a plan is present if and only if status is READY")
        return self
