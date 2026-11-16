"""Builders shared by the Stage A and Stage B tests.

A controlled, hand-built SQLi hypothesis plus the Module 1/Module 2 context a
plan needs, and a known-good tactic derived from the approved reference fixture.
Deliberately synthetic: the tests exercise the two stages on data whose every
field is known, rather than on whatever a capture happened to contain.
"""

from __future__ import annotations

from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path

import yaml

from websecuritycheck.analysis.correlation import (
    CorrelationKind,
    CorrelationRecord,
    CorrelationResult,
    CorrelationStatus,
    IndependenceAssessment,
    IndependenceStatus,
    Module2CorrelationEnvelope,
)
from websecuritycheck.analysis.correlation.models import CorrelationCoverage
from websecuritycheck.analysis.cve import InjectionSubtype
from websecuritycheck.domain.analysis_models import (
    CATEGORY_TO_CAPABILITY,
    ConfidenceLevel,
    InputCandidate,
    Module2AnalysisRequest,
    Module2Output,
    SinkCandidate,
    SinkKind,
    SinkRelationship,
    VulnerabilityCategory,
)
from websecuritycheck.domain.enums import AuthMechanism, DiscoverySource, InputLocation
from websecuritycheck.domain.models import (
    AssessmentConfig,
    AuthReferenceConfig,
    EndpointDefinition,
    ExecutionPolicy,
    HttpExecutionPolicy,
    ObservedParameter,
    ScopeApprovalRecord,
    TargetModel,
)
from websecuritycheck.hypothesis import generate_hypotheses
from websecuritycheck.hypothesis.generate import GenerationResult
from websecuritycheck.tactic_planning.contracts import (
    SQLiSafetyPolicy,
    SQLiTechnique,
    capability_fingerprint,
)
from websecuritycheck.tactic_planning.stage_a import (
    AdmittedTactic,
    RecordedWstgAdapter,
    TacticDocument,
)
from websecuritycheck.tactic_planning.stage_a.models import (
    TACTIC_SCHEMA_VERSION,
    CompatibilityFingerprint,
    TacticMetadata,
    TacticState,
    bundled_schema_sha256,
)
from websecuritycheck.tactic_planning.stage_a.resolver import _publish, environment_fingerprint
from websecuritycheck.tactic_planning.stage_b.models import (
    GuardedHypothesisContext,
    PlanningContext,
    StopCondition,
    TestCaseDraft,
    TestPlanDraft,
)
from websecuritycheck.tactic_planning.stage_b.planner import DefaultRequestTemplateResolver

ENDPOINT_ID = "a" * 12
FIXTURES = Path(__file__).resolve().parents[1] / "fixtures"
REF_YAML = FIXTURES / "tactics" / "sqli_testing.reference.yaml"
WSTG_DIR = FIXTURES / "wstg"
NOW = datetime(2026, 11, 16, 12, 0, 0, tzinfo=UTC)


def enabled_policy() -> SQLiSafetyPolicy:
    """The default ceilings, but authorized for active testing."""
    return SQLiSafetyPolicy(enabled=True)


def recorded_adapter() -> RecordedWstgAdapter:
    return RecordedWstgAdapter(WSTG_DIR)


def reference_tactic_document(*, fix_wstg: bool = True) -> TacticDocument:
    """The approved reference tactic; with its WSTG id corrected unless asked not to."""
    data = yaml.safe_load(REF_YAML.read_text(encoding="utf-8"))
    if fix_wstg:
        data["references"] = [
            "WSTG-v42-INPV-05" if ref == "WSTG-INJT-05" else ref for ref in data["references"]
        ]
    return TacticDocument.model_validate(data)


def admitted_tactic(registry, *, policy: SQLiSafetyPolicy | None = None) -> AdmittedTactic:
    """Publish the corrected reference tactic into a registry and return it."""
    policy = policy or enabled_policy()
    snapshot = recorded_adapter().get_test_case("WSTG-INPV-05")
    env_fp = environment_fingerprint(VulnerabilityCategory.SQL_INJECTION, policy)
    return _publish(
        reference_tactic_document(),
        snapshot=snapshot,
        env_fp=env_fp,
        category=VulnerabilityCategory.SQL_INJECTION,
        safety_policy=policy,
        registry=registry,
        model_name="fake:deterministic",
        attempts=1,
        now=NOW,
    )


@dataclass
class M2Fixture:
    generation: GenerationResult
    envelope: Module2CorrelationEnvelope
    request: Module2AnalysisRequest
    hypothesis_id: str


def sqli_m2(*, require_auth: bool = False, with_auth_ref: bool = False) -> M2Fixture:
    """A guarded HIGH-confidence SQLi hypothesis with its M1/M2 context."""
    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id=ENDPOINT_ID,
        location=InputLocation.QUERY,
        parameter_name="id",
        data_type="string",
        evidence_refs=["EVD-004"],
    )
    sink = SinkCandidate(
        sink_id="SNK-001",
        sink_kind=SinkKind.SQL_QUERY,
        file_path="app/db.py",
        start_line=10,
        rule_id="python-sql-raw-concat",
        has_static_taint_flow=True,
        dataflow_steps=["id -> cursor.execute"],
        confidence=ConfidenceLevel.HIGH,
        evidence_refs=["EVD-004"],
    )
    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=NOW,
        inputs=[inp],
        sink_candidates=[sink],
    )
    record = CorrelationRecord(
        correlation_id="COR-" + "a" * 16,
        kind=CorrelationKind.INPUT_SINK,
        status=CorrelationStatus.VERIFIED,
        confidence=ConfidenceLevel.HIGH,
        injection_subtype=InjectionSubtype.SQL_INJECTION,
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        endpoint_id=ENDPOINT_ID,
        input_ref="INP-001",
        sink_ref="SNK-001",
        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        relation_evidence_refs=["EVD-004"],
        independent_relation_source_count=2,
        independence=IndependenceAssessment(
            status=IndependenceStatus.INDEPENDENT, distinct_execution_count=2
        ),
        rationale="Parameter 'id' flows into a raw SQL string.",
    )
    generation = generate_hypotheses(output, [record])
    hypothesis = generation.hypotheses[0]
    correlation = CorrelationResult(
        records=(record,),
        coverage=CorrelationCoverage(
            input_sink_enabled=True,
            sink_cve_enabled=False,
            chain_enabled=False,
            cve_technology_enabled=False,
            blocking_dependencies=(),
        ),
        trust_policy_fingerprint="test-trust-policy",
        trust_policy_is_default=True,
    )
    envelope = Module2CorrelationEnvelope(output=output, correlation=correlation)

    endpoint = EndpointDefinition(
        endpoint_id=ENDPOINT_ID,
        origin="https://lab.example.com",
        path="/api/search",
        method="GET",
        observed_parameters=[ObservedParameter(name="id", location=InputLocation.QUERY)],
        discovery_sources=[DiscoverySource.HTTP_OBSERVATION],
        required_auth_role="user" if require_auth else None,
    )
    auth_references = []
    if with_auth_ref:
        auth_references = [
            AuthReferenceConfig(
                role_name="user",
                auth_mechanism=AuthMechanism.BEARER,
                vault_secret_ref="VAULT-user-token",
            )
        ]
    assessment = AssessmentConfig(
        assessment_id="ASM-001",
        target="https://lab.example.com",
        authorized_scope=["https://lab.example.com"],
        scope_approval=ScopeApprovalRecord(),
        execution_policy=ExecutionPolicy(
            http_policy=HttpExecutionPolicy(timeout_seconds=120, request_budget=1000)
        ),
        auth_references=auth_references,
    )
    target_model = TargetModel(
        target_id="TGT-001",
        assessment_id="ASM-001",
        last_updated=NOW,
        endpoints=[endpoint],
        scope_rules=assessment,
    )
    request = Module2AnalysisRequest(target_model=target_model)
    return M2Fixture(
        generation=generation,
        envelope=envelope,
        request=request,
        hypothesis_id=hypothesis.hypothesis_id,
    )


def in_memory_tactic(*, policy: SQLiSafetyPolicy | None = None) -> AdmittedTactic:
    """An admitted tactic with correct metadata but no file I/O - for gate tests."""
    policy = policy or enabled_policy()
    doc = reference_tactic_document()
    snapshot = recorded_adapter().get_test_case("WSTG-INPV-05")
    env_fp = environment_fingerprint(VulnerabilityCategory.SQL_INJECTION, policy)
    compat = CompatibilityFingerprint(
        vulnerability_category="SQL_INJECTION",
        wstg_version=snapshot.wstg_version,
        wstg_content_sha256=snapshot.content_hash(),
        tactic_schema_version=TACTIC_SCHEMA_VERSION,
        tactic_schema_sha256=bundled_schema_sha256(),
        capability_fingerprint=capability_fingerprint(),
        safety_policy_fingerprint=policy.fingerprint(),
    )
    metadata = TacticMetadata(
        tactic_id=doc.tactic_id,
        tactic_version="0.1.0",
        schema_version=TACTIC_SCHEMA_VERSION,
        vulnerability_category="SQL_INJECTION",
        state=TacticState.ACTIVE,
        content_sha256=doc.canonical_content_hash(),
        compatibility=compat,
        compatibility_fingerprint=compat.value(),
        environment_fingerprint=env_fp.value(),
        wstg_requested_id=snapshot.requested_id,
        wstg_version=snapshot.wstg_version,
        authoring_model="fake:deterministic",
        prompt_version="sqli-author-v1",
        authoring_attempts=1,
        created_at=NOW,
    )
    return AdmittedTactic(document=doc, metadata=metadata)


def planning_context(
    *,
    require_auth: bool = False,
    with_auth_ref: bool = False,
    policy: SQLiSafetyPolicy | None = None,
) -> PlanningContext:
    """A fully-bound PlanningContext for exercising the plan admission gates."""
    policy = policy or enabled_policy()
    fx = sqli_m2(require_auth=require_auth, with_auth_ref=with_auth_ref)
    hypothesis = fx.generation.hypotheses[0]
    output = fx.envelope.output
    input_candidate = output.inputs[0]
    endpoint = fx.request.target_model.endpoints[0]
    assessment = fx.request.target_model.scope_rules
    template = DefaultRequestTemplateResolver().resolve(
        endpoint=endpoint,
        input_candidate=input_candidate,
        auth_references=assessment.auth_references,
    )
    return PlanningContext(
        guarded=GuardedHypothesisContext(
            hypothesis=hypothesis,
            correlation_ref=fx.generation.provenance[hypothesis.hypothesis_id],
        ),
        input_candidate=input_candidate,
        endpoint=endpoint,
        sink=output.sink_candidates[0],
        expected_signals=hypothesis.validation_proposals[0].expected_signals,
        validation_capability=CATEGORY_TO_CAPABILITY[hypothesis.vulnerability_category],
        evidence_refs=list(hypothesis.supporting_evidence_refs),
        observation_refs=list(hypothesis.supporting_observation_refs),
        execution_policy=assessment.execution_policy,
        authorized_scope=list(assessment.authorized_scope),
        request_template=template,
        dbms_hint=None,
        tactic=in_memory_tactic(policy=policy),
        safety_policy=policy,
    )


def valid_plan_draft() -> TestPlanDraft:
    """A clean baseline + ERROR + optional TIME plan within the ceilings."""
    return TestPlanDraft(
        test_cases=[
            TestCaseDraft(
                tactic_step_ref="baseline",
                capability_id="HTTP_REQUEST",
                purpose="Establish a reproducible baseline and check auth/stability.",
                sample_count=2,
                max_requests=2,
                timeout_seconds=15,
                stop_conditions=[StopCondition.BASELINE_NOT_READY, StopCondition.AUTH_FAILURE],
            ),
            TestCaseDraft(
                tactic_step_ref="primary_detection",
                capability_id="SQLI_DETECTION",
                technique=SQLiTechnique.ERROR,
                purpose="Error-based detection against the baseline.",
                depends_on=[0],
                max_requests=120,
                timeout_seconds=90,
                evidence_requirements=["SQL error signature differential vs control"],
                stop_conditions=[StopCondition.TARGET_UNSTABLE, StopCondition.RATE_LIMITED],
            ),
            TestCaseDraft(
                tactic_step_ref="optional_time_detection",
                capability_id="SQLI_DETECTION",
                technique=SQLiTechnique.TIME,
                purpose="Optional time-based detection if justified.",
                depends_on=[0],
                max_requests=80,
                timeout_seconds=90,
                optional=True,
                evidence_requirements=["Repeatable delay contrast vs stable baseline"],
                stop_conditions=[StopCondition.TARGET_UNSTABLE],
            ),
        ],
        expected_terminal_outcomes=["CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE"],
        limitations=["TIME testing is conditional on baseline stability."],
    )
