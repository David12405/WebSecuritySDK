"""Offline deterministic E2E tests: M1/M2 -> Stage A/B -> M3 ValidationPlanExecutor."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime
from functools import wraps
from pathlib import Path

import yaml

from mcp_servers.websec_tools.errors import envelope as l6_envelope
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
    ConfidenceLevel,
    ExpectedSignal,
    InputCandidate,
    Module2AnalysisRequest,
    Module2Output,
    SinkCandidate,
    SinkKind,
    SinkRelationship,
    VulnerabilityCategory,
)
from websecuritycheck.domain.enums import DiscoverySource, InputLocation
from websecuritycheck.domain.models import (
    AssessmentConfig,
    EndpointDefinition,
    ExecutionPolicy,
    HttpExecutionPolicy,
    ObservedParameter,
    ScopeApprovalRecord,
    TargetModel,
)
from websecuritycheck.hypothesis import generate_hypotheses
from websecuritycheck.tactic_planning.contracts import (
    SQLiSafetyPolicy,
)
from websecuritycheck.tactic_planning.contracts import (
    SQLiTechnique as StageBSQLiTechnique,
)
from websecuritycheck.tactic_planning.stage_a import (
    FakeTacticAuthor,
    FileTacticRegistry,
    RecordedWstgAdapter,
    TacticDocument,
)
from websecuritycheck.tactic_planning.stage_b import (
    build_m3_handoff,
    prepare_sql_injection_plan,
)
from websecuritycheck.tactic_planning.stage_b.models import (
    PlanningStatus,
    StopCondition,
    TestCaseDraft,
    TestPlanDraft,
)
from websecuritycheck.validation import (
    HttpBaselineAdapter,
    InMemoryRequestMaterializer,
    SQLiTechnique,
    SqlmapDetectionAdapter,
    ValidationOutcome,
    ValidationPlanExecutor,
)

REPO_ROOT = Path(__file__).resolve().parents[2]
WSTG_DIR = REPO_ROOT / "tests" / "fixtures" / "wstg"
REF_TACTIC = REPO_ROOT / "tactics" / "sqli" / "sqli_testing.yaml"
NOW = datetime(2026, 11, 19, 12, 0, 0, tzinfo=UTC)
ENDPOINT_ID = "a" * 12


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _reference_tactic() -> TacticDocument:
    data = yaml.safe_load(REF_TACTIC.read_text(encoding="utf-8"))
    data["references"] = [
        "WSTG-v42-INPV-05" if ref == "WSTG-INJT-05" else ref for ref in data["references"]
    ]
    return TacticDocument.model_validate(data)


class _DeterministicPlanner:
    def __init__(self, *, sample_count: int = 2) -> None:
        self._sample_count = sample_count

    def plan(self, context, *, attempt: int = 0, feedback=()) -> TestPlanDraft:
        return TestPlanDraft(
            test_cases=[
                TestCaseDraft(
                    tactic_step_ref="baseline",
                    capability_id="HTTP_REQUEST",
                    purpose="Establish stable baseline.",
                    sample_count=self._sample_count,
                    max_requests=self._sample_count,
                    timeout_seconds=15,
                    evidence_requirements=["Baseline response captured"],
                    stop_conditions=[StopCondition.BASELINE_NOT_READY],
                ),
                TestCaseDraft(
                    tactic_step_ref="primary_detection",
                    capability_id="SQLI_DETECTION",
                    technique=StageBSQLiTechnique.ERROR,
                    purpose="Detect error-based SQLi.",
                    depends_on=[0],
                    max_requests=50,
                    timeout_seconds=60,
                    expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
                    evidence_requirements=["SQL error differential vs baseline"],
                    stop_conditions=[
                        StopCondition.VERIFIED_PROOF_FOUND,
                        StopCondition.TARGET_UNSTABLE,
                        StopCondition.RATE_LIMITED,
                    ],
                ),
                TestCaseDraft(
                    tactic_step_ref="primary_detection",
                    capability_id="SQLI_DETECTION",
                    technique=StageBSQLiTechnique.BOOLEAN,
                    purpose="Detect boolean-blind SQLi.",
                    depends_on=[0],
                    max_requests=50,
                    timeout_seconds=60,
                    expected_signals=[ExpectedSignal.BOOLEAN_RESPONSE_DIFF],
                    evidence_requirements=["Boolean differential vs baseline"],
                    stop_conditions=[
                        StopCondition.VERIFIED_PROOF_FOUND,
                        StopCondition.TARGET_UNSTABLE,
                    ],
                ),
                TestCaseDraft(
                    tactic_step_ref="optional_time_detection",
                    capability_id="SQLI_DETECTION",
                    technique=StageBSQLiTechnique.TIME,
                    purpose="Optional time-based SQLi.",
                    depends_on=[0],
                    max_requests=50,
                    timeout_seconds=60,
                    expected_signals=[ExpectedSignal.TIMING_DIFF],
                    evidence_requirements=["Repeatable delay contrast vs baseline"],
                    stop_conditions=[
                        StopCondition.VERIFIED_PROOF_FOUND,
                        StopCondition.TARGET_UNSTABLE,
                    ],
                    optional=True,
                ),
            ],
            expected_terminal_outcomes=["CONFIRMED", "NOT_CONFIRMED", "INCONCLUSIVE"],
            limitations=["TIME testing is optional."],
        )


def _build_handoff(tmp_path: Path, *, sample_count: int = 2) -> dict:
    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id=ENDPOINT_ID,
        location=InputLocation.QUERY,
        parameter_name="id",
        data_type="string",
        evidence_refs=["EVD-001"],
    )
    sink = SinkCandidate(
        sink_id="SNK-001",
        sink_kind=SinkKind.SQL_QUERY,
        file_path="src/index.js",
        start_line=73,
        rule_id="cloudflare-workers.tainted-d1-sql-injection",
        has_static_taint_flow=True,
        dataflow_steps=["id -> env.DB.prepare"],
        confidence=ConfidenceLevel.HIGH,
        evidence_refs=["EVD-002"],
    )
    output = Module2Output(
        assessment_id="ASM-103",
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
        relation_evidence_refs=["EVD-001", "EVD-002"],
        independent_relation_source_count=2,
        independence=IndependenceAssessment(
            status=IndependenceStatus.INDEPENDENT,
            distinct_execution_count=2,
        ),
        rationale="Verified static taint flow from id to SNK-001",
    )
    m2_envelope = Module2CorrelationEnvelope(
        output=output,
        correlation=CorrelationResult(
            records=(record,),
            coverage=CorrelationCoverage(
                input_sink_enabled=True,
                sink_cve_enabled=False,
                chain_enabled=False,
                cve_technology_enabled=False,
                blocking_dependencies=(),
            ),
            trust_policy_fingerprint="e2e-test",
            trust_policy_is_default=True,
        ),
    )
    endpoint = EndpointDefinition(
        endpoint_id=ENDPOINT_ID,
        origin="https://api-target.7an6rando.workers.dev",
        path="/api/users",
        method="GET",
        observed_parameters=[ObservedParameter(name="id", location=InputLocation.QUERY)],
        discovery_sources=[DiscoverySource.HTTP_OBSERVATION],
    )
    config = AssessmentConfig(
        assessment_id="ASM-103",
        target="https://api-target.7an6rando.workers.dev",
        authorized_scope=["https://api-target.7an6rando.workers.dev"],
        scope_approval=ScopeApprovalRecord(),
        execution_policy=ExecutionPolicy(
            http_policy=HttpExecutionPolicy(
                timeout_seconds=120,
                request_budget=1000,
                allowed_methods=["GET", "POST"],
            )
        ),
    )
    target_model = TargetModel(
        target_id="TGT-001",
        assessment_id="ASM-103",
        last_updated=NOW,
        scope_rules=config,
        endpoints=[endpoint],
    )
    request = Module2AnalysisRequest(target_model=target_model)
    generation = generate_hypotheses(output, [record])
    hypothesis = generation.hypotheses[0]

    prep = prepare_sql_injection_plan(
        generation,
        hypothesis.hypothesis_id,
        m2_envelope,
        request,
        registry=FileTacticRegistry(tmp_path / "registry"),
        author=FakeTacticAuthor(_reference_tactic()),
        planner=_DeterministicPlanner(sample_count=sample_count),
        wstg_adapter=RecordedWstgAdapter(WSTG_DIR),
        safety_policy=SQLiSafetyPolicy(enabled=True),
        model_name="fake:deterministic",
        now=NOW,
    )
    assert prep.status == PlanningStatus.READY
    assert prep.plan is not None
    return build_m3_handoff(
        prep.plan,
        envelope=m2_envelope,
        request=request,
        hypothesis=hypothesis,
    )


def _probe_ok(*, status: int = 200, response_body: str = '{"users":[]}'):
    counter = 0

    async def _probe(url, method="GET", headers=None, body=None):
        nonlocal counter
        counter += 1
        return l6_envelope(
            f"GET {status}",
            {
                "target": url,
                "method": method,
                "final_url": url,
                "status": status,
                "http_version": "HTTP/1.1",
                "redirects": [],
                "request_headers": {},
                "response_headers": {"content-type": "application/json"},
                "request_content_type": None,
                "response_content_type": "application/json",
                "request_parameter_names": [],
                "response_body_size": len(response_body),
                "response_body_text": response_body,
                "body_truncated": False,
                "redacted_headers": [],
                "artifact_manifests": [
                    {
                        "artifact_ref": f"http-exchange-base-{counter:03d}",
                        "artifact_type": "HTTP_RAW_EXCHANGE",
                        "content": "{}",
                        "media_type": "application/json",
                        "redaction_applied": True,
                    }
                ],
            },
            False,
        )

    return _probe


def _sqli_result(
    *,
    findings: list[dict],
    dbms: str | None = "SQLite",
    heuristic: bool = False,
    rate_limited: bool = False,
):
    calls: list[list[str]] = []

    async def _detect(target, parameter_name, **kwargs):
        calls.append(list(kwargs["techniques"]))
        return l6_envelope(
            "sqlmap",
            {
                "tool": "sqlmap",
                "target": target,
                "method": kwargs["method"],
                "parameter_name": parameter_name,
                "parameter_location": kwargs["parameter_location"],
                "requested_techniques": kwargs["techniques"],
                "findings": findings,
                "dbms_identified": dbms,
                "heuristic_signal_detected": heuristic,
                "target_stable": True,
                "auth_failure_detected": False,
                "rate_limited": rate_limited,
                "waf_or_filter_detected": False,
                "warnings": [],
                "artifact_manifests": [
                    {
                        "artifact_ref": f"sqlmap-output-{len(calls):03d}",
                        "artifact_type": "TOOL_RAW_OUTPUT",
                        "content": "redacted log",
                        "media_type": "text/plain",
                        "redaction_applied": True,
                    }
                ],
            },
            False,
        )

    return _detect, calls


@async_test
async def test_e2e_confirmed_stops_early_on_verified_proof(tmp_path: Path):
    handoff = _build_handoff(tmp_path, sample_count=2)
    detect_fn, calls = _sqli_result(
        findings=[
            {
                "parameter_name": "id",
                "location_label": "GET",
                "technique": "ERROR",
                "sqlmap_type": "error-based",
                "title": "SQLite error-based",
                "redacted_payload_summary": "id=1' AND 1=CAST(1 AS INT)",
                "dbms_identified": "SQLite",
            }
        ]
    )
    materializer = InMemoryRequestMaterializer()
    scope = ["https://api-target.7an6rando.workers.dev"]
    executor = ValidationPlanExecutor(
        materializer=materializer,
        http_adapter=HttpBaselineAdapter(
            authorized_scope=scope,
            materializer=materializer,
            probe_fn=_probe_ok(status=200),
        ),
        sqli_adapter=SqlmapDetectionAdapter(
            authorized_scope=scope,
            materializer=materializer,
            detect_fn=detect_fn,
        ),
    )

    result = await executor.execute_handoff(handoff)

    assert result.outcome == ValidationOutcome.CONFIRMED
    assert result.stop_reason == "VERIFIED_PROOF_FOUND"
    assert result.confirmed_techniques == [SQLiTechnique.ERROR]
    assert result.dbms_identified == "SQLite"
    assert len(calls) == 1  # Stopped after TC-002; TC-003 and TC-004 were not invoked
    assert len(result.case_results) == 2
    assert any(proof.verified for proof in result.proofs)


@async_test
async def test_e2e_stops_immediately_when_baseline_not_ready(tmp_path: Path):
    handoff = _build_handoff(tmp_path, sample_count=1)  # sample_count=1 -> baseline_ready=False
    detect_fn, calls = _sqli_result(findings=[])
    materializer = InMemoryRequestMaterializer()
    scope = ["https://api-target.7an6rando.workers.dev"]
    executor = ValidationPlanExecutor(
        materializer=materializer,
        http_adapter=HttpBaselineAdapter(
            authorized_scope=scope,
            materializer=materializer,
            probe_fn=_probe_ok(status=200),
        ),
        sqli_adapter=SqlmapDetectionAdapter(
            authorized_scope=scope,
            materializer=materializer,
            detect_fn=detect_fn,
        ),
    )

    result = await executor.execute_handoff(handoff)

    assert result.outcome == ValidationOutcome.INCONCLUSIVE
    assert result.stop_reason == "BASELINE_NOT_READY"
    assert calls == []


@async_test
async def test_e2e_not_confirmed_when_all_techniques_clean(tmp_path: Path):
    handoff = _build_handoff(tmp_path, sample_count=2)
    detect_fn, calls = _sqli_result(findings=[], dbms=None, heuristic=False)
    materializer = InMemoryRequestMaterializer()
    scope = ["https://api-target.7an6rando.workers.dev"]
    executor = ValidationPlanExecutor(
        materializer=materializer,
        http_adapter=HttpBaselineAdapter(
            authorized_scope=scope,
            materializer=materializer,
            probe_fn=_probe_ok(status=200),
        ),
        sqli_adapter=SqlmapDetectionAdapter(
            authorized_scope=scope,
            materializer=materializer,
            detect_fn=detect_fn,
        ),
    )

    result = await executor.execute_handoff(handoff)

    assert result.outcome == ValidationOutcome.NOT_CONFIRMED
    assert result.confirmed_techniques == []
    assert len(calls) == 3  # ERROR, BOOLEAN, optional TIME all executed cleanly


@async_test
async def test_e2e_heuristic_only_and_out_of_scope_fail_closed(tmp_path: Path):
    handoff = _build_handoff(tmp_path, sample_count=2)
    detect_fn, _calls = _sqli_result(findings=[], dbms=None, heuristic=True)
    materializer = InMemoryRequestMaterializer()
    scope = ["https://api-target.7an6rando.workers.dev"]
    executor = ValidationPlanExecutor(
        materializer=materializer,
        http_adapter=HttpBaselineAdapter(
            authorized_scope=scope,
            materializer=materializer,
            probe_fn=_probe_ok(status=200),
        ),
        sqli_adapter=SqlmapDetectionAdapter(
            authorized_scope=scope,
            materializer=materializer,
            detect_fn=detect_fn,
        ),
    )
    heuristic_res = await executor.execute_handoff(handoff)
    assert heuristic_res.outcome == ValidationOutcome.INCONCLUSIVE

    blocked_executor = ValidationPlanExecutor(
        authorized_scope=["https://other-scope.example.com"],
        http_adapter=HttpBaselineAdapter(
            authorized_scope=["https://other-scope.example.com"],
            probe_fn=_probe_ok(status=200),
        ),
        sqli_adapter=SqlmapDetectionAdapter(
            authorized_scope=["https://other-scope.example.com"],
            detect_fn=detect_fn,
        ),
    )
    blocked_res = await blocked_executor.execute_handoff(handoff)
    assert blocked_res.outcome == ValidationOutcome.POLICY_BLOCKED
