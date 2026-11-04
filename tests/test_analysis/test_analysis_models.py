"""Unit tests for Module 2 domain schemas and fail-closed validation contracts."""

from __future__ import annotations

import ast
from datetime import UTC, datetime
from pathlib import Path

import pytest
from pydantic import ValidationError

from websecuritycheck.domain.analysis_models import (
    CATEGORY_TO_CAPABILITY,
    AuthoritativeReferenceIndex,
    ConfidenceLevel,
    CVECandidate,
    ExpectedSignal,
    Hypothesis,
    InputCandidate,
    Module2AnalysisRequest,
    Module2Output,
    SinkCandidate,
    SinkKind,
    SinkRelationship,
    TechnologyTargetRef,
    ValidationCapability,
    ValidationCapabilityRequirement,
    VulnerabilityCategory,
    filter_unsupported_capabilities,
    validate_module2_handoff,
)
from websecuritycheck.domain.enums import (
    ArtifactType,
    InputLocation,
    ObservationSource,
    ObservationType,
    TechnologyCategory,
    TestingMode,
)
from websecuritycheck.domain.models import (
    AssessmentConfig,
    EndpointDefinition,
    EndpointObservationPayload,
    EvidenceArtifactRecord,
    Id,
    ObservationRecord,
    ObservedParameter,
    ScopeApprovalRecord,
    TargetModel,
    TechnologyObservationPayload,
    TechnologyRecord,
)

# Avoid pytest treating TestingMode enum as a test class
TestingMode.__test__ = False

FIXED_TIME = datetime(2026, 11, 4, 10, 0, 0, tzinfo=UTC)


def _build_base_request() -> Module2AnalysisRequest:
    """Builds a canonical Module2AnalysisRequest fixture with valid references."""
    evd1 = EvidenceArtifactRecord(
        evidence_id="EVD-001",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.HTTP_RAW_EXCHANGE,
        artifact_ref="raw-http-req-1",
        storage_uri="memory://evd-1",
        sha256_hash="0" * 64,
        size_bytes=100,
        captured_at=FIXED_TIME,
    )
    evd2 = EvidenceArtifactRecord(
        evidence_id="EVD-002",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.TOOL_RAW_OUTPUT,
        artifact_ref="nmap-raw-1",
        storage_uri="memory://evd-2",
        sha256_hash="1" * 64,
        size_bytes=200,
        captured_at=FIXED_TIME,
    )
    obs1 = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=EndpointObservationPayload(
            origin="https://example.com",
            path="/login",
            method="POST",
            parameters=[
                ObservedParameter(
                    name="username",
                    location=InputLocation.JSON_BODY,
                    evidence_refs=[Id("EVD-001")],
                    observation_refs=[Id("OBS-001")],
                )
            ],
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        observed_at=FIXED_TIME,
    )
    obs2 = ObservationRecord(
        observation_id="OBS-002",
        assessment_id="ASM-001",
        observation_type=ObservationType.TECHNOLOGY,
        payload=TechnologyObservationPayload(
            name="Apache",
            category=TechnologyCategory.WEB_SERVER,
            version="2.4.49",
        ),
        source_type=ObservationSource.WHATWEB,
        observed_at=FIXED_TIME,
    )
    endpoint = EndpointDefinition(
        endpoint_id="a3f901c2d4e5",
        origin="https://example.com",
        path="/login",
        method="POST",
        observed_parameters=[
            ObservedParameter(
                name="username",
                location=InputLocation.JSON_BODY,
                evidence_refs=[Id("EVD-001")],
                observation_refs=[Id("OBS-001")],
            )
        ],
        evidence_refs=[Id("EVD-001")],
        observation_refs=[Id("OBS-001")],
    )
    tech = TechnologyRecord(
        category=TechnologyCategory.WEB_SERVER,
        name="Apache",
        version="2.4.49",
        evidence_refs=[Id("EVD-002")],
        observation_refs=[Id("OBS-002")],
    )
    target_model = TargetModel(
        target_id=Id("TGT-001"),
        assessment_id=Id("ASM-001"),
        last_updated=FIXED_TIME,
        endpoints=[endpoint],
        technologies=[tech],
    )
    return Module2AnalysisRequest(
        target_model=target_model,
        observations=[obs1, obs2],
        evidence_records=[evd1, evd2],
        source_repo_path="src/repo",
    )


def test_ownership_boundary_no_agent_or_strands_imports():
    """Verify analysis_models has zero dependency on Agent runtime, strands, or MCP servers."""
    file_path = (
        Path(__file__).resolve().parent.parent.parent
        / "src"
        / "websecuritycheck"
        / "domain"
        / "analysis_models.py"
    )
    assert file_path.is_file(), f"analysis_models.py not found at {file_path}"
    tree = ast.parse(file_path.read_text(encoding="utf-8"))

    disallowed_prefixes = (
        "strands",
        "websecuritycheck.engine",
        "mcp_servers",
        "mcp",
    )

    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            for alias in node.names:
                for prefix in disallowed_prefixes:
                    assert not alias.name.startswith(prefix), (
                        f"Disallowed import {alias.name!r} in analysis_models.py"
                    )
        elif isinstance(node, ast.ImportFrom):
            mod = node.module or ""
            for prefix in disallowed_prefixes:
                assert not mod.startswith(prefix), (
                    f"Disallowed from-import {mod!r} in analysis_models.py"
                )


def test_endpoint_and_component_level_cve_hypotheses():
    """Verify input-based vulns and component-level CVEs validate correctly with evidence."""
    request = _build_base_request()

    analysis_evd = EvidenceArtifactRecord(
        evidence_id="EVD-003",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.SOURCE_ARTIFACT,
        artifact_ref="semgrep-rule-auth-bypass",
        storage_uri="memory://evd-3",
        sha256_hash="2" * 64,
        size_bytes=50,
        captured_at=FIXED_TIME,
    )

    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id="a3f901c2d4e5",
        location=InputLocation.JSON_BODY,
        parameter_name="username",
        evidence_refs=["EVD-001"],
    )

    sink = SinkCandidate(
        sink_id="SNK-001",
        sink_kind=SinkKind.SQL_QUERY,
        file_path="app/auth.py",
        start_line=42,
        end_line=45,
        rule_id="python.django.security.injection.raw-sql",
        has_static_taint_flow=True,
        dataflow_steps=["app/auth.py:20", "app/auth.py:42"],
        confidence=ConfidenceLevel.HIGH,
        evidence_refs=["EVD-003"],
    )

    tech_ref = TechnologyTargetRef(
        category=TechnologyCategory.WEB_SERVER,
        name="Apache",
        version="2.4.49",
    )
    cve = CVECandidate(
        cve_candidate_id="CVC-001",
        cve_id="CVE-2021-41773",
        target_technology=tech_ref,
        affected_range="2.4.49",
        confidence=ConfidenceLevel.HIGH,
        match_rationale="Exact version match with known path traversal",
        evidence_refs=["EVD-002"],
    )

    prop1 = ValidationCapabilityRequirement(
        proposal_id="VCR-001",
        hypothesis_ref="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        suggested_capability=ValidationCapability.SQLI_DETECTION,
        target_endpoint_id="a3f901c2d4e5",
        target_input_ref="INP-001",
        expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
        evidence_refs=["EVD-001"],
    )

    hyp1 = Hypothesis(
        hypothesis_id="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        target_endpoint_id="a3f901c2d4e5",
        input_ref="INP-001",
        sink_ref="SNK-001",
        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        confidence=ConfidenceLevel.HIGH,
        rationale="Semgrep confirmed static taint from input to raw SQL query",
        supporting_evidence_refs=["EVD-001", "EVD-003"],
        validation_proposals=[prop1],
    )

    prop2 = ValidationCapabilityRequirement(
        proposal_id="VCR-002",
        hypothesis_ref="HYP-002",
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        suggested_capability=ValidationCapability.CVE_SAFE_CHECK,
        target_endpoint_id=None,
        target_technology=tech_ref,
        cve_candidate_ref="CVC-001",
        expected_signals=[ExpectedSignal.SAFE_CVE_CHECK_MATCH],
        evidence_refs=["EVD-002"],
    )

    hyp2 = Hypothesis(
        hypothesis_id="HYP-002",
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        target_endpoint_id=None,
        target_technology=tech_ref,
        cve_candidate_ref="CVC-001",
        confidence=ConfidenceLevel.HIGH,
        rationale="Apache 2.4.49 matches CVE-2021-41773 component-level",
        supporting_evidence_refs=["EVD-002"],
        validation_proposals=[prop2],
    )

    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        analysis_evidence_records=[analysis_evd],
        inputs=[inp],
        sink_candidates=[sink],
        cve_candidates=[cve],
        hypotheses=[hyp1, hyp2],
    )

    validated = validate_module2_handoff(output, request)
    assert len(validated.hypotheses) == 2

    # Verify that associating KNOWN_CVE with an endpoint sharing NO evidence raises ValueError
    bad_prop = prop2.model_copy(update={"target_endpoint_id": "a3f901c2d4e5"})
    bad_hyp = hyp2.model_copy(
        update={
            "target_endpoint_id": "a3f901c2d4e5",
            "validation_proposals": [bad_prop],
        }
    )
    bad_output = output.model_copy(update={"hypotheses": [hyp1, bad_hyp]})
    with pytest.raises(ValueError, match="cannot associate with endpoint"):
        validate_module2_handoff(bad_output, request)

    # But if the endpoint and KNOWN_CVE share evidence/observation, it succeeds
    req_with_shared = _build_base_request()
    ep = req_with_shared.target_model.endpoints[0].model_copy(
        update={"evidence_refs": [Id("EVD-001"), Id("EVD-002")]}
    )
    req_with_shared = req_with_shared.model_copy(
        update={"target_model": req_with_shared.target_model.model_copy(update={"endpoints": [ep]})}
    )
    shared_validated = validate_module2_handoff(bad_output, req_with_shared)
    assert shared_validated.hypotheses[1].target_endpoint_id == "a3f901c2d4e5"


def test_static_taint_flow_semantics_and_no_sink_endpoint_field():
    """Verify SinkCandidate forbids endpoint_id and enforces taint flow invariants."""
    # Extra field endpoint_id is forbidden
    with pytest.raises(ValidationError):
        SinkCandidate(
            sink_id="SNK-001",
            sink_kind=SinkKind.SQL_QUERY,
            file_path="app/query.py",
            start_line=10,
            rule_id="rule-sql",
            confidence=ConfidenceLevel.LOW,
            evidence_refs=["EVD-003"],
            endpoint_id="a3f901c2d4e5",  # type: ignore[call-arg]
        )

    # has_static_taint_flow=True requires dataflow_steps
    with pytest.raises(ValidationError, match="requires dataflow_steps"):
        SinkCandidate(
            sink_id="SNK-001",
            sink_kind=SinkKind.SQL_QUERY,
            file_path="app/query.py",
            start_line=10,
            rule_id="rule-sql",
            has_static_taint_flow=True,
            dataflow_steps=[],
            confidence=ConfidenceLevel.HIGH,
            evidence_refs=["EVD-003"],
        )

    # Unsafe non-relative paths rejected
    for bad_path in ("/etc/passwd", "\\windows\\win.ini", "../escape.py", "C:\\app.py"):
        with pytest.raises(ValidationError, match="must be repository-relative"):
            SinkCandidate(
                sink_id="SNK-001",
                sink_kind=SinkKind.SQL_QUERY,
                file_path=bad_path,
                start_line=10,
                rule_id="rule-sql",
                confidence=ConfidenceLevel.LOW,
                evidence_refs=["EVD-003"],
            )

    # Hypothesis claiming STATIC_TAINT_FLOW_FOUND fails if sink has has_static_taint_flow=False
    unverified_sink = SinkCandidate(
        sink_id="SNK-001",
        sink_kind=SinkKind.SQL_QUERY,
        file_path="app/query.py",
        start_line=10,
        rule_id="rule-sql",
        has_static_taint_flow=False,
        confidence=ConfidenceLevel.LOW,
        evidence_refs=["EVD-003"],
    )
    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id="a3f901c2d4e5",
        location=InputLocation.JSON_BODY,
        parameter_name="username",
        evidence_refs=["EVD-001"],
    )
    prop = ValidationCapabilityRequirement(
        proposal_id="VCR-001",
        hypothesis_ref="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        suggested_capability=ValidationCapability.SQLI_DETECTION,
        target_endpoint_id="a3f901c2d4e5",
        target_input_ref="INP-001",
        expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
        evidence_refs=["EVD-001"],
    )
    hyp = Hypothesis(
        hypothesis_id="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        target_endpoint_id="a3f901c2d4e5",
        input_ref="INP-001",
        sink_ref="SNK-001",
        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        confidence=ConfidenceLevel.HIGH,
        rationale="False claim of static taint flow",
        supporting_evidence_refs=["EVD-001"],
        validation_proposals=[prop],
    )
    with pytest.raises(ValidationError, match="claims STATIC_TAINT_FLOW_FOUND"):
        Module2Output(
            assessment_id="ASM-001",
            target_id="TGT-001",
            generated_at=FIXED_TIME,
            inputs=[inp],
            sink_candidates=[unverified_sink],
            hypotheses=[hyp],
        )


def test_semgrep_evidence_provenance_and_collision_rejection():
    """Verify Semgrep evidence must be SOURCE_ARTIFACT and must not collide with Module 1."""
    request = _build_base_request()

    # Rejection: analysis_evidence_record is not SOURCE_ARTIFACT
    non_source_evd = EvidenceArtifactRecord(
        evidence_id="EVD-003",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.TOOL_RAW_OUTPUT,
        artifact_ref="raw-out",
        storage_uri="memory://evd-3",
        sha256_hash="0" * 64,
        size_bytes=10,
        captured_at=FIXED_TIME,
    )
    with pytest.raises(ValidationError, match="must have artifact_type=SOURCE_ARTIFACT"):
        Module2Output(
            assessment_id="ASM-001",
            target_id="TGT-001",
            generated_at=FIXED_TIME,
            analysis_evidence_records=[non_source_evd],
        )

    # Rejection: analysis_evidence_record ID collides with Module 1 EVD-001
    colliding_evd = EvidenceArtifactRecord(
        evidence_id="EVD-001",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.SOURCE_ARTIFACT,
        artifact_ref="colliding-semgrep",
        storage_uri="memory://evd-1-collide",
        sha256_hash="0" * 64,
        size_bytes=10,
        captured_at=FIXED_TIME,
    )
    output_with_collision = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        analysis_evidence_records=[colliding_evd],
    )
    with pytest.raises(ValueError, match="collides with an existing Module 1 evidence_id"):
        validate_module2_handoff(output_with_collision, request)


def test_handoff_validation_fails_closed_when_context_missing_or_dangling():
    """Verify fail-closed behavior for missing validation context and dangling references."""
    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
    )

    # Calling validate_module2_handoff with request=None and index=None raises ValueError
    with pytest.raises(ValueError, match="requires an AuthoritativeReferenceIndex"):
        validate_module2_handoff(output, request=None, index=None)

    # Calling model_validate with empty dict context raises ValueError/ValidationError
    with pytest.raises(ValidationError, match="must provide 'reference_index' or 'request'"):
        Module2Output.model_validate(
            {
                "assessment_id": "ASM-001",
                "target_id": "TGT-001",
                "generated_at": FIXED_TIME.isoformat(),
            },
            context={},
        )

    # Dangling endpoint_id in InputCandidate
    dangling_inp = InputCandidate(
        input_id="INP-001",
        endpoint_id="b00000000000",
        location=InputLocation.QUERY,
        parameter_name="q",
        evidence_refs=["EVD-001"],
    )
    dangling_output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        inputs=[dangling_inp],
    )
    request = _build_base_request()
    with pytest.raises(ValueError, match="references unknown endpoint_id"):
        validate_module2_handoff(dangling_output, request)

    # Unregistered technology in CVECandidate
    unknown_tech = TechnologyTargetRef(
        category=TechnologyCategory.WEB_SERVER,
        name="Nginx",
        version="1.18.0",
    )
    dangling_cve = CVECandidate(
        cve_candidate_id="CVC-001",
        cve_id="CVE-2021-23017",
        target_technology=unknown_tech,
        affected_range="1.18.0",
        confidence=ConfidenceLevel.MEDIUM,
        match_rationale="Unregistered technology check",
        evidence_refs=["EVD-002"],
    )
    cve_output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        cve_candidates=[dangling_cve],
    )
    with pytest.raises(ValueError, match=r"not present in TargetModel\.technologies"):
        validate_module2_handoff(cve_output, request)

    # Fabricated EVD-999
    fab_inp = InputCandidate(
        input_id="INP-001",
        endpoint_id="a3f901c2d4e5",
        location=InputLocation.QUERY,
        parameter_name="q",
        evidence_refs=["EVD-999"],
    )
    fab_output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        inputs=[fab_inp],
    )
    with pytest.raises(ValueError, match="references unresolvable evidence_id EVD-999"):
        validate_module2_handoff(fab_output, request)


def test_draft_validation_capability_contract_and_unsupported_filtering():
    """Verify cross-team capability alignment, strict validation, and deterministic filtering."""
    assert (
        CATEGORY_TO_CAPABILITY[VulnerabilityCategory.SQL_INJECTION]
        == ValidationCapability.SQLI_DETECTION
    )
    assert (
        CATEGORY_TO_CAPABILITY[VulnerabilityCategory.KNOWN_CVE]
        == ValidationCapability.CVE_SAFE_CHECK
    )

    # Extra tool-specific parameters like sqlmap_flags or payloads are rejected
    with pytest.raises(ValidationError):
        ValidationCapabilityRequirement(
            proposal_id="VCR-001",
            hypothesis_ref="HYP-001",
            vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
            suggested_capability=ValidationCapability.SQLI_DETECTION,
            target_endpoint_id="a3f901c2d4e5",
            target_input_ref="INP-001",
            expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
            evidence_refs=["EVD-001"],
            sqlmap_flags="--risk=3",  # type: ignore[call-arg]
        )

    # Test filtering unsupported capabilities
    inp = InputCandidate(
        input_id="INP-001",
        endpoint_id="a3f901c2d4e5",
        location=InputLocation.JSON_BODY,
        parameter_name="username",
        evidence_refs=["EVD-001"],
    )
    tech_ref = TechnologyTargetRef(
        category=TechnologyCategory.WEB_SERVER,
        name="Apache",
        version="2.4.49",
    )
    cve = CVECandidate(
        cve_candidate_id="CVC-001",
        cve_id="CVE-2021-41773",
        target_technology=tech_ref,
        affected_range="2.4.49",
        confidence=ConfidenceLevel.HIGH,
        match_rationale="Matched Apache 2.4.49",
        evidence_refs=["EVD-002"],
    )
    prop_sqli = ValidationCapabilityRequirement(
        proposal_id="VCR-001",
        hypothesis_ref="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        suggested_capability=ValidationCapability.SQLI_DETECTION,
        target_endpoint_id="a3f901c2d4e5",
        target_input_ref="INP-001",
        expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
        evidence_refs=["EVD-001"],
    )
    prop_cve = ValidationCapabilityRequirement(
        proposal_id="VCR-002",
        hypothesis_ref="HYP-002",
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        suggested_capability=ValidationCapability.CVE_SAFE_CHECK,
        target_endpoint_id=None,
        target_technology=tech_ref,
        cve_candidate_ref="CVC-001",
        expected_signals=[ExpectedSignal.SAFE_CVE_CHECK_MATCH],
        evidence_refs=["EVD-002"],
    )
    hyp1 = Hypothesis(
        hypothesis_id="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        target_endpoint_id="a3f901c2d4e5",
        input_ref="INP-001",
        confidence=ConfidenceLevel.HIGH,
        rationale="SQLi hypothesis",
        supporting_evidence_refs=["EVD-001"],
        validation_proposals=[prop_sqli],
    )
    hyp2 = Hypothesis(
        hypothesis_id="HYP-002",
        vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
        target_endpoint_id=None,
        target_technology=tech_ref,
        cve_candidate_ref="CVC-001",
        confidence=ConfidenceLevel.HIGH,
        rationale="CVE hypothesis",
        supporting_evidence_refs=["EVD-002"],
        validation_proposals=[prop_cve],
    )
    output = Module2Output(
        assessment_id="ASM-001",
        target_id="TGT-001",
        generated_at=FIXED_TIME,
        inputs=[inp],
        cve_candidates=[cve],
        hypotheses=[hyp1, hyp2],
    )

    request = _build_base_request()
    # Allowed capability check raises when CVE_SAFE_CHECK is not in allowed_capabilities
    with pytest.raises(ValueError, match="requests unsupported capability CVE_SAFE_CHECK"):
        validate_module2_handoff(
            output,
            request,
            allowed_capabilities={ValidationCapability.SQLI_DETECTION},
        )

    # Pruning unsupported capabilities
    pruned = filter_unsupported_capabilities(output, {ValidationCapability.SQLI_DETECTION})
    assert len(pruned.hypotheses[0].validation_proposals) == 1
    assert len(pruned.hypotheses[1].validation_proposals) == 0
    assert any("Dropped proposal VCR-002" in limit for limit in pruned.limitations)


def test_canonical_observations_only_no_passive_signals_field():
    """Verify Module2AnalysisRequest forbids passive_signals and indexes observations."""
    base = _build_base_request()

    # Reject extra passive_signals parameter
    with pytest.raises(ValidationError):
        Module2AnalysisRequest(
            target_model=base.target_model,
            observations=base.observations,
            evidence_records=base.evidence_records,
            passive_signals=[],  # type: ignore[call-arg]
        )

    # Canonical observations index cleanly into AuthoritativeReferenceIndex
    index = AuthoritativeReferenceIndex.from_request(base)
    assert "OBS-001" in index.observation_ids
    assert "OBS-002" in index.observation_ids
    assert "EVD-001" in index.evidence_ids
    assert "EVD-002" in index.evidence_ids
    assert "a3f901c2d4e5" in index.endpoint_refs
    assert ("WEB_SERVER", "apache", "2.4.49") in index.technology_refs


def test_blackbox_testing_mode_rejects_source_repo_path():
    """Verify source_repo_path is forbidden when scope testing_mode is BLACKBOX."""
    base = _build_base_request()
    blackbox_config = AssessmentConfig(
        assessment_id=Id("ASM-001"),
        target="https://example.com",
        authorized_scope=["https://example.com"],
        scope_approval=ScopeApprovalRecord(is_approved=False),
        testing_mode=TestingMode.BLACKBOX,
    )
    blackbox_target_model = base.target_model.model_copy(update={"scope_rules": blackbox_config})
    with pytest.raises(
        ValidationError,
        match="source_repo_path is not allowed when testing_mode is BLACKBOX",
    ):
        Module2AnalysisRequest(
            target_model=blackbox_target_model,
            source_repo_path="src/repo",
        )
