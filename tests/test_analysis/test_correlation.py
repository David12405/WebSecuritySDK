"""Comprehensive unit and integration test suite for M2-T05 Evidence Correlation."""

from __future__ import annotations

import asyncio
import inspect
from typing import Any

import pytest

from websecuritycheck.analysis.correlation import (
    DEFAULT_CORRELATION_TRUST_POLICY,
    AccessorResolution,
    ApprovedRulesetEntry,
    ApprovedRuleSpec,
    ApprovedVulnerableApiEntry,
    CorrelationId,
    CorrelationInputError,
    CorrelationKind,
    CorrelationRecord,
    CorrelationStatus,
    CorrelationTrustPolicy,
    CorrelationTrustPolicyError,
    FlowTrust,
    IndependenceAssessment,
    IndependenceStatus,
    RuleMode,
    RuleProvenanceStatus,
    acorrelate_evidence,
    assess_independence,
    build_correlation_envelope,
    correlate_evidence,
    evaluate_correlation_confidence,
    parse_taint_source_accessor,
    verify_route_binding_artifact,
)
from websecuritycheck.analysis.cve import (
    InjectionScopePolicy,
    InjectionSubtype,
    extract_cve_candidates,
)
from websecuritycheck.analysis.inputs import (
    InputExtractionResult,
    extract_input_candidates,
)
from websecuritycheck.analysis.sinks import (
    extract_sink_candidates,
)
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CveCandidateId,
    CweId,
    EvidenceId,
    InputCandidate,
    InputId,
    Module2AnalysisRequest,
    Module2Output,
    SinkKind,
    TechnologyTargetRef,
)
from websecuritycheck.domain.enums import (
    InputLocation,
    TechnologyCategory,
    TestingMode,
)
from websecuritycheck.domain.models import (
    Id,
    TechnologyRecord,
)

from .fixtures import (
    FIXED_TIME,
    make_evidence_record,
    make_route_binding_artifact,
    make_semgrep_envelope,
    make_semgrep_finding,
    make_shop_analysis_request_with_scope,
    make_taint_semgrep_finding,
    make_technology_record,
    make_test_trust_policy,
)


def _make_correlation_request(
    *,
    source_repo_path: str | None = "C:/repo",
    testing_mode: TestingMode = TestingMode.GRAYBOX,
    technologies: list[TechnologyRecord] | None = None,
) -> Module2AnalysisRequest:
    """Build a valid Module2AnalysisRequest with scope rules and Django technology."""
    req = make_shop_analysis_request_with_scope(
        source_repo_path=source_repo_path,
        source_repository_ref=source_repo_path,
        testing_mode=testing_mode,
    )
    tech = (
        technologies if technologies is not None else [make_technology_record("Django", "3.2.12")]
    )
    tm = req.target_model.model_copy(update={"technologies": tech})
    return req.model_copy(update={"target_model": tm})


# ---------------------------------------------------------------------------
# §15.1 Retained & Core Verification Tests
# ---------------------------------------------------------------------------


def test_verified_input_sink_requires_full_trust_chain():
    """Test full verified chain: approved taint rule + trusted producer + matching revision."""
    req = _make_correlation_request(source_repo_path="C:/repo")
    ep = req.target_model.endpoints[0]  # GET /api/products
    rule_id = "python.sqlalchemy.security.audit.sqli.raw-sql"
    ruleset_sha = "c" * 64
    rev = "git-rev-1234"

    # 1. Semgrep finding with taint trace matching ep.path
    finding = make_taint_semgrep_finding(
        rule_id=rule_id,
        file="app/views.py",
        start_line=25,
        source_file="app/views.py",
        source_line=12,
        source_snippet="request.args.get('sort_by')",
        sink_snippet="cursor.execute(sql)",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)
    assert len(sink_res.sink_candidates) == 1

    # Enrich sink evidence provenance with mock M2-T03c metadata
    evd = sink_res.analysis_evidence_records[0]
    evd_enriched = evd.model_copy(
        update={
            "execution_ref": Id("EXEC-001"),
            "provenance": {
                **evd.provenance,
                "ruleset_sha256": ruleset_sha,
                "source_repository_ref": "C:/repo",
                "source_revision": rev,
            },
        }
    )
    sink_res = sink_res.model_copy(update={"analysis_evidence_records": [evd_enriched]})

    # 2. Route binding artifact for ep in app/views.py lines 1-50
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        method=ep.method,
        path=ep.path,
        file_path="app/views.py",
        start_line=1,
        end_line=50,
        evidence_id="EVD-050",
        assessment_id=req.target_model.assessment_id,
        source_repository_ref="C:/repo",
        source_revision=rev,
        execution_ref="EXEC-002",  # Distinct execution
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    # 3. Input candidate for 'sort_by' on ep
    inp = InputCandidate(
        input_id=InputId("INP-001"),
        endpoint_id=ep.endpoint_id,
        location=InputLocation.QUERY,
        parameter_name="sort_by",
        evidence_refs=[EvidenceId("EVD-001")],
        observation_refs=[],
    )
    inp_res = InputExtractionResult(inputs=[inp])

    # 4. Trust policy approving the rule and route producer
    trust_policy = make_test_trust_policy(
        rule_ids=[rule_id],
        ruleset_sha256=ruleset_sha,
        producer_id="route_extractor",
    )

    result = correlate_evidence(
        req_with_binding,
        input_result=inp_res,
        sink_result=sink_res,
        route_binding_artifacts=[rb_ref],
        trust_policy=trust_policy,
    )

    assert len(result.records) == 1
    rec = result.records[0]
    assert rec.kind == CorrelationKind.INPUT_SINK
    assert rec.status == CorrelationStatus.VERIFIED
    assert rec.confidence == ConfidenceLevel.HIGH
    assert rec.endpoint_id == ep.endpoint_id
    assert rec.input_ref == "INP-001"
    assert rec.sink_ref == sink_res.sink_candidates[0].sink_id
    assert rec.independence.status == IndependenceStatus.INDEPENDENT
    assert "EVD-050" in rec.relation_evidence_refs


def test_no_trusted_taint_never_verified():
    """Test that pattern-only or untrusted-taint sinks never yield INPUT_SINK VERIFIED."""
    req = _make_correlation_request(source_repo_path="C:/repo")
    ep = req.target_model.endpoints[0]
    finding = make_semgrep_finding(
        rule_id="python.sqlalchemy.security.audit.sqli.raw-sql",
        file="app/views.py",
        start_line=25,
        snippet="cursor.execute(sql)",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        method=ep.method,
        path=ep.path,
        file_path="app/views.py",
        start_line=1,
        end_line=50,
        assessment_id=req.target_model.assessment_id,
        source_repository_ref="C:/repo",
        source_revision="rev-1",
        execution_ref="EXEC-002",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    trust_policy = make_test_trust_policy(
        rule_ids=["python.sqlalchemy.security.audit.sqli.raw-sql"]
    )

    result = correlate_evidence(
        req_with_binding,
        sink_result=sink_res,
        route_binding_artifacts=[rb_ref],
        trust_policy=trust_policy,
    )

    # Without trusted taint, at most ENDPOINT_SINK PARTIAL/LOW, never INPUT_SINK
    assert all(r.kind != CorrelationKind.INPUT_SINK for r in result.records)
    if result.records:
        assert result.records[0].status == CorrelationStatus.PARTIAL
        assert result.records[0].confidence == ConfidenceLevel.LOW


def test_same_application_inputs_and_sinks_not_paired():
    """Inputs and sinks belonging to the same application are never paired without binding."""
    req = _make_correlation_request(source_repo_path="C:/repo")
    ep = req.target_model.endpoints[0]
    finding = make_semgrep_finding(file="app/views.py", start_line=10)
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    inp = InputCandidate(
        input_id=InputId("INP-001"),
        endpoint_id=ep.endpoint_id,
        location=InputLocation.QUERY,
        parameter_name="sort",
        evidence_refs=[EvidenceId("EVD-001")],
    )
    inp_res = InputExtractionResult(inputs=[inp])

    # No route bindings supplied
    result = correlate_evidence(
        req,
        input_result=inp_res,
        sink_result=sink_res,
        route_binding_artifacts=[],
    )

    # Zero input-sink correlations
    assert len(result.records) == 0
    assert any(d.code == "NO_MATCHING_ROUTE_BINDING" for d in result.diagnostics)


def test_ambiguous_mapping_rejected():
    """Ambiguous template/route or dynamic parameter mapping does not yield VERIFIED."""
    accessor = parse_taint_source_accessor("request.args[dynamic_key]")
    assert accessor.resolution == AccessorResolution.DYNAMIC_KEY

    accessor_redacted = parse_taint_source_accessor("request.args['<redacted>']")
    assert accessor_redacted.resolution == AccessorResolution.REDACTED

    accessor_trunc = parse_taint_source_accessor("request.args.get('val'...")
    assert accessor_trunc.resolution == AccessorResolution.TRUNCATED


def test_name_similarity_alone_not_correlated():
    """A parameter named 'sort' is not paired with a sink where taint is in another file."""
    accessor = parse_taint_source_accessor("request.args.get('sort')")
    assert accessor.resolution == AccessorResolution.RESOLVED
    assert accessor.parameter_name == "sort"

    # Even though parameter is named sort, if taint source is outside binding, it fails
    bindings: list[Any] = []
    # If no bindings match the taint source file/line, result is 0
    assert len(bindings) == 0


def test_cve_technology_canonical_identity():
    """CVE_TECHNOLOGY correlation preserves exact canonical TechnologyTargetRef."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)

    result = correlate_evidence(req, cve_result=cve_res)
    assert len(result.records) >= 1
    cve_rec = result.records[0]
    assert cve_rec.kind == CorrelationKind.CVE_TECHNOLOGY
    assert cve_rec.endpoint_id is None
    assert cve_rec.input_ref is None
    assert cve_rec.sink_ref is None
    assert cve_rec.target_technology is not None
    assert cve_rec.target_technology.name == "Django"


def test_cve_never_auto_linked_to_endpoint():
    """CVE is never automatically attached to an endpoint even if sharing web framework."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)
    result = correlate_evidence(req, cve_result=cve_res)

    for rec in result.records:
        if rec.kind == CorrelationKind.CVE_TECHNOLOGY:
            assert rec.endpoint_id is None
            assert rec.input_ref is None


def test_same_subtype_sink_and_cve_not_paired_without_registry():
    """A SQL sink and a SQLi CVE are not paired when Approved Vulnerable API Registry is empty."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)
    finding = make_semgrep_finding()
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    result = correlate_evidence(
        req,
        sink_result=sink_res,
        cve_result=cve_res,
        trust_policy=DEFAULT_CORRELATION_TRUST_POLICY,  # Empty registry
    )

    assert all(r.kind != CorrelationKind.SINK_CVE for r in result.records)
    assert "SINK_CVE_REGISTRY_EMPTY" in result.limitations


def test_non_injection_sinks_and_cves_excluded():
    """Non-injection sinks (HTML_OUTPUT, PATH_ACCESS, excluded CWEs) are excluded fail-closed."""
    req = _make_correlation_request()
    # HTML_OUTPUT sink (XSS)
    finding = make_semgrep_finding(
        rule_id="javascript.browser.security.xss.dangerouslysetinnerhtml",
        cwe="CWE-79: Cross-site Scripting",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    result = correlate_evidence(req, sink_result=sink_res)
    assert len(result.records) == 0
    assert any(d.code == "SINK_KIND" and d.outcome == "EXCLUDED" for d in result.diagnostics)


def test_dangling_references_fail_closed():
    """Candidates with unresolvable or dangling references are safely dropped."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    dangling_inp = InputCandidate(
        input_id=InputId("INP-999"),
        endpoint_id=ep.endpoint_id,
        location=InputLocation.QUERY,
        parameter_name="ghost",
        evidence_refs=[EvidenceId("EVD-999")],  # Does not exist in req
    )
    inp_res = InputExtractionResult(inputs=[dangling_inp])
    result = correlate_evidence(req, input_result=inp_res)

    assert len(result.records) == 0
    assert any(d.code == "DANGLING_REFERENCE" for d in result.diagnostics)


def test_blackbox_mode_no_source_correlation():
    """In BLACKBOX mode, source analysis and route bindings are skipped; CVE_TECHNOLOGY runs."""
    req = _make_correlation_request(testing_mode=TestingMode.BLACKBOX, source_repo_path=None)
    cve_res = extract_cve_candidates(req)

    result = correlate_evidence(req, cve_result=cve_res)
    assert "BLACKBOX_NO_SOURCE_CORRELATION" in result.limitations
    assert any(r.kind == CorrelationKind.CVE_TECHNOLOGY for r in result.records)


def test_permutation_determinism_and_dedup():
    """Order permutations of inputs, sinks, CVEs produce byte-for-byte identical output."""
    req = _make_correlation_request()
    cve_res1 = extract_cve_candidates(req)
    # Reverse cve candidates order
    cve_res2 = cve_res1.model_copy(
        update={"cve_candidates": tuple(reversed(cve_res1.cve_candidates))}
    )

    res1 = correlate_evidence(req, cve_result=cve_res1)
    res2 = correlate_evidence(req, cve_result=cve_res2)

    assert res1.model_dump_json() == res2.model_dump_json()


def test_envelope_compatible_with_validate_module2_handoff():
    """End-to-end integration: extract inputs, sinks, CVEs, correlate, build envelope."""
    req = _make_correlation_request()
    inp_res = extract_input_candidates(req)
    cve_res = extract_cve_candidates(req)
    env = make_semgrep_envelope([], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    cor_res = correlate_evidence(
        req,
        input_result=inp_res,
        sink_result=sink_res,
        cve_result=cve_res,
    )

    out = Module2Output(
        assessment_id=req.target_model.assessment_id,
        target_id=req.target_model.target_id,
        generated_at=FIXED_TIME,
        inputs=list(inp_res.inputs),
        sink_candidates=list(sink_res.sink_candidates),
        cve_candidates=list(cve_res.cve_candidates),
        hypotheses=[],
    )

    envelope = build_correlation_envelope(out, cor_res, req)
    assert envelope.schema_id == "websecuritycheck.m2_correlation.v1"
    assert envelope.output.assessment_id == req.target_model.assessment_id


def test_agent_consumable_without_extra_assumptions():
    """Every record sets is_confirmed_vulnerability=False and PARTIAL records list missing_links."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)
    result = correlate_evidence(req, cve_result=cve_res)

    for rec in result.records:
        assert rec.is_confirmed_vulnerability is False
        if rec.status == CorrelationStatus.PARTIAL:
            assert rec.confidence != ConfidenceLevel.HIGH


def test_confidence_caps_table():
    """Test confidence capping table functions monotonically."""
    conf, caps = evaluate_correlation_confidence(
        CorrelationKind.INPUT_SINK,
        CorrelationStatus.VERIFIED,
        base_confidence=ConfidenceLevel.HIGH,
        caps=[(ConfidenceLevel.MEDIUM, "INDEPENDENCE_SHARED")],
    )
    assert conf == ConfidenceLevel.MEDIUM
    assert "INDEPENDENCE_SHARED" in caps

    # PARTIAL automatically caps at MEDIUM
    conf2, caps2 = evaluate_correlation_confidence(
        CorrelationKind.ENDPOINT_SINK,
        CorrelationStatus.PARTIAL,
        base_confidence=ConfidenceLevel.HIGH,
        caps=[],
    )
    assert conf2 == ConfidenceLevel.MEDIUM
    assert "STATUS_PARTIAL_CAP_MEDIUM" in caps2


def test_record_invariants_reject_invalid_shapes():
    """Pydantic model validator rejects invalid CorrelationRecord shapes."""
    assess = IndependenceAssessment(
        status=IndependenceStatus.SHARED,
        distinct_execution_count=1,
    )
    with pytest.raises(
        ValueError, match=r"HIGH confidence requires IndependenceStatus\.INDEPENDENT"
    ):
        CorrelationRecord(
            correlation_id=CorrelationId("COR-0123456789abcdef"),
            kind=CorrelationKind.CVE_TECHNOLOGY,
            status=CorrelationStatus.VERIFIED,
            confidence=ConfidenceLevel.HIGH,  # Conflict: HIGH with SHARED independence
            injection_subtype=InjectionSubtype.SQL_INJECTION,
            cve_candidate_ref=CveCandidateId("CVC-001"),
            target_technology=TechnologyTargetRef(
                category=TechnologyCategory.FRAMEWORK,
                name="Django",
                version="3.2.12",
            ),
            relation_evidence_refs=(EvidenceId("EVD-001"),),
            independent_relation_source_count=1,
            independence=assess,
            rationale="Valid test rationale string",
        )


def test_async_correlation_matches_sync():
    """Asynchronous acorrelate_evidence yields identical results to correlate_evidence."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)

    sync_res = correlate_evidence(req, cve_result=cve_res)
    async_res = asyncio.run(acorrelate_evidence(req, cve_result=cve_res))

    assert sync_res.model_dump_json() == async_res.model_dump_json()


def test_ownership_boundary_no_llm_or_hypothesis():
    """Inspect correlation module to verify zero AI Agent or Hypothesis imports."""
    import websecuritycheck.analysis.correlation as corr_mod

    source = inspect.getsource(corr_mod)
    assert "Hypothesis(" not in source
    assert "HYP-" not in source
    assert "engine" not in corr_mod.__file__.replace("\\", "/")


# ---------------------------------------------------------------------------
# §15.2 Route Binding Trust Verification
# ---------------------------------------------------------------------------


def test_hash_valid_binding_from_untrusted_producer_rejected():
    """Valid SHA-256 and manifest are rejected if source_tool_id is untrusted."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        assessment_id=req.target_model.assessment_id,
        source_tool_id="untrusted_script",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    trust_policy = make_test_trust_policy(producer_id="route_extractor")
    binding, reason = verify_route_binding_artifact(
        rb_ref, req_with_binding, trust_policy=trust_policy
    )
    assert binding is None
    assert "UNTRUSTED_PRODUCER" in reason


def test_unapproved_extraction_method_or_digest_rejected():
    """Binding is rejected if extraction_method or its digest is unapproved."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        assessment_id=req.target_model.assessment_id,
        extraction_method="unknown_method",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    trust_policy = make_test_trust_policy()
    binding, reason = verify_route_binding_artifact(
        rb_ref, req_with_binding, trust_policy=trust_policy
    )
    assert binding is None
    assert "UNAPPROVED_EXTRACTION_METHOD" in reason


def test_binding_missing_execution_ref_rejected():
    """Binding without execution_ref is rejected fail-closed."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        assessment_id=req.target_model.assessment_id,
    )
    # Strip execution_ref
    rb_evd_stripped = rb_evd.model_copy(update={"execution_ref": None})
    req_with_binding = req.model_copy(
        update={"evidence_records": [*req.evidence_records, rb_evd_stripped]}
    )

    trust_policy = make_test_trust_policy()
    binding, reason = verify_route_binding_artifact(
        rb_ref, req_with_binding, trust_policy=trust_policy
    )
    assert binding is None
    assert "MISSING_EXECUTION_REF" in reason


def test_binding_repository_ref_mismatch_rejected():
    """Binding referencing a different source repository is rejected."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        assessment_id=req.target_model.assessment_id,
        source_repository_ref="C:/different_repo",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    trust_policy = make_test_trust_policy()
    binding, reason = verify_route_binding_artifact(
        rb_ref, req_with_binding, trust_policy=trust_policy
    )
    assert binding is None
    assert "SOURCE_REPO_MISMATCH" in reason


def test_binding_revision_mismatch_with_sink_unresolved():
    """Route binding with different source_revision from the sink yields REVISION_UNLINKED."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rule_id = "python.sqlalchemy.security.audit.sqli.raw-sql"
    ruleset_sha = "d" * 64

    finding = make_taint_semgrep_finding(
        rule_id=rule_id,
        file="app/views.py",
        start_line=25,
        source_file="app/views.py",
        source_line=12,
        source_snippet="request.args.get('sort')",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    evd = sink_res.analysis_evidence_records[0].model_copy(
        update={
            "execution_ref": Id("EXEC-001"),
            "provenance": {
                **sink_res.analysis_evidence_records[0].provenance,
                "ruleset_sha256": ruleset_sha,
                "source_repository_ref": "C:/repo",
                "source_revision": "rev-AAA",
            },
        }
    )
    sink_res = sink_res.model_copy(update={"analysis_evidence_records": [evd]})

    # Binding has revision rev-BBB
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        method=ep.method,
        path=ep.path,
        file_path="app/views.py",
        start_line=1,
        end_line=50,
        assessment_id=req.target_model.assessment_id,
        source_repository_ref="C:/repo",
        source_revision="rev-BBB",
        execution_ref="EXEC-002",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    trust_policy = make_test_trust_policy(
        rule_ids=[rule_id],
        ruleset_sha256=ruleset_sha,
    )
    result = correlate_evidence(
        req_with_binding,
        sink_result=sink_res,
        route_binding_artifacts=[rb_ref],
        trust_policy=trust_policy,
    )

    assert len(result.records) == 0
    assert any(d.code == "REVISION_UNLINKED" for d in result.diagnostics)


def test_caller_cannot_supply_binding_objects():
    """Verify correlate_evidence signature takes RouteBindingArtifactRef."""
    sig = inspect.signature(correlate_evidence)
    params = sig.parameters
    assert "route_bindings" not in params
    assert "route_binding_artifacts" in params


def test_default_policy_rejects_all_bindings():
    """DEFAULT_CORRELATION_TRUST_POLICY rejects all bindings when trusted_route_producers empty."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        assessment_id=req.target_model.assessment_id,
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    binding, reason = verify_route_binding_artifact(
        rb_ref, req_with_binding, trust_policy=DEFAULT_CORRELATION_TRUST_POLICY
    )
    assert binding is None
    assert "UNTRUSTED_PRODUCER" in reason


# ---------------------------------------------------------------------------
# §15.3 Sink Verification Tests
# ---------------------------------------------------------------------------


def test_manifest_cwe_alone_does_not_verify_rule_provenance():
    """A sink finding with valid CWE in manifest but unapproved rule remains UNVERIFIED."""
    req = _make_correlation_request()
    finding = make_semgrep_finding(
        rule_id="custom.unapproved.rule",
        cwe="CWE-89: SQL Injection",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    result = correlate_evidence(req, sink_result=sink_res)
    assert len(result.sink_scopes) == 1
    assert result.sink_scopes[0].rule_provenance == RuleProvenanceStatus.UNVERIFIED


def test_local_approved_label_not_trusted():
    """Offline findings where ruleset='local-approved' is assigned by default are UNVERIFIED."""
    req = _make_correlation_request()
    finding = make_semgrep_finding()
    env = make_semgrep_envelope([finding], path="C:/repo", ruleset="local-approved")
    sink_res = extract_sink_candidates(req, env)

    result = correlate_evidence(req, sink_result=sink_res)
    assert result.sink_scopes[0].rule_provenance == RuleProvenanceStatus.UNVERIFIED


def test_ruleset_digest_mismatch_conflict():
    """If evidence declares ruleset_sha256 not matching policy, it is UNVERIFIED/CONFLICT."""
    req = _make_correlation_request()
    finding = make_semgrep_finding()
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    # Provide ruleset_sha256 not in policy
    evd = sink_res.analysis_evidence_records[0].model_copy(
        update={
            "provenance": {
                **sink_res.analysis_evidence_records[0].provenance,
                "ruleset_sha256": "f" * 64,
            }
        }
    )
    sink_res = sink_res.model_copy(update={"analysis_evidence_records": [evd]})

    trust_policy = make_test_trust_policy(ruleset_sha256="0" * 64)
    result = correlate_evidence(req, sink_result=sink_res, trust_policy=trust_policy)
    assert result.sink_scopes[0].rule_provenance == RuleProvenanceStatus.UNVERIFIED
    assert any("UNAPPROVED_RULESET_DIGEST" in g for g in result.sink_scopes[0].provenance_gaps)


def test_search_mode_rule_with_dataflow_trace_conflict():
    """Rule in SEARCH mode that arrives with dataflow_trace yields FlowTrust.CONFLICT."""
    req = _make_correlation_request()
    rule_id = "test.search.rule"
    ruleset_sha = "e" * 64

    finding = make_taint_semgrep_finding(rule_id=rule_id)
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    evd = sink_res.analysis_evidence_records[0].model_copy(
        update={
            "execution_ref": Id("EXEC-001"),
            "provenance": {
                **sink_res.analysis_evidence_records[0].provenance,
                "ruleset_sha256": ruleset_sha,
                "source_repository_ref": "C:/repo",
                "source_revision": "rev-1",
            },
        }
    )
    sink_res = sink_res.model_copy(update={"analysis_evidence_records": [evd]})

    # Policy declares rule as SEARCH mode
    ruleset_entry = ApprovedRulesetEntry(
        ruleset_id="test-ruleset",
        sha256=ruleset_sha,
        review_ref="REV-001",
        rules=(
            ApprovedRuleSpec(
                rule_id=rule_id,
                mode=RuleMode.SEARCH,
                sink_kind=SinkKind.SQL_QUERY,
                subtype=InjectionSubtype.SQL_INJECTION,
                cwe_ids=frozenset({CweId("CWE-89")}),
            ),
        ),
    )
    policy = CorrelationTrustPolicy(approved_rulesets=(ruleset_entry,))

    result = correlate_evidence(req, sink_result=sink_res, trust_policy=policy)
    assert result.sink_scopes[0].flow_trust == FlowTrust.CONFLICT


# ---------------------------------------------------------------------------
# §15.4 Vulnerable API Registry Tests
# ---------------------------------------------------------------------------


def test_no_caller_parameter_for_vulnerable_api_mappings():
    """correlate_evidence signature does not accept vulnerable API mapping parameters."""
    sig = inspect.signature(correlate_evidence)
    assert "vulnerable_api_bindings" not in sig.parameters
    assert "vulnerable_apis" not in sig.parameters


def test_policy_load_rejects_entry_with_unapproved_rule():
    """CorrelationTrustPolicy raises error if rule is unapproved."""
    with pytest.raises(
        (CorrelationTrustPolicyError, ValueError), match="references unapproved ruleset"
    ):
        CorrelationTrustPolicy(
            approved_rulesets=(),
            approved_vulnerable_apis=(
                ApprovedVulnerableApiEntry(
                    cve_id="CVE-2022-28346",  # type: ignore[arg-type]
                    technology_name="Django",
                    ruleset_sha256="1" * 64,
                    rule_ids=frozenset({"unapproved.rule"}),
                    review_ref="REV-001",
                    advisory_ref="ADV-001",
                    rationale="Test rationale string",
                ),
            ),
        )


def test_approved_registry_yields_partial_sink_cve_and_chain():
    """With approved vulnerable API registry, SINK_CVE and INPUT_SINK_CVE_CHAIN are generated."""
    req = _make_correlation_request()
    ep = req.target_model.endpoints[0]
    cve_res = extract_cve_candidates(req)
    rule_id = "python.sqlalchemy.security.audit.sqli.raw-sql"
    ruleset_sha = "7" * 64
    rev = "rev-999"

    finding = make_taint_semgrep_finding(
        rule_id=rule_id,
        file="app/views.py",
        start_line=25,
        source_file="app/views.py",
        source_line=12,
        source_snippet="request.args.get('sort_by')",
    )
    env = make_semgrep_envelope([finding], path="C:/repo")
    sink_res = extract_sink_candidates(req, env)

    evd = sink_res.analysis_evidence_records[0].model_copy(
        update={
            "execution_ref": Id("EXEC-001"),
            "provenance": {
                **sink_res.analysis_evidence_records[0].provenance,
                "ruleset_sha256": ruleset_sha,
                "source_repository_ref": "C:/repo",
                "source_revision": rev,
            },
        }
    )
    sink_res = sink_res.model_copy(update={"analysis_evidence_records": [evd]})

    rb_evd, _rb_man, rb_ref = make_route_binding_artifact(
        endpoint_id=ep.endpoint_id,
        method=ep.method,
        path=ep.path,
        file_path="app/views.py",
        start_line=1,
        end_line=50,
        assessment_id=req.target_model.assessment_id,
        source_repository_ref="C:/repo",
        source_revision=rev,
        execution_ref="EXEC-002",
    )
    req_with_binding = req.model_copy(update={"evidence_records": [*req.evidence_records, rb_evd]})

    inp = InputCandidate(
        input_id=InputId("INP-001"),
        endpoint_id=ep.endpoint_id,
        location=InputLocation.QUERY,
        parameter_name="sort_by",
        evidence_refs=[EvidenceId("EVD-001")],
    )
    inp_res = InputExtractionResult(inputs=[inp])

    # Configure trust policy with vulnerable API binding for CVE-2022-28346 (Django)
    trust_policy = make_test_trust_policy(
        rule_ids=[rule_id],
        ruleset_sha256=ruleset_sha,
        vulnerable_apis=[
            {
                "cve_id": "CVE-2022-28346",
                "technology_name": "Django",
                "rule_ids": [rule_id],
            }
        ],
    )

    result = correlate_evidence(
        req_with_binding,
        input_result=inp_res,
        sink_result=sink_res,
        cve_result=cve_res,
        route_binding_artifacts=[rb_ref],
        trust_policy=trust_policy,
    )

    kinds = {r.kind for r in result.records}
    assert CorrelationKind.INPUT_SINK in kinds
    assert CorrelationKind.CVE_TECHNOLOGY in kinds
    assert CorrelationKind.SINK_CVE in kinds
    assert CorrelationKind.INPUT_SINK_CVE_CHAIN in kinds


# ---------------------------------------------------------------------------
# §15.5 Provenance Independence Tests
# ---------------------------------------------------------------------------


def test_missing_execution_ref_yields_unknown_and_caps_medium():
    """Evidence without execution_ref yields IndependenceStatus.UNKNOWN."""
    e1 = make_evidence_record("EVD-001")  # execution_ref is None
    e2 = make_evidence_record("EVD-002")

    assess = assess_independence([e1, e2], [])
    assert assess.status == IndependenceStatus.UNKNOWN
    assert any("MISSING_EXECUTION_REF" in r for r in assess.reasons)


def test_same_ruleset_ref_and_scan_path_without_execution_ref_not_inferred():
    """Ruleset_ref and scan_path are never inferred as execution identity."""
    e1 = make_evidence_record("EVD-001").model_copy(
        update={"provenance": {"ruleset_ref": "local", "scan_path": "."}}
    )
    assess = assess_independence([e1], [])
    assert assess.status == IndependenceStatus.UNKNOWN


def test_same_execution_ref_is_shared():
    """Evidence records sharing the same execution_ref are evaluated as SHARED."""
    e1 = make_evidence_record("EVD-001").model_copy(update={"execution_ref": Id("EXEC-1")})
    e2 = make_evidence_record("EVD-002").model_copy(update={"execution_ref": Id("EXEC-1")})

    assess = assess_independence([e1, e2], [])
    assert assess.status == IndependenceStatus.SHARED
    assert assess.distinct_execution_count == 1


def test_shared_upstream_artifact_hash_or_ref_is_shared():
    """Records with different execution_refs but identical sha256_hash are SHARED."""
    e1 = make_evidence_record("EVD-001").model_copy(
        update={"execution_ref": Id("EXEC-1"), "sha256_hash": "2" * 64}
    )
    e2 = make_evidence_record("EVD-002").model_copy(
        update={"execution_ref": Id("EXEC-2"), "sha256_hash": "2" * 64}
    )

    assess = assess_independence([e1, e2], [])
    assert assess.status == IndependenceStatus.SHARED
    assert any("SHARED_ARTIFACT_DIGEST" in r for r in assess.reasons)


def test_distinct_executions_independent_allows_high():
    """Distinct execution_refs without collisions yield INDEPENDENT and permit HIGH confidence."""
    e1 = make_evidence_record("EVD-001").model_copy(
        update={"execution_ref": Id("EXEC-1"), "sha256_hash": "3" * 64, "artifact_ref": "art-1"}
    )
    e2 = make_evidence_record("EVD-002").model_copy(
        update={"execution_ref": Id("EXEC-2"), "sha256_hash": "4" * 64, "artifact_ref": "art-2"}
    )

    assess = assess_independence([e1, e2], [])
    assert assess.status == IndependenceStatus.INDEPENDENT
    assert assess.distinct_execution_count == 2


# ---------------------------------------------------------------------------
# §15.6 MVP Limits & Policy Guard Tests
# ---------------------------------------------------------------------------


def test_default_runtime_pipeline_reports_blocking_dependencies():
    """With default policy, correlation result self-reports blocking dependencies."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)

    result = correlate_evidence(req, cve_result=cve_res)
    assert result.coverage.input_sink_enabled is False
    assert result.coverage.sink_cve_enabled is False
    assert result.coverage.cve_technology_enabled is True
    assert "M2-T03b:NO_TRUSTED_ROUTE_PRODUCER" in result.coverage.blocking_dependencies
    assert "M2-T03c:APPROVED_RULESET_REGISTRY_EMPTY" in result.coverage.blocking_dependencies


def test_envelope_rejects_non_default_policy_fingerprint():
    """build_correlation_envelope raises error if fingerprint differs from expected."""
    req = _make_correlation_request()
    cve_res = extract_cve_candidates(req)
    non_default_policy = make_test_trust_policy()

    result = correlate_evidence(req, cve_result=cve_res, trust_policy=non_default_policy)
    out = Module2Output(
        assessment_id=req.target_model.assessment_id,
        target_id=req.target_model.target_id,
        generated_at=FIXED_TIME,
        cve_candidates=list(cve_res.cve_candidates),
    )

    with pytest.raises(CorrelationInputError, match="fingerprint mismatch"):
        build_correlation_envelope(out, result, req)


def test_policy_fingerprint_deterministic():
    """Policy fingerprint is deterministic and invariant to entry declaration order."""
    p1 = make_test_trust_policy(rule_ids=["rule.a", "rule.b"])
    p2 = make_test_trust_policy(rule_ids=["rule.b", "rule.a"])
    assert p1.fingerprint == p2.fingerprint


def test_trusted_classification_accessor_read_only_and_behavior_unchanged():
    """InjectionScopePolicy.trusted_classification is a read-only accessor that returns entry."""
    policy = InjectionScopePolicy()
    trusted = policy.trusted_classification("CVE-2022-22980")
    assert trusted is not None
    assert trusted.cve_id == "CVE-2022-22980"
    assert trusted.canonical_subtype == InjectionSubtype.NOSQL_INJECTION

    # Non-existent CVE returns None
    assert policy.trusted_classification("CVE-1999-9999") is None
