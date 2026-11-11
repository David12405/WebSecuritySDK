"""M2-T05 Injection-Focused Evidence Correlation Package.

Deterministic, offline, evidence-grounded correlation for Module 2
(Vulnerability Analysis) of WebSecuritySDK. Correlates InputCandidate,
SinkCandidate, and CVECandidate within OWASP Top 10:2025 A05: Injection scope.
"""

from __future__ import annotations

from collections.abc import Sequence

from websecuritycheck.domain.analysis_models import (
    AuthoritativeReferenceIndex,
    Module2AnalysisRequest,
    Module2Output,
    VulnerabilityCategory,
    validate_module2_handoff,
)

from ..cve import CVEExtractionResult, InjectionScopePolicy
from ..inputs import InputExtractionResult
from ..sinks import SinkExtractionResult
from .accessors import classify_injection_sink, parse_taint_source_accessor
from .models import (
    CorrelationCoverage,
    CorrelationDiagnostic,
    CorrelationRecord,
    CorrelationResult,
    IndependenceAssessment,
    InjectionSinkScope,
    Module2CorrelationEnvelope,
    RouteBindingArtifactRef,
    RouteHandlerBinding,
    TaintSourceAccessor,
)
from .policy import (
    DEFAULT_CORRELATION_TRUST_POLICY,
    PINNED_CLOUDFLARE_RULESET_SHA256,
    REVIEWED_CLOUDFLARE_RULESET_ENTRY,
    SINK_KIND_INJECTION_CWES,
    SUBTYPE_TO_CATEGORY,
    AccessorResolution,
    ApprovedRulesetEntry,
    ApprovedRuleSpec,
    ApprovedVulnerableApiEntry,
    CorrelationId,
    CorrelationInputError,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    CorrelationTrustPolicyError,
    FlowTrust,
    IndependenceStatus,
    RuleMode,
    RuleProvenanceStatus,
    TrustedRouteProducer,
    TrustedTaintProducer,
)
from .stage_cves import run_correlation_pipeline
from .stage_grounding import correlation_identity_key, evaluate_correlation_confidence
from .verifiers import (
    assess_independence,
    verify_ast_taint_provenance,
    verify_route_binding_artifact,
)


def correlate_evidence(
    request: Module2AnalysisRequest,
    *,
    input_result: InputExtractionResult | None = None,
    sink_result: SinkExtractionResult | None = None,
    cve_result: CVEExtractionResult | None = None,
    route_binding_artifacts: Sequence[RouteBindingArtifactRef] = (),
    scope_policy: InjectionScopePolicy | None = None,
    trust_policy: CorrelationTrustPolicy | None = None,
) -> CorrelationResult:
    """Execute deterministic 6-stage evidence correlation within A05: Injection scope."""
    return run_correlation_pipeline(
        request,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        route_binding_artifacts=route_binding_artifacts,
        scope_policy=scope_policy,
        trust_policy=trust_policy,
    )


async def acorrelate_evidence(
    request: Module2AnalysisRequest,
    *,
    input_result: InputExtractionResult | None = None,
    sink_result: SinkExtractionResult | None = None,
    cve_result: CVEExtractionResult | None = None,
    route_binding_artifacts: Sequence[RouteBindingArtifactRef] = (),
    scope_policy: InjectionScopePolicy | None = None,
    trust_policy: CorrelationTrustPolicy | None = None,
) -> CorrelationResult:
    """Asynchronous wrapper for deterministic evidence correlation."""
    return correlate_evidence(
        request,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        route_binding_artifacts=route_binding_artifacts,
        scope_policy=scope_policy,
        trust_policy=trust_policy,
    )


def build_correlation_envelope(
    output: Module2Output,
    correlation: CorrelationResult,
    request: Module2AnalysisRequest,
    *,
    expected_trust_policy_fingerprint: str = DEFAULT_CORRELATION_TRUST_POLICY.fingerprint,
) -> Module2CorrelationEnvelope:
    """Package Module2Output and CorrelationResult fail-closed into a validated envelope."""
    validate_module2_handoff(output, request)

    if correlation.trust_policy_fingerprint != expected_trust_policy_fingerprint:
        raise CorrelationInputError(
            f"Correlation trust policy fingerprint mismatch: "
            f"got {correlation.trust_policy_fingerprint}, "
            f"expected {expected_trust_policy_fingerprint}"
        )

    known_inputs = {i.input_id: i for i in output.inputs}
    known_sinks = {s.sink_id: s for s in output.sink_candidates}
    known_cves = {c.cve_candidate_id: c for c in output.cve_candidates}
    known_records = {r.correlation_id: r for r in correlation.records}

    ref_index = AuthoritativeReferenceIndex.from_request(request)
    output_evd_ids = {
        e.evidence_id for e in output.analysis_evidence_records
    } | ref_index.evidence_ids
    output_obs_ids = ref_index.observation_ids

    for rec in correlation.records:
        if rec.input_ref:
            inp = known_inputs.get(rec.input_ref)
            if not inp:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown input {rec.input_ref}"
                )
            if rec.endpoint_id and inp.endpoint_id != rec.endpoint_id:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} endpoint_id {rec.endpoint_id} does not "
                    f"match input {inp.input_id} endpoint {inp.endpoint_id}"
                )

        if rec.sink_ref and rec.sink_ref not in known_sinks:
            raise CorrelationInputError(
                f"Record {rec.correlation_id} references unknown sink {rec.sink_ref}"
            )

        if rec.cve_candidate_ref:
            cve = known_cves.get(rec.cve_candidate_ref)
            if not cve:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown cve {rec.cve_candidate_ref}"
                )
            if rec.target_technology and cve.target_technology != rec.target_technology:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} target_technology does not match CVE candidate"
                )

        for comp_id in rec.component_refs:
            if comp_id not in known_records:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} references unknown component correlation "
                    f"{comp_id}"
                )

        for e_ref in rec.existence_evidence_refs:
            if e_ref not in output_evd_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable existence evidence ref {e_ref}"
                )
        for o_ref in rec.existence_observation_refs:
            if o_ref not in output_obs_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable existence observation ref "
                    f"{o_ref}"
                )
        for r_ref in rec.relation_evidence_refs:
            if r_ref not in output_evd_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable relation evidence ref {r_ref}"
                )
        for ro_ref in rec.relation_observation_refs:
            if ro_ref not in output_obs_ids:
                raise CorrelationInputError(
                    f"Record {rec.correlation_id} has unresolvable relation observation ref "
                    f"{ro_ref}"
                )

    return Module2CorrelationEnvelope(output=output, correlation=correlation)


__all__ = [
    "DEFAULT_CORRELATION_TRUST_POLICY",
    "PINNED_CLOUDFLARE_RULESET_SHA256",
    "REVIEWED_CLOUDFLARE_RULESET_ENTRY",
    "SINK_KIND_INJECTION_CWES",
    "SUBTYPE_TO_CATEGORY",
    "AccessorResolution",
    "ApprovedRuleSpec",
    "ApprovedRulesetEntry",
    "ApprovedVulnerableApiEntry",
    "CorrelationCoverage",
    "CorrelationDiagnostic",
    "CorrelationId",
    "CorrelationInputError",
    "CorrelationKind",
    "CorrelationRecord",
    "CorrelationResult",
    "CorrelationStatus",
    "CorrelationTrustPolicy",
    "CorrelationTrustPolicyError",
    "FlowTrust",
    "IndependenceAssessment",
    "IndependenceStatus",
    "InjectionSinkScope",
    "Module2CorrelationEnvelope",
    "RouteBindingArtifactRef",
    "RouteHandlerBinding",
    "RuleMode",
    "RuleProvenanceStatus",
    "TaintSourceAccessor",
    "TrustedRouteProducer",
    "TrustedTaintProducer",
    "VulnerabilityCategory",
    "acorrelate_evidence",
    "assess_independence",
    "build_correlation_envelope",
    "classify_injection_sink",
    "correlate_evidence",
    "correlation_identity_key",
    "evaluate_correlation_confidence",
    "parse_taint_source_accessor",
    "verify_ast_taint_provenance",
    "verify_route_binding_artifact",
]

