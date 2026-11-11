"""Stages 4-6 & pipeline runner: TECH_CVE, SINK_CVE, chain composition, and packaging."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from typing import Any

from websecuritycheck.domain.analysis_models import (
    AuthoritativeReferenceIndex,
    ConfidenceLevel,
    CVECandidate,
    Module2AnalysisRequest,
    SinkCandidate,
    VulnerabilityCategory,
)
from websecuritycheck.domain.models import (
    ArtifactManifest,
    EvidenceArtifactRecord,
    ObservationRecord,
)

from ..cve import (
    CVECorrelationMetadata,
    CVEExtractionResult,
    InjectionScopePolicy,
    InjectionSubtype,
    ProductMatchKind,
)
from ..inputs import InputExtractionResult
from ..sinks import SinkCorrelationMetadata, SinkExtractionResult
from .models import (
    CorrelationCoverage,
    CorrelationDiagnostic,
    CorrelationRecord,
    CorrelationResult,
    InjectionSinkScope,
    RouteBindingArtifactRef,
)
from .policy import (
    DEFAULT_CORRELATION_TRUST_POLICY,
    ApprovedVulnerableApiEntry,
    CorrelationId,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    IndependenceStatus,
    RuleProvenanceStatus,
)
from .stage_grounding import (
    _stage1_ground_candidates,
    _stage2_evaluate_scope,
    correlation_identity_key,
    evaluate_correlation_confidence,
)
from .stage_sinks import _stage3_correlate_sinks
from .verifiers import assess_independence


def _stage4_correlate_cves(
    *,
    allowed_cves: list[tuple[CVECandidate, InjectionSubtype]],
    ref_index: AuthoritativeReferenceIndex,
    cve_meta_map: dict[Any, CVECorrelationMetadata],
    all_request_evd: dict[str, EvidenceArtifactRecord],
    all_request_obs: dict[str, ObservationRecord],
    warnings: list[str],
) -> list[CorrelationRecord]:
    cve_tech_records: list[CorrelationRecord] = []
    for cve, subtype in allowed_cves:
        t_key = cve.target_technology.canonical_key
        tech_supp = ref_index.technology_refs.get(t_key, frozenset())
        cve_supp = set(cve.evidence_refs) | set(cve.observation_refs)
        intersected = cve_supp & tech_supp

        rel_evd = [all_request_evd[e] for e in intersected if e in all_request_evd]
        rel_obs = [all_request_obs[o] for o in intersected if o in all_request_obs]

        ind_assess = assess_independence(rel_evd, rel_obs)
        caps: list[tuple[ConfidenceLevel, str]] = []
        if ind_assess.status != IndependenceStatus.INDEPENDENT:
            caps.append((ConfidenceLevel.MEDIUM, f"INDEPENDENCE_{ind_assess.status.value}"))

        c_meta = cve_meta_map.get(cve.cve_candidate_id)
        preconditions = c_meta.environmental_preconditions if c_meta else ()
        if preconditions:
            caps.append((ConfidenceLevel.MEDIUM, "ENVIRONMENTAL_PRECONDITIONS_PRESENT"))

        status = (
            CorrelationStatus.PARTIAL
            if c_meta and c_meta.product_match_kind == ProductMatchKind.ALIAS
            else CorrelationStatus.VERIFIED
        )
        conf, applied_caps = evaluate_correlation_confidence(
            CorrelationKind.CVE_TECHNOLOGY,
            status,
            base_confidence=cve.confidence,
            caps=caps,
        )

        if c_meta and c_meta.independent_source_count > ind_assess.distinct_execution_count:
            warnings.append(
                f"M2T04_INDEPENDENCE_OVERCOUNT:{cve.cve_candidate_id} "
                f"(M2-T04 reported {c_meta.independent_source_count}, "
                f"verified {ind_assess.distinct_execution_count})"
            )

        key = correlation_identity_key(
            CorrelationKind.CVE_TECHNOLOGY,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            None,
            t_key,
            cve.cve_id,
        )
        cor_id = CorrelationId(f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}")
        missing_links = ("ENVIRONMENTAL_PRECONDITIONS_UNVERIFIED",) if preconditions else ()

        cve_tech_records.append(
            CorrelationRecord(
                correlation_id=cor_id,
                kind=CorrelationKind.CVE_TECHNOLOGY,
                status=status,
                confidence=conf,
                injection_subtype=subtype,
                vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
                cve_candidate_ref=cve.cve_candidate_id,
                target_technology=cve.target_technology,
                existence_evidence_refs=tuple(sorted(cve.evidence_refs)),
                existence_observation_refs=tuple(sorted(cve.observation_refs)),
                relation_evidence_refs=tuple(sorted(e.evidence_id for e in rel_evd)),
                relation_observation_refs=tuple(sorted(o.observation_id for o in rel_obs)),
                independent_relation_source_count=ind_assess.distinct_execution_count,
                independence=ind_assess,
                unverified_preconditions=tuple(preconditions),
                missing_links=missing_links,
                confidence_caps_applied=applied_caps,
                rationale=(
                    f"Grounded CVE {cve.cve_id} against {cve.target_technology.name} "
                    f"{cve.target_technology.version} ({subtype.value})"
                ),
            )
        )
    return cve_tech_records


def _stage5_compose_sink_cves(
    *,
    policy: CorrelationTrustPolicy,
    cve_tech_records: list[CorrelationRecord],
    grounded_cves: list[CVECandidate],
    allowed_sinks: list[
        tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord, InjectionSinkScope]
    ],
    sink_metadata_map: dict[Any, SinkCorrelationMetadata],
    candidate_records: list[CorrelationRecord],
    all_request_evd: dict[str, EvidenceArtifactRecord],
    all_request_obs: dict[str, ObservationRecord],
    limitations: list[str],
) -> None:
    if not policy.approved_vulnerable_apis:
        limitations.append("SINK_CVE_REGISTRY_EMPTY")
        return

    api_by_cve: dict[str, list[ApprovedVulnerableApiEntry]] = {}
    for api in policy.approved_vulnerable_apis:
        api_by_cve.setdefault(api.cve_id, []).append(api)

    for cve_rec in cve_tech_records:
        cve_cand = next(
            (c for c in grounded_cves if c.cve_candidate_id == cve_rec.cve_candidate_ref),
            None,
        )
        if not cve_cand:
            continue
        for api in api_by_cve.get(cve_cand.cve_id, []):
            tech_name = cve_rec.target_technology.name.casefold().strip()  # type: ignore[union-attr]
            if api.technology_name.casefold().strip() != tech_name:
                continue

            for snk, _man, evd, scope_res in allowed_sinks:
                if scope_res.rule_provenance != RuleProvenanceStatus.VERIFIED:
                    continue
                meta = sink_metadata_map.get(snk.sink_id)
                all_rules = set(meta.all_rule_ids) if meta else {snk.rule_id}
                if not (all_rules & api.rule_ids):
                    continue

                rel_evd = [
                    evd,
                    *[
                        all_request_evd[e]
                        for e in cve_rec.relation_evidence_refs
                        if e in all_request_evd
                    ],
                ]
                rel_obs = [
                    all_request_obs[o]
                    for o in cve_rec.relation_observation_refs
                    if o in all_request_obs
                ]
                ind_assess = assess_independence(rel_evd, rel_obs)
                conf, applied_caps = evaluate_correlation_confidence(
                    CorrelationKind.SINK_CVE,
                    CorrelationStatus.PARTIAL,
                    base_confidence=ConfidenceLevel.MEDIUM,
                    caps=[
                        (snk.confidence, "SINK_CONFIDENCE_CAP"),
                        (cve_rec.confidence, "CVE_CONFIDENCE_CAP"),
                    ],
                )
                sink_t_key = (
                    cve_rec.target_technology.category.value,  # type: ignore[union-attr]
                    cve_rec.target_technology.name,  # type: ignore[union-attr]
                    cve_rec.target_technology.version,  # type: ignore[union-attr]
                )
                key = correlation_identity_key(
                    CorrelationKind.SINK_CVE,
                    None,
                    None,
                    None,
                    snk.file_path,
                    snk.start_line,
                    None,
                    None,
                    None,
                    sink_t_key,
                    cve_cand.cve_id,
                )
                sink_cve_id = CorrelationId(
                    f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                )
                sink_cve_rec = CorrelationRecord(
                    correlation_id=sink_cve_id,
                    kind=CorrelationKind.SINK_CVE,
                    status=CorrelationStatus.PARTIAL,
                    confidence=conf,
                    injection_subtype=cve_rec.injection_subtype,
                    vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
                    sink_ref=snk.sink_id,
                    cve_candidate_ref=cve_rec.cve_candidate_ref,
                    target_technology=cve_rec.target_technology,
                    component_refs=(cve_rec.correlation_id,),
                    existence_evidence_refs=tuple(
                        sorted(set(snk.evidence_refs) | set(cve_rec.existence_evidence_refs))
                    ),
                    existence_observation_refs=cve_rec.existence_observation_refs,
                    relation_evidence_refs=tuple(
                        sorted({*snk.evidence_refs, *cve_rec.relation_evidence_refs})
                    ),
                    relation_observation_refs=cve_rec.relation_observation_refs,
                    independent_relation_source_count=ind_assess.distinct_execution_count,
                    independence=ind_assess,
                    confidence_caps_applied=applied_caps,
                    rationale=(
                        f"Correlated sink {snk.sink_id} with CVE {cve_cand.cve_id} via "
                        f"approved vulnerable API registry entry ({api.review_ref})"
                    ),
                )
                candidate_records.append(sink_cve_rec)

                for in_sink_rec in [
                    r
                    for r in candidate_records
                    if r.kind == CorrelationKind.INPUT_SINK
                    and r.status == CorrelationStatus.VERIFIED
                    and r.sink_ref == snk.sink_id
                ]:
                    chain_conf, chain_caps = evaluate_correlation_confidence(
                        CorrelationKind.INPUT_SINK_CVE_CHAIN,
                        CorrelationStatus.PARTIAL,
                        base_confidence=ConfidenceLevel.MEDIUM,
                        caps=[
                            (in_sink_rec.confidence, "INPUT_SINK_CONFIDENCE_CAP"),
                            (sink_cve_rec.confidence, "SINK_CVE_CONFIDENCE_CAP"),
                        ],
                    )
                    chain_key = correlation_identity_key(
                        CorrelationKind.INPUT_SINK_CVE_CHAIN,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        None,
                        component_identity_keys=[
                            in_sink_rec.correlation_id,
                            sink_cve_rec.correlation_id,
                        ],
                    )
                    chain_id = CorrelationId(
                        f"COR-{hashlib.sha256(chain_key.encode('utf-8')).hexdigest()[:16]}"
                    )
                    candidate_records.append(
                        CorrelationRecord(
                            correlation_id=chain_id,
                            kind=CorrelationKind.INPUT_SINK_CVE_CHAIN,
                            status=CorrelationStatus.PARTIAL,
                            confidence=chain_conf,
                            injection_subtype=cve_rec.injection_subtype,
                            vulnerability_category=VulnerabilityCategory.KNOWN_CVE,
                            endpoint_id=in_sink_rec.endpoint_id,
                            input_ref=in_sink_rec.input_ref,
                            sink_ref=snk.sink_id,
                            cve_candidate_ref=cve_rec.cve_candidate_ref,
                            target_technology=cve_rec.target_technology,
                            component_refs=(
                                in_sink_rec.correlation_id,
                                sink_cve_rec.correlation_id,
                            ),
                            existence_evidence_refs=tuple(
                                sorted(
                                    set(in_sink_rec.existence_evidence_refs)
                                    | set(sink_cve_rec.existence_evidence_refs)
                                )
                            ),
                            existence_observation_refs=tuple(
                                sorted(
                                    set(in_sink_rec.existence_observation_refs)
                                    | set(sink_cve_rec.existence_observation_refs)
                                )
                            ),
                            relation_evidence_refs=tuple(
                                sorted(
                                    set(in_sink_rec.relation_evidence_refs)
                                    | set(sink_cve_rec.relation_evidence_refs)
                                )
                            ),
                            relation_observation_refs=sink_cve_rec.relation_observation_refs,
                            independent_relation_source_count=min(
                                in_sink_rec.independent_relation_source_count,
                                sink_cve_rec.independent_relation_source_count,
                            ),
                            independence=in_sink_rec.independence,
                            confidence_caps_applied=chain_caps,
                            rationale=(
                                f"Composed end-to-end chain from input {in_sink_rec.input_ref} "
                                f"via sink {snk.sink_id} to CVE {cve_cand.cve_id}"
                            ),
                        )
                    )


def _stage6_package_result(
    *,
    candidate_records: list[CorrelationRecord],
    sink_scopes: list[InjectionSinkScope],
    diagnostics: list[CorrelationDiagnostic],
    limitations: list[str],
    warnings: list[str],
    allowed_cves: list[tuple[CVECandidate, InjectionSubtype]],
    policy: CorrelationTrustPolicy,
) -> CorrelationResult:
    dedup_map: dict[str, CorrelationRecord] = {}
    levels = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
    inv_levels = {1: ConfidenceLevel.LOW, 2: ConfidenceLevel.MEDIUM, 3: ConfidenceLevel.HIGH}

    for rec in candidate_records:
        cid = rec.correlation_id
        if cid not in dedup_map:
            dedup_map[cid] = rec
        else:
            prev = dedup_map[cid]
            merged_conf = inv_levels[min(levels[prev.confidence], levels[rec.confidence])]
            dedup_map[cid] = prev.model_copy(
                update={
                    "confidence": merged_conf,
                    "existence_evidence_refs": tuple(
                        sorted(set(prev.existence_evidence_refs) | set(rec.existence_evidence_refs))
                    ),
                    "existence_observation_refs": tuple(
                        sorted(
                            set(prev.existence_observation_refs)
                            | set(rec.existence_observation_refs)
                        )
                    ),
                    "relation_evidence_refs": tuple(
                        sorted(set(prev.relation_evidence_refs) | set(rec.relation_evidence_refs))
                    ),
                    "relation_observation_refs": tuple(
                        sorted(
                            set(prev.relation_observation_refs) | set(rec.relation_observation_refs)
                        )
                    ),
                    "confidence_caps_applied": tuple(
                        sorted(set(prev.confidence_caps_applied) | set(rec.confidence_caps_applied))
                    ),
                    "missing_links": tuple(
                        sorted(set(prev.missing_links) | set(rec.missing_links))
                    ),
                    "candidate_input_names_in_handler": tuple(
                        sorted(
                            set(prev.candidate_input_names_in_handler)
                            | set(rec.candidate_input_names_in_handler)
                        )
                    ),
                    "handler_code_slice": prev.handler_code_slice or rec.handler_code_slice,
                }
            )

    kind_order = {
        CorrelationKind.INPUT_SINK: 1,
        CorrelationKind.ENDPOINT_SINK: 2,
        CorrelationKind.CVE_TECHNOLOGY: 3,
        CorrelationKind.SINK_CVE: 4,
        CorrelationKind.INPUT_SINK_CVE_CHAIN: 5,
    }
    status_order = {CorrelationStatus.VERIFIED: 1, CorrelationStatus.PARTIAL: 2}

    sorted_records = sorted(
        dedup_map.values(),
        key=lambda r: (
            kind_order.get(r.kind, 9),
            status_order.get(r.status, 9),
            r.correlation_id,
        ),
    )
    sorted_diagnostics = sorted(
        diagnostics,
        key=lambda d: (d.stage, d.subject_ref, d.code, d.reason),
    )

    blocking: list[str] = []
    if not policy.trusted_route_producers:
        blocking.append("M2-T03b:NO_TRUSTED_ROUTE_PRODUCER")
    if not policy.approved_rulesets:
        blocking.append("M2-T03c:APPROVED_RULESET_REGISTRY_EMPTY")
    if not policy.approved_vulnerable_apis:
        blocking.append("VULNERABLE_API_REGISTRY_EMPTY")

    coverage = CorrelationCoverage(
        input_sink_enabled=any(r.kind == CorrelationKind.INPUT_SINK for r in sorted_records),
        sink_cve_enabled=any(r.kind == CorrelationKind.SINK_CVE for r in sorted_records),
        chain_enabled=any(r.kind == CorrelationKind.INPUT_SINK_CVE_CHAIN for r in sorted_records),
        cve_technology_enabled=any(r.kind == CorrelationKind.CVE_TECHNOLOGY for r in sorted_records)
        or bool(allowed_cves),
        blocking_dependencies=tuple(sorted(blocking)),
    )

    return CorrelationResult(
        records=tuple(sorted_records),
        sink_scopes=tuple(sorted(sink_scopes, key=lambda s: s.sink_id)),
        diagnostics=tuple(sorted_diagnostics),
        limitations=tuple(sorted(set(limitations))),
        warnings=tuple(sorted(set(warnings))),
        coverage=coverage,
        trust_policy_fingerprint=policy.fingerprint,
        trust_policy_is_default=(
            policy.fingerprint == DEFAULT_CORRELATION_TRUST_POLICY.fingerprint
        ),
    )


def run_correlation_pipeline(
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
    policy = trust_policy or DEFAULT_CORRELATION_TRUST_POLICY
    cve_policy = scope_policy or InjectionScopePolicy()
    diagnostics: list[CorrelationDiagnostic] = []
    limitations: list[str] = []
    warnings: list[str] = []

    ref_index, grounded_inputs, grounded_sinks, grounded_cves = _stage1_ground_candidates(
        request,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        diagnostics=diagnostics,
        limitations=limitations,
    )

    sink_metadata_map = sink_result.sink_metadata if sink_result else {}
    cve_meta_map = (
        {m.cve_candidate_id: m for m in cve_result.correlation_metadata} if cve_result else {}
    )

    sink_scopes, allowed_sinks, allowed_cves = _stage2_evaluate_scope(
        request,
        grounded_sinks=grounded_sinks,
        grounded_cves=grounded_cves,
        sink_metadata_map=sink_metadata_map,
        cve_meta_map=cve_meta_map,
        policy=policy,
        cve_policy=cve_policy,
        diagnostics=diagnostics,
    )

    all_request_evd = {e.evidence_id: e for e in request.evidence_records}
    all_request_obs = {o.observation_id: o for o in request.observations}
    endpoint_map = {ep.endpoint_id: ep for ep in request.target_model.endpoints}

    candidate_records = _stage3_correlate_sinks(
        request,
        allowed_sinks=allowed_sinks,
        sink_metadata_map=sink_metadata_map,
        grounded_inputs=grounded_inputs,
        route_binding_artifacts=route_binding_artifacts,
        policy=policy,
        all_request_evd=all_request_evd,
        endpoint_map=endpoint_map,
        diagnostics=diagnostics,
        limitations=limitations,
    )

    cve_tech_records = _stage4_correlate_cves(
        allowed_cves=allowed_cves,
        ref_index=ref_index,
        cve_meta_map=cve_meta_map,
        all_request_evd=all_request_evd,
        all_request_obs=all_request_obs,
        warnings=warnings,
    )
    candidate_records.extend(cve_tech_records)

    _stage5_compose_sink_cves(
        policy=policy,
        cve_tech_records=cve_tech_records,
        grounded_cves=grounded_cves,
        allowed_sinks=allowed_sinks,
        sink_metadata_map=sink_metadata_map,
        candidate_records=candidate_records,
        all_request_evd=all_request_evd,
        all_request_obs=all_request_obs,
        limitations=limitations,
    )

    return _stage6_package_result(
        candidate_records=candidate_records,
        sink_scopes=sink_scopes,
        diagnostics=diagnostics,
        limitations=limitations,
        warnings=warnings,
        allowed_cves=allowed_cves,
        policy=policy,
    )


__all__ = ["run_correlation_pipeline"]
