"""Stage 1 & 2 correlation helpers: candidate grounding, scope evaluation, and confidence caps."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from websecuritycheck.domain.analysis_models import (
    AuthoritativeReferenceIndex,
    ConfidenceLevel,
    CVECandidate,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkKind,
)
from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import (
    ArtifactManifest,
    EndpointDefinition,
    EvidenceArtifactRecord,
)

from ..cve import (
    DIRECT_INJECTION_CWES,
    CVECorrelationMetadata,
    CVEExtractionResult,
    InjectionScopePolicy,
    InjectionScopeStatus,
    InjectionSubtype,
)
from ..inputs import InputExtractionResult
from ..sinks import SinkCorrelationMetadata, SinkExtractionResult
from .accessors import classify_injection_sink
from .models import (
    CorrelationDiagnostic,
    InjectionSinkScope,
    RouteHandlerBinding,
)
from .policy import (
    CorrelationInputError,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    IndependenceStatus,
)
from .verifiers import assess_independence


def correlation_identity_key(
    kind: CorrelationKind,
    endpoint_id: str | None,
    location: InputLocation | None,
    parameter_name: str | None,
    sink_file_path: str | None,
    sink_start_line: int | None,
    sink_kind: SinkKind | None,
    source_file: str | None,
    source_line: int | None,
    tech_canonical_key: tuple[str, str, str] | None,
    cve_id: str | None,
    component_identity_keys: Sequence[str] = (),
) -> str:
    """Generate a canonical deterministic identity string for deduplication."""
    parts: list[str] = [kind.value]
    if kind == CorrelationKind.INPUT_SINK:
        parts.extend(
            [
                endpoint_id or "",
                location.value if location else "",
                parameter_name or "",
                sink_file_path or "",
                str(sink_start_line or 0),
                sink_kind.value if sink_kind else "",
                source_file or "",
                str(source_line or 0),
            ]
        )
    elif kind == CorrelationKind.ENDPOINT_SINK:
        parts.extend(
            [
                endpoint_id or "",
                sink_file_path or "",
                str(sink_start_line or 0),
                sink_kind.value if sink_kind else "",
                source_file or "-",
                str(source_line or 0),
            ]
        )
    elif kind == CorrelationKind.CVE_TECHNOLOGY:
        cat, name, ver = tech_canonical_key or ("", "", "")
        parts.extend([cat, name, ver, cve_id or ""])
    elif kind == CorrelationKind.SINK_CVE:
        cat, name, ver = tech_canonical_key or ("", "", "")
        parts.extend(
            [sink_file_path or "", str(sink_start_line or 0), cve_id or "", cat, name, ver]
        )
    elif kind == CorrelationKind.INPUT_SINK_CVE_CHAIN:
        parts.extend(sorted(component_identity_keys))
    return "|".join(parts)


def evaluate_correlation_confidence(
    kind: CorrelationKind,
    status: CorrelationStatus,
    *,
    base_confidence: ConfidenceLevel,
    caps: Sequence[tuple[ConfidenceLevel, str]],
) -> tuple[ConfidenceLevel, tuple[str, ...]]:
    """Determine confidence monotonically capping without ever upgrading."""
    levels = {ConfidenceLevel.LOW: 1, ConfidenceLevel.MEDIUM: 2, ConfidenceLevel.HIGH: 3}
    inv_levels = {1: ConfidenceLevel.LOW, 2: ConfidenceLevel.MEDIUM, 3: ConfidenceLevel.HIGH}

    current_val = levels[base_confidence]
    applied_caps: list[str] = []

    if status == CorrelationStatus.PARTIAL and current_val > levels[ConfidenceLevel.MEDIUM]:
        current_val = levels[ConfidenceLevel.MEDIUM]
        applied_caps.append("STATUS_PARTIAL_CAP_MEDIUM")

    for cap_lvl, cap_reason in caps:
        cap_val = levels[cap_lvl]
        if current_val > cap_val:
            current_val = cap_val
            applied_caps.append(cap_reason)

    return inv_levels[current_val], tuple(applied_caps)


def _stage1_ground_candidates(
    request: Module2AnalysisRequest,
    *,
    input_result: InputExtractionResult | None,
    sink_result: SinkExtractionResult | None,
    cve_result: CVEExtractionResult | None,
    diagnostics: list[CorrelationDiagnostic],
    limitations: list[str],
) -> tuple[
    AuthoritativeReferenceIndex,
    list[Any],
    list[tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord]],
    list[CVECandidate],
]:
    ref_index = AuthoritativeReferenceIndex.from_request(request)
    analysis_evd_map: dict[str, EvidenceArtifactRecord] = {}
    if sink_result:
        for evd in sink_result.analysis_evidence_records:
            if evd.evidence_id in ref_index.evidence_ids:
                raise CorrelationInputError(
                    f"Evidence ID collision with Module 1: {evd.evidence_id}"
                )
            analysis_evd_map[str(evd.evidence_id)] = evd

    all_valid_evd = ref_index.evidence_ids | set(analysis_evd_map.keys())
    all_valid_obs = ref_index.observation_ids

    grounded_inputs: list[Any] = []
    if input_result:
        for inp in input_result.inputs:
            if inp.endpoint_id not in ref_index.endpoint_refs:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=inp.input_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_ENDPOINT_REF",
                        reason=(
                            f"Input {inp.input_id} references unknown endpoint {inp.endpoint_id}"
                        ),
                    )
                )
                continue
            if not all(r in all_valid_evd for r in inp.evidence_refs) or not all(
                r in all_valid_obs for r in inp.observation_refs
            ):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=inp.input_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=(
                            f"Input {inp.input_id} has unresolvable evidence or observation refs"
                        ),
                    )
                )
                continue
            grounded_inputs.append(inp)
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:INPUT_EXTRACTION_SKIPPED")

    sink_manifest_map = (
        {m.artifact_ref: m for m in sink_result.artifact_manifests} if sink_result else {}
    )
    grounded_sinks: list[tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord]] = []
    if sink_result:
        for snk in sink_result.sink_candidates:
            if not snk.evidence_refs or not all(r in all_valid_evd for r in snk.evidence_refs):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=f"Sink {snk.sink_id} has unresolvable evidence refs",
                    )
                )
                continue
            evd_rec = analysis_evd_map.get(str(snk.evidence_refs[0]))
            if not evd_rec:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="MISSING_SOURCE_ARTIFACT",
                        reason=f"Sink {snk.sink_id} missing backing EvidenceArtifactRecord",
                    )
                )
                continue
            man = sink_manifest_map.get(evd_rec.artifact_ref)
            if not man:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="MISSING_MANIFEST",
                        reason=f"Sink {snk.sink_id} missing backing ArtifactManifest",
                    )
                )
                continue
            grounded_sinks.append((snk, man, evd_rec))
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:SINK_EXTRACTION_SKIPPED")

    grounded_cves: list[CVECandidate] = []
    if cve_result:
        for cve in cve_result.cve_candidates:
            t_key = cve.target_technology.canonical_key
            if t_key not in ref_index.technology_refs:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="TECHNOLOGY_UNGROUNDED",
                        reason=f"CVE {cve.cve_candidate_id} technology {t_key} not in TargetModel",
                    )
                )
                continue
            if not all(r in all_valid_evd for r in cve.evidence_refs) or not all(
                r in all_valid_obs for r in cve.observation_refs
            ):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="DANGLING_REFERENCE",
                        reason=f"CVE {cve.cve_candidate_id} has unresolvable refs",
                    )
                )
                continue
            tech_supp = ref_index.technology_refs[t_key]
            cve_supp = set(cve.evidence_refs) | set(cve.observation_refs)
            if tech_supp and not (cve_supp & tech_supp):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="grounding",
                        outcome="UNRESOLVED",
                        code="TECHNOLOGY_UNGROUNDED",
                        reason=f"CVE {cve.cve_candidate_id} refs do not intersect TechnologyRecord",
                    )
                )
                continue
            grounded_cves.append(cve)
    else:
        limitations.append("PARTIAL_UPSTREAM_RESULTS:CVE_EXTRACTION_SKIPPED")

    return ref_index, grounded_inputs, grounded_sinks, grounded_cves


def _stage2_evaluate_scope(
    request: Module2AnalysisRequest,
    *,
    grounded_sinks: list[tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord]],
    grounded_cves: list[CVECandidate],
    sink_metadata_map: dict[Any, SinkCorrelationMetadata],
    cve_meta_map: dict[Any, CVECorrelationMetadata],
    policy: CorrelationTrustPolicy,
    cve_policy: InjectionScopePolicy,
    diagnostics: list[CorrelationDiagnostic],
) -> tuple[
    list[InjectionSinkScope],
    list[tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord, InjectionSinkScope]],
    list[tuple[CVECandidate, InjectionSubtype]],
]:
    sink_scopes: list[InjectionSinkScope] = []
    allowed_sinks: list[
        tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord, InjectionSinkScope]
    ] = []

    for snk, man, evd in grounded_sinks:
        meta = sink_metadata_map.get(snk.sink_id)
        scope_res = classify_injection_sink(
            snk, man, evd, meta, request=request, trust_policy=policy
        )
        sink_scopes.append(scope_res)
        if scope_res.scope_status == InjectionScopeStatus.ALLOWED:
            allowed_sinks.append((snk, man, evd, scope_res))
        else:
            diagnostics.append(
                CorrelationDiagnostic(
                    subject_ref=snk.sink_id,
                    stage="scope",
                    outcome=(
                        "EXCLUDED"
                        if scope_res.scope_status == InjectionScopeStatus.EXCLUDED
                        else "UNRESOLVED"
                    ),
                    code=scope_res.scope_basis,
                    reason=scope_res.reason,
                )
            )

    allowed_cves: list[tuple[CVECandidate, InjectionSubtype]] = []
    for cve in grounded_cves:
        c_meta = cve_meta_map.get(cve.cve_candidate_id)
        if not c_meta:
            diagnostics.append(
                CorrelationDiagnostic(
                    subject_ref=cve.cve_candidate_id,
                    stage="scope",
                    outcome="UNRESOLVED",
                    code="CVE_METADATA_MISSING",
                    reason=f"CVE {cve.cve_candidate_id} missing correlation metadata",
                )
            )
            continue

        trusted = cve_policy.trusted_classification(cve.cve_id)
        if trusted:
            if cve.cwe_id and cve.cwe_id in trusted.expected_cwe_ids:
                allowed_cves.append((cve, trusted.canonical_subtype))
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="scope",
                        outcome="EXCLUDED",
                        code="CVE_SCOPE_REVERIFICATION_FAILED",
                        reason=f"CVE {cve.cve_id} failed trusted classification CWE check",
                    )
                )
        else:
            if cve.cwe_id and cve.cwe_id in DIRECT_INJECTION_CWES:
                st = DIRECT_INJECTION_CWES[cve.cwe_id]
                if st == c_meta.injection_subtype:
                    allowed_cves.append((cve, st))
                else:
                    diagnostics.append(
                        CorrelationDiagnostic(
                            subject_ref=cve.cve_candidate_id,
                            stage="scope",
                            outcome="EXCLUDED",
                            code="CVE_SCOPE_REVERIFICATION_FAILED",
                            reason=(
                                f"Subtype conflict: CWE mapped {st} vs "
                                f"meta {c_meta.injection_subtype}"
                            ),
                        )
                    )
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=cve.cve_candidate_id,
                        stage="scope",
                        outcome="EXCLUDED",
                        code="CVE_SCOPE_REVERIFICATION_FAILED",
                        reason=f"CWE {cve.cwe_id} not in direct injection allowlist",
                    )
                )

    return sink_scopes, allowed_sinks, allowed_cves


def _check_revision_alignment(
    scope_res: InjectionSinkScope,
    matched_b: RouteHandlerBinding,
    *,
    require_non_empty: bool,
) -> bool:
    """Return True when sink and route binding revisions are aligned."""
    if require_non_empty and (
        not scope_res.source_revision or scope_res.source_revision != matched_b.source_revision
    ):
        return False
    if (
        not require_non_empty
        and scope_res.source_revision
        and matched_b.source_revision
        and scope_res.source_revision != matched_b.source_revision
    ):
        return False
    return not (
        scope_res.source_tree_sha256
        and matched_b.source_tree_sha256
        and scope_res.source_tree_sha256 != matched_b.source_tree_sha256
    )


def _compute_caps_and_independence(
    evd: EvidenceArtifactRecord,
    man: ArtifactManifest,
    matched_b: RouteHandlerBinding,
    all_request_evd: dict[str, EvidenceArtifactRecord],
    endpoint_map: dict[str, EndpointDefinition],
) -> tuple[list[EvidenceArtifactRecord], Any, list[tuple[ConfidenceLevel, str]]]:
    binding_evd = all_request_evd.get(matched_b.evidence_ref)
    rel_evd = [evd]
    if binding_evd:
        rel_evd.append(binding_evd)

    ind_assess = assess_independence(rel_evd, [])
    caps: list[tuple[ConfidenceLevel, str]] = []
    if ind_assess.status != IndependenceStatus.INDEPENDENT:
        caps.append((ConfidenceLevel.MEDIUM, f"INDEPENDENCE_{ind_assess.status.value}"))

    matched_ep = endpoint_map.get(matched_b.endpoint_id)
    if matched_ep and not matched_ep.runtime_observed:
        caps.append((ConfidenceLevel.MEDIUM, "ENDPOINT_NOT_RUNTIME_OBSERVED"))

    if man.redaction_applied or man.truncated:
        caps.append((ConfidenceLevel.MEDIUM, "MANIFEST_REDACTION_OR_TRUNCATION"))

    return rel_evd, ind_assess, caps


__all__ = [
    "_check_revision_alignment",
    "_compute_caps_and_independence",
    "_stage1_ground_candidates",
    "_stage2_evaluate_scope",
    "correlation_identity_key",
    "evaluate_correlation_confidence",
]
