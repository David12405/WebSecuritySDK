"""Deterministic CVE matching and candidate extraction pipeline."""

from __future__ import annotations

from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CVECandidate,
    EvidenceId,
    Module2AnalysisRequest,
    ObservationId,
    TechnologyTargetRef,
)
from websecuritycheck.domain.enums import ObservationType, TechnologyCategory
from websecuritycheck.domain.models import ObservationRecord, TechnologyRecord

from .models import (
    CPEProductEntry,
    CVEAdvisoryRecord,
    CVECorrelationMetadata,
    CVEEvaluationDiagnostic,
    CVEExtractionResult,
    InjectionScopeStatus,
    InjectionSubtype,
    ProductMatchKind,
    VersionApplicability,
)
from .policy import InjectionScopePolicy
from .provider import (
    AsyncVulnerabilityKnowledgePort,
    LocalSeedCVEProvider,
    VulnerabilityKnowledgeProvider,
)
from .version_matcher import (
    _calculate_provenance_independence,
    _parse_numeric_dot_tuple,
    evaluate_version_applicability,
    normalize_technology_fingerprint,
)


def extract_cve_candidates(
    request: Module2AnalysisRequest,
    *,
    provider: VulnerabilityKnowledgeProvider | None = None,
    scope_policy: InjectionScopePolicy | None = None,
    caller_asserted_evidence_ids: frozenset[EvidenceId] | set[EvidenceId] | None = None,
    caller_asserted_observation_ids: frozenset[ObservationId] | set[ObservationId] | None = None,
) -> CVEExtractionResult:
    """Deterministically match versioned technologies against Injection CVEs."""
    if provider is None:
        provider = LocalSeedCVEProvider()
    if scope_policy is None:
        scope_policy = InjectionScopePolicy()

    verified_evd_ids = {e.evidence_id for e in request.evidence_records} | set(
        caller_asserted_evidence_ids or ()
    )
    verified_obs_ids = {o.observation_id for o in request.observations} | set(
        caller_asserted_observation_ids or ()
    )

    diagnostics: list[CVEEvaluationDiagnostic] = []
    limitations: list[str] = []

    if not provider.is_complete_source:
        limitations.append(
            "LocalSeedCVEProvider is an offline MVP seed catalog with limited product and "
            "CVE coverage; zero matched CVE candidates never implies the target technology "
            "is free of known vulnerabilities."
        )

    tech_keys = {
        (t.category.value.upper(), t.name.casefold().strip(), (t.version or "").casefold().strip())
        for t in request.target_model.technologies
    }
    for obs in request.observations:
        if obs.observation_type == ObservationType.NETWORK_SERVICE:
            payload = obs.payload
            product = getattr(payload, "product", None)
            version = getattr(payload, "version", None)
            if product and version:
                norm_p = product.casefold().strip()
                norm_v = version.casefold().strip()
                matched_in_model = any(k[1] == norm_p and k[2] == norm_v for k in tech_keys)
                if not matched_in_model:
                    limitations.append(
                        f"Observation {obs.observation_id} detected network service "
                        f"{product} {version} which is not promoted into "
                        "TargetModel.technologies (CR-M1-02); skipping CVE extraction "
                        "to prevent handoff reference validation failure."
                    )

    intermediate_candidates: list[
        tuple[
            TechnologyRecord,
            CVEAdvisoryRecord,
            CPEProductEntry,
            ProductMatchKind,
            InjectionSubtype,
            list[EvidenceId],
            list[ObservationId],
            int,
            bool,
        ]
    ] = []

    for tech in request.target_model.technologies:
        if not tech.version or not tech.version.strip():
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=None,
                    stage="version_parsing",
                    outcome="SKIPPED",
                    reason="TechnologyRecord has no version specified",
                )
            )
            continue

        tech_verified_evd = [ref for ref in tech.evidence_refs if ref in verified_evd_ids]
        tech_verified_obs = [ref for ref in tech.observation_refs if ref in verified_obs_ids]
        tech_verified_refs = set(tech_verified_evd) | set(tech_verified_obs)

        if not tech_verified_refs:
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="grounding",
                    outcome="SKIPPED",
                    reason="TechnologyRecord has no verified evidence or observation references",
                )
            )
            continue

        norm_name, norm_version = normalize_technology_fingerprint(tech.name, tech.version)
        match_kind, product_entry = provider.resolve_product(norm_name, tech.category)

        if (
            match_kind in (ProductMatchKind.UNMAPPED, ProductMatchKind.AMBIGUOUS)
            or product_entry is None
        ):
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="product_matching",
                    outcome="SKIPPED",
                    reason=f"Product resolution result was {match_kind.value}",
                )
            )
            continue

        advisories = provider.query_by_product(product_entry.vendor, product_entry.product)
        if not advisories:
            diagnostics.append(
                CVEEvaluationDiagnostic(
                    technology_name=tech.name,
                    technology_version=tech.version,
                    stage="catalog_coverage",
                    outcome="SKIPPED",
                    reason=(
                        f"No advisories found for {product_entry.vendor}:{product_entry.product}"
                    ),
                )
            )
            continue

        corroborating_obs: list[ObservationRecord] = []
        for obs in request.observations:
            if obs.observation_id not in verified_obs_ids:
                continue
            if obs.observation_type == ObservationType.TECHNOLOGY:
                p_name = getattr(obs.payload, "name", "")
                p_ver = getattr(obs.payload, "version", "")
                if (
                    p_name.casefold().strip() == tech.name.casefold().strip()
                    and (p_ver or "").casefold().strip() == tech.version.casefold().strip()
                ):
                    corroborating_obs.append(obs)
            elif obs.observation_type == ObservationType.NETWORK_SERVICE:
                p_prod = getattr(obs.payload, "product", "")
                p_ver = getattr(obs.payload, "version", "")
                if p_prod and p_ver:
                    clean_p, clean_v = normalize_technology_fingerprint(p_prod, p_ver)
                    if clean_p == norm_name and clean_v == norm_version:
                        corroborating_obs.append(obs)

        corrob_evd_refs: list[EvidenceId] = list(tech_verified_evd)
        corrob_obs_refs: list[ObservationId] = list(tech_verified_obs)
        for obs in corroborating_obs:
            if obs.observation_id not in corrob_obs_refs:
                corrob_obs_refs.append(obs.observation_id)
            for evd_ref in obs.evidence_refs:
                if evd_ref in verified_evd_ids and evd_ref not in corrob_evd_refs:
                    corrob_evd_refs.append(evd_ref)

        independent_source_count = _calculate_provenance_independence(
            tech, corroborating_obs, request.evidence_records
        )

        for adv in advisories:
            scope_eval = scope_policy.evaluate(adv)
            if scope_eval.status == InjectionScopeStatus.EXCLUDED:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="injection_scope",
                        outcome="EXCLUDED",
                        reason=scope_eval.reason,
                    )
                )
                continue
            if scope_eval.status == InjectionScopeStatus.UNKNOWN:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="injection_scope",
                        outcome="UNKNOWN",
                        reason=scope_eval.reason,
                    )
                )
                continue

            app_status, app_reason = evaluate_version_applicability(
                norm_version, adv.affected_range, scheme=product_entry.version_scheme
            )
            if app_status == VersionApplicability.NOT_AFFECTED:
                continue
            if app_status == VersionApplicability.UNKNOWN:
                diagnostics.append(
                    CVEEvaluationDiagnostic(
                        technology_name=tech.name,
                        technology_version=tech.version,
                        cve_id=adv.cve_id,
                        stage="version_applicability",
                        outcome="UNKNOWN",
                        reason=app_reason,
                    )
                )
                continue

            assert scope_eval.subtype is not None
            intermediate_candidates.append(
                (
                    tech,
                    adv,
                    product_entry,
                    match_kind,
                    scope_eval.subtype,
                    corrob_evd_refs,
                    corrob_obs_refs,
                    independent_source_count,
                    scope_eval.used_trusted_allowlist,
                )
            )

    grouped: dict[
        tuple[tuple[str, str, str], str],
        list[
            tuple[
                TechnologyRecord,
                CVEAdvisoryRecord,
                CPEProductEntry,
                ProductMatchKind,
                InjectionSubtype,
                list[EvidenceId],
                list[ObservationId],
                int,
                bool,
            ]
        ],
    ] = {}

    for item in intermediate_candidates:
        tech, adv = item[0], item[1]
        t_ref = TechnologyTargetRef.from_record(tech)
        key = (t_ref.canonical_key, adv.cve_id)
        grouped.setdefault(key, []).append(item)

    cve_candidates: list[CVECandidate] = []
    correlation_metadata: list[CVECorrelationMetadata] = []

    sorted_group_keys = sorted(grouped.keys(), key=lambda k: (k[0], k[1]))

    for idx, g_key in enumerate(sorted_group_keys, start=1):
        items = grouped[g_key]
        primary_item = items[0]
        (
            tech,
            adv,
            _product_entry,
            match_kind,
            injection_subtype,
            _,
            _,
            _,
            used_trusted_allowlist,
        ) = primary_item

        merged_evd_refs: set[EvidenceId] = set()
        merged_obs_refs: set[ObservationId] = set()
        max_sources = 1
        for it in items:
            merged_evd_refs.update(it[5])
            merged_obs_refs.update(it[6])
            if it[7] > max_sources:
                max_sources = it[7]

        tech_orig_refs = set(tech.evidence_refs) | set(tech.observation_refs)
        assert (merged_evd_refs | merged_obs_refs) & tech_orig_refs

        parsed_v = _parse_numeric_dot_tuple(tech.version or "")
        is_full_patch_version = parsed_v is not None and parsed_v[2] is not None

        if (
            match_kind == ProductMatchKind.EXACT
            and is_full_patch_version
            and not used_trusted_allowlist
            and max_sources >= 2
            and tech.category != TechnologyCategory.OTHER
        ):
            confidence = ConfidenceLevel.HIGH
        elif (
            (
                match_kind == ProductMatchKind.EXACT
                and is_full_patch_version
                and not used_trusted_allowlist
            )
            or (match_kind == ProductMatchKind.ALIAS and is_full_patch_version and max_sources >= 2)
        ) and tech.category != TechnologyCategory.OTHER:
            confidence = ConfidenceLevel.MEDIUM
        else:
            confidence = ConfidenceLevel.LOW

        cand_id = f"CVC-{idx:03d}"
        target_ref = TechnologyTargetRef.from_record(tech)

        precond_note = (
            f" Preconditions: {'; '.join(adv.environmental_preconditions)}"
            if adv.environmental_preconditions
            else ""
        )
        rationale = (
            f"Matched {tech.name} {tech.version} against {adv.cve_id} ({injection_subtype.value}) "
            f"in range '{adv.affected_range}' via {adv.provider_name}.{precond_note}"
        )

        candidate = CVECandidate(
            cve_candidate_id=cand_id,  # type: ignore[arg-type]
            cve_id=adv.cve_id,
            target_technology=target_ref,
            affected_range=adv.affected_range,
            cwe_id=adv.primary_cwe_id,
            cvss_score=adv.cvss_score,
            confidence=confidence,
            match_rationale=rationale,
            evidence_refs=sorted(merged_evd_refs),
            observation_refs=sorted(merged_obs_refs),
            is_confirmed=False,
        )
        cve_candidates.append(candidate)

        meta = CVECorrelationMetadata(
            cve_candidate_id=cand_id,  # type: ignore[arg-type]
            cve_id=adv.cve_id,
            matched_cpe=adv.cpe_prefix,
            product_match_kind=match_kind,
            injection_subtype=injection_subtype,
            environmental_preconditions=adv.environmental_preconditions,
            independent_source_count=max_sources,
            provider_name=adv.provider_name,
            catalog_version=adv.catalog_version,
            advisory_source=adv.advisory_source,
            published_date=adv.published_date,
            advisory_url=adv.advisory_url,
        )
        correlation_metadata.append(meta)

    return CVEExtractionResult(
        cve_candidates=tuple(cve_candidates),
        correlation_metadata=tuple(correlation_metadata),
        diagnostics=tuple(diagnostics),
        limitations=tuple(limitations),
    )


async def aextract_cve_candidates(
    request: Module2AnalysisRequest,
    *,
    provider: AsyncVulnerabilityKnowledgePort | VulnerabilityKnowledgeProvider | None = None,
    scope_policy: InjectionScopePolicy | None = None,
    caller_asserted_evidence_ids: frozenset[EvidenceId] | set[EvidenceId] | None = None,
    caller_asserted_observation_ids: frozenset[ObservationId] | set[ObservationId] | None = None,
) -> CVEExtractionResult:
    """Asynchronous wrapper for CVE candidate extraction."""
    return extract_cve_candidates(
        request,
        provider=provider,  # type: ignore[arg-type]
        scope_policy=scope_policy,
        caller_asserted_evidence_ids=caller_asserted_evidence_ids,
        caller_asserted_observation_ids=caller_asserted_observation_ids,
    )


__all__ = ["aextract_cve_candidates", "extract_cve_candidates"]

