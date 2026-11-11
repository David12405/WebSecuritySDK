"""Endpoint and observation input extraction pipeline (M2-T02)."""

from __future__ import annotations

from collections.abc import Set
from urllib.parse import parse_qsl, urlsplit

from websecuritycheck.domain.analysis_models import InputCandidate, Module2AnalysisRequest
from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import (
    AuthenticationObservationPayload,
    EndpointDefinition,
    EndpointObservationPayload,
    HttpExchangeObservationPayload,
    ObservationRecord,
    ObservedParameter,
)
from websecuritycheck.recon.endpoints import endpoint_key
from websecuritycheck.recon.evidence import RecordIdAllocator

from .models import (
    _ROUTE_SPEC_SOURCES,
    InputExtractionResult,
    _extract_template_params_from_path,
    _InputAccumulator,
    _observation_to_discovery_source,
    normalize_parameter_name,
)
from .state import _ExtractionState


def _extract_from_endpoint_definitions(state: _ExtractionState) -> None:
    for ep in state.endpoints_by_id.values():
        sorted_params = sorted(
            ep.observed_parameters,
            key=lambda p: (
                p.location.value,
                normalize_parameter_name(p.name, p.location),
                str(p.data_type or ""),
                str(p.required),
                tuple(sorted(p.evidence_refs)),
                tuple(sorted(p.observation_refs)),
            ),
        )
        for param in sorted_params:
            label = f"endpoint {ep.endpoint_id} parameter {param.name!r}"
            evd_refs, obs_refs = state.filter_verified_refs(
                list(param.evidence_refs),
                list(param.observation_refs),
                context_label=label,
            )
            state.record_candidate(
                endpoint=ep,
                location=param.location,
                raw_name=param.name,
                data_type=param.data_type,
                required=param.required,
                discovery_sources=ep.discovery_sources,
                evd_refs=evd_refs,
                obs_refs=obs_refs,
            )

        template_params, malformed_segments = _extract_template_params_from_path(ep.path)
        for bad_seg in malformed_segments:
            state.add_warning(
                f"Ignored malformed path template segment {bad_seg!r} "
                f"on endpoint {ep.endpoint_id} ({ep.path})"
            )

        if template_params:
            has_spec_source = bool(set(ep.discovery_sources) & _ROUTE_SPEC_SOURCES)
            ep_evd: set[str] = set()
            ep_obs: set[str] = set()
            if has_spec_source:
                ep_evd, ep_obs = state.filter_verified_refs(
                    list(ep.evidence_refs),
                    list(ep.observation_refs),
                    context_label=f"endpoint {ep.endpoint_id} path template specification",
                )
            for param_name in template_params:
                state.record_candidate(
                    endpoint=ep,
                    location=InputLocation.PATH,
                    raw_name=param_name,
                    required=True,
                    discovery_sources=ep.discovery_sources,
                    evd_refs=ep_evd,
                    obs_refs=ep_obs,
                )


def _record_observed_parameter_from_obs(
    state: _ExtractionState,
    ep: EndpointDefinition,
    obs: ObservationRecord,
    param: ObservedParameter,
) -> None:
    src = _observation_to_discovery_source(obs.source_type)
    combined_evd = [*obs.evidence_refs, *param.evidence_refs]
    combined_obs = [obs.observation_id, *param.observation_refs]
    evd_refs, obs_refs = state.filter_verified_refs(
        combined_evd,
        combined_obs,
        context_label=f"observation {obs.observation_id} parameter {param.name!r}",
    )
    state.record_candidate(
        endpoint=ep,
        location=param.location,
        raw_name=param.name,
        data_type=param.data_type,
        required=param.required,
        discovery_sources={*ep.discovery_sources, src},
        evd_refs=evd_refs,
        obs_refs=obs_refs,
    )


def _ground_template_params_from_matched_obs(
    state: _ExtractionState,
    ep: EndpointDefinition,
    obs: ObservationRecord,
) -> None:
    template_params, _ = _extract_template_params_from_path(ep.path)
    if not template_params:
        return
    src = _observation_to_discovery_source(obs.source_type)
    evd_refs, obs_refs = state.filter_verified_refs(
        list(obs.evidence_refs),
        [obs.observation_id],
        context_label=f"observation {obs.observation_id} route template match",
    )
    for param_name in template_params:
        state.record_candidate(
            endpoint=ep,
            location=InputLocation.PATH,
            raw_name=param_name,
            required=True,
            discovery_sources={*ep.discovery_sources, src},
            evd_refs=evd_refs,
            obs_refs=obs_refs,
        )


def _extract_from_observations(state: _ExtractionState) -> None:
    sorted_observations = sorted(state.request.observations, key=lambda o: o.observation_id)
    for obs in sorted_observations:
        if not obs.validated:
            state.add_warning(
                f"Skipped unvalidated observation {obs.observation_id} (validated=False)"
            )
            continue

        payload = obs.payload
        if isinstance(payload, EndpointObservationPayload):
            ep, matched_template = state.resolve_endpoint_for_observation(
                obs.observation_id,
                payload.origin,
                payload.path,
                payload.method,
                has_extracted_data=bool(payload.parameters),
            )
            if ep is None:
                continue
            if matched_template:
                _ground_template_params_from_matched_obs(state, ep, obs)
            for param in payload.parameters:
                _record_observed_parameter_from_obs(state, ep, obs, param)

        elif isinstance(payload, HttpExchangeObservationPayload):
            parsed = urlsplit(payload.url)
            if not parsed.scheme or not parsed.netloc:
                state.add_warning(
                    f"Observation {obs.observation_id} has malformed URL {payload.url!r}; skipped"
                )
                continue
            origin = f"{parsed.scheme}://{parsed.netloc}"
            ep, matched_template = state.resolve_endpoint_for_observation(
                obs.observation_id,
                origin,
                parsed.path or "/",
                payload.method,
                has_extracted_data=bool(payload.parameters or parsed.query),
            )
            if ep is None:
                continue
            if matched_template:
                _ground_template_params_from_matched_obs(state, ep, obs)

            seen_query_names: set[str] = set()
            for param in payload.parameters:
                if param.location is InputLocation.QUERY:
                    seen_query_names.add(param.name.strip())
                _record_observed_parameter_from_obs(state, ep, obs, param)

            query_names = sorted(
                {
                    q_name.strip()
                    for q_name, _ in parse_qsl(parsed.query, keep_blank_values=True)
                    if q_name.strip()
                }
            )
            for q_name in query_names:
                if q_name in seen_query_names:
                    continue
                synthetic_param = ObservedParameter(
                    name=q_name,
                    location=InputLocation.QUERY,
                    evidence_refs=list(obs.evidence_refs),
                    observation_refs=[obs.observation_id],
                )
                _record_observed_parameter_from_obs(state, ep, obs, synthetic_param)

        elif isinstance(payload, AuthenticationObservationPayload):
            cleaned_cookies = sorted({c.strip() for c in payload.cookie_names if c and c.strip()})
            if cleaned_cookies:
                state.add_limitation(
                    f"Skipped AuthenticationObservationPayload {obs.observation_id} "
                    f"cookie_names {cleaned_cookies}: authentication observation lacks "
                    "HTTP method and request-parameter provenance for endpoint-specific "
                    "COOKIE input attribution"
                )


def extract_input_candidates(
    request: Module2AnalysisRequest,
    *,
    allocator: RecordIdAllocator | None = None,
    caller_asserted_evidence_ids: Set[str] | None = None,
    caller_asserted_observation_ids: Set[str] | None = None,
    verified_evidence_ids: Set[str] | None = None,
    verified_observation_ids: Set[str] | None = None,
) -> InputExtractionResult:
    """Deterministically extract, normalize, and deduplicate InputCandidates from Module 1 data."""
    if not isinstance(request, Module2AnalysisRequest):
        raise ValueError("request must be a Module2AnalysisRequest instance")

    # Combine caller assertions supporting both parameter naming conventions
    asserted_evd = set(caller_asserted_evidence_ids or set()) | set(verified_evidence_ids or set())
    asserted_obs = set(caller_asserted_observation_ids or set()) | set(
        verified_observation_ids or set()
    )

    state = _ExtractionState(
        request,
        caller_asserted_evidence_ids=asserted_evd,
        caller_asserted_observation_ids=asserted_obs,
    )
    if not state.verified_evd_ids and not state.verified_obs_ids and request.target_model.endpoints:
        state.add_limitation(
            "No authoritative evidence_records, validated observations, or verified store IDs "
            "provided in request; cannot ground InputCandidates from unverified TargetModel "
            "reference strings"
        )

    _extract_from_endpoint_definitions(state)
    _extract_from_observations(state)
    state.process_unverified_candidates()

    def _sort_key(acc: _InputAccumulator) -> tuple[str, str, str, str, str, str]:
        ep = state.endpoints_by_id[acc.endpoint_id]
        norm_origin, norm_path, norm_method = endpoint_key(ep.origin, ep.path, ep.method)
        return (
            norm_origin,
            norm_path,
            norm_method,
            acc.endpoint_id,
            acc.location.value,
            acc.parameter_name,
        )

    sorted_accumulators = sorted(state.accumulators.values(), key=_sort_key)
    id_allocator = allocator or RecordIdAllocator()

    inputs: list[InputCandidate] = []
    for acc in sorted_accumulators:
        resolved_type: str | None = None
        if len(acc.data_types) == 1:
            resolved_type = next(iter(acc.data_types))
        elif len(acc.data_types) > 1:
            conflict_list = sorted(acc.data_types)
            state.add_warning(
                f"Conflicting data_type values {conflict_list} for input "
                f"{acc.parameter_name!r} ({acc.location.value}) on endpoint "
                f"{acc.endpoint_id}; reset to None"
            )

        resolved_required: bool | None = None
        if True in acc.required_flags:
            resolved_required = True
        elif False in acc.required_flags:
            resolved_required = False

        inputs.append(
            InputCandidate(
                input_id=id_allocator.new("INP"),
                endpoint_id=acc.endpoint_id,
                location=acc.location,
                parameter_name=acc.parameter_name,
                data_type=resolved_type,
                required=resolved_required,
                sample_value=None,
                discovery_sources=sorted(acc.discovery_sources, key=lambda item: item.value),
                evidence_refs=sorted(acc.evidence_refs),
                observation_refs=sorted(acc.observation_refs),
            )
        )

    return InputExtractionResult(
        inputs=inputs,
        limitations=sorted(state.limitations),
        warnings=sorted(state.warnings),
    )


__all__ = ["extract_input_candidates"]

