"""Deterministic InputCandidate extraction and normalization (M2-T02).

Consumes canonical Module 1 outputs wrapped in Module2AnalysisRequest and produces
deduplicated, strictly record-grounded InputCandidate records with stable INP-001..N IDs.

Trust Boundary:
`caller_asserted_evidence_ids` and `caller_asserted_observation_ids` (or their aliases
`verified_evidence_ids` / `verified_observation_ids`) represent trusted caller-provided
assertions (e.g. historical records validated by TargetStore or external evidence repository).
The extraction function does not independently query external databases or verify their
underlying storage integrity; it accepts them strictly as authoritative assertions from the caller.
"""

from __future__ import annotations

import re
from collections.abc import Set
from dataclasses import dataclass, field
from urllib.parse import parse_qsl, urlsplit

from pydantic import Field

from websecuritycheck.domain.analysis_models import (
    InputCandidate,
    Module2AnalysisRequest,
)
from websecuritycheck.domain.enums import (
    DiscoverySource,
    InputLocation,
    ObservationSource,
)
from websecuritycheck.domain.models import (
    AuthenticationObservationPayload,
    EndpointDefinition,
    EndpointId,
    EndpointObservationPayload,
    HttpExchangeObservationPayload,
    ObservationRecord,
    ObservedParameter,
    StrictModel,
)
from websecuritycheck.recon.endpoints import (
    endpoint_key,
    normalize_method,
    normalize_origin,
    normalize_path,
)
from websecuritycheck.recon.evidence import RecordIdAllocator

_EVIDENCE_ID_RE = re.compile(r"^EVD-[0-9]{3,}$")
_OBSERVATION_ID_RE = re.compile(r"^OBS-[0-9]{3,}$")
_PATH_TEMPLATE_RE = re.compile(r"^\{([A-Za-z_][A-Za-z0-9_.-]*)\}$")
_ROUTE_SPEC_SOURCES: frozenset[DiscoverySource] = frozenset(
    {DiscoverySource.API_SPEC, DiscoverySource.SOURCE_CODE}
)


class InputExtractionResult(StrictModel):
    """Deterministic result of Module 2 input candidate extraction."""

    inputs: list[InputCandidate] = Field(default_factory=list)
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def normalize_parameter_name(name: str, location: InputLocation) -> str:
    """Normalize parameter name by location (headers are lowercase per RFC 9110)."""
    cleaned = name.strip()
    if location is InputLocation.HEADER:
        return cleaned.lower()
    return cleaned


def input_identity_key(
    endpoint_id: EndpointId, location: InputLocation, parameter_name: str
) -> tuple[EndpointId, str, str]:
    """Return the canonical composite identity key for deduplicating inputs."""
    return (
        endpoint_id,
        location.value,
        normalize_parameter_name(parameter_name, location),
    )


def _observation_to_discovery_source(source: ObservationSource) -> DiscoverySource:
    return {
        ObservationSource.API_SPEC: DiscoverySource.API_SPEC,
        ObservationSource.ZAP: DiscoverySource.CRAWLER,
        ObservationSource.ZAP_PROXY: DiscoverySource.HTTP_OBSERVATION,
        ObservationSource.BROWSER: DiscoverySource.BROWSER,
        ObservationSource.HTTP_OBSERVATION: DiscoverySource.HTTP_OBSERVATION,
    }.get(source, DiscoverySource.OTHER)


def _normalize_data_type(value: str | None) -> str | None:
    if value is None:
        return None
    cleaned = value.strip().lower()
    return cleaned if cleaned else None


def _extract_template_params_from_path(
    path: str,
) -> tuple[list[str], list[str]]:
    """Return (valid_template_param_names, malformed_segments) from an endpoint path."""
    params: list[str] = []
    malformed: list[str] = []
    for segment in path.split("/"):
        if not segment:
            continue
        if segment.startswith("{") or segment.endswith("}"):
            match = _PATH_TEMPLATE_RE.fullmatch(segment)
            if match:
                params.append(match.group(1))
            else:
                malformed.append(segment)
    return params, malformed


def _path_matches_template(concrete_path: str, template_path: str) -> bool:
    """Return True if normalized concrete_path matches parameterized template_path."""
    c_segs = [s for s in normalize_path(concrete_path).split("/") if s]
    t_segs = [s for s in normalize_path(template_path).split("/") if s]
    if len(c_segs) != len(t_segs) or not t_segs:
        return False
    has_template = False
    for c_seg, t_seg in zip(c_segs, t_segs, strict=True):
        if _PATH_TEMPLATE_RE.fullmatch(t_seg):
            has_template = True
            if not c_seg:
                return False
        elif c_seg != t_seg:
            return False
    return has_template


@dataclass
class _InputAccumulator:
    endpoint_id: EndpointId
    location: InputLocation
    parameter_name: str
    data_types: set[str] = field(default_factory=set)
    required_flags: set[bool] = field(default_factory=set)
    discovery_sources: set[DiscoverySource] = field(default_factory=set)
    evidence_refs: set[str] = field(default_factory=set)
    observation_refs: set[str] = field(default_factory=set)


@dataclass
class _UnverifiedCandidate:
    endpoint: EndpointDefinition
    location: InputLocation
    parameter_name: str
    data_type: str | None
    required: bool | None
    discovery_sources: set[DiscoverySource]


class _ExtractionState:
    def __init__(
        self,
        request: Module2AnalysisRequest,
        *,
        caller_asserted_evidence_ids: Set[str] | None = None,
        caller_asserted_observation_ids: Set[str] | None = None,
    ) -> None:
        self.request = request
        self.verified_evd_ids: frozenset[str] = frozenset(
            {evd.evidence_id for evd in request.evidence_records}
            | {
                ref
                for ref in (caller_asserted_evidence_ids or set())
                if _EVIDENCE_ID_RE.fullmatch(ref)
            }
        )
        self.verified_obs_ids: frozenset[str] = frozenset(
            {obs.observation_id for obs in request.observations if obs.validated}
            | {
                ref
                for ref in (caller_asserted_observation_ids or set())
                if _OBSERVATION_ID_RE.fullmatch(ref)
            }
        )

        self.accumulators: dict[tuple[EndpointId, str, str], _InputAccumulator] = {}
        self.unverified_candidates: dict[
            tuple[EndpointId, str, str], list[_UnverifiedCandidate]
        ] = {}
        self.limitations: set[str] = set()
        self.warnings: set[str] = set()

        self.endpoints_by_id: dict[EndpointId, EndpointDefinition] = {}
        self.endpoints_by_norm_key: dict[tuple[str, str, str], EndpointDefinition] = {}
        self.template_endpoints: list[EndpointDefinition] = []

        sorted_eps = sorted(
            request.target_model.endpoints,
            key=lambda ep: (
                *endpoint_key(ep.origin, ep.path, ep.method),
                ep.endpoint_id,
            ),
        )
        for ep in sorted_eps:
            norm_key = endpoint_key(ep.origin, ep.path, ep.method)
            if ep.endpoint_id in self.endpoints_by_id:
                existing = self.endpoints_by_id[ep.endpoint_id]
                merged_ep = existing.model_copy(
                    update={
                        "observed_parameters": [
                            *existing.observed_parameters,
                            *ep.observed_parameters,
                        ],
                        "discovery_sources": sorted(
                            {*existing.discovery_sources, *ep.discovery_sources},
                            key=lambda s: s.value,
                        ),
                        "evidence_refs": sorted({*existing.evidence_refs, *ep.evidence_refs}),
                        "observation_refs": sorted(
                            {*existing.observation_refs, *ep.observation_refs}
                        ),
                    }
                )
                self.endpoints_by_id[ep.endpoint_id] = merged_ep
                self.endpoints_by_norm_key[norm_key] = merged_ep
            else:
                self.endpoints_by_id[ep.endpoint_id] = ep
                self.endpoints_by_norm_key[norm_key] = ep

        for ep in self.endpoints_by_id.values():
            t_params, _ = _extract_template_params_from_path(ep.path)
            if t_params:
                self.template_endpoints.append(ep)

    def add_limitation(self, msg: str) -> None:
        self.limitations.add(msg)

    def add_warning(self, msg: str) -> None:
        self.warnings.add(msg)

    def filter_verified_refs(
        self,
        raw_evd_refs: list[str],
        raw_obs_refs: list[str],
        *,
        context_label: str,
    ) -> tuple[set[str], set[str]]:
        valid_evd: set[str] = set()
        for ref in sorted(set(raw_evd_refs)):
            if not _EVIDENCE_ID_RE.fullmatch(ref):
                self.add_warning(f"Ignored non-EVD reference {ref!r} on {context_label}")
            elif ref not in self.verified_evd_ids:
                self.add_warning(
                    f"Ignored unverified evidence_ref {ref!r} on {context_label} "
                    "(not in request.evidence_records or trusted caller assertions)"
                )
            else:
                valid_evd.add(ref)

        valid_obs: set[str] = set()
        for ref in sorted(set(raw_obs_refs)):
            if not _OBSERVATION_ID_RE.fullmatch(ref):
                self.add_warning(f"Ignored non-OBS reference {ref!r} on {context_label}")
            elif ref not in self.verified_obs_ids:
                self.add_warning(
                    f"Ignored unverified observation_ref {ref!r} on {context_label} "
                    "(not in validated request.observations or trusted caller assertions)"
                )
            else:
                valid_obs.add(ref)

        return valid_evd, valid_obs

    def resolve_endpoint_for_observation(
        self,
        obs_id: str,
        origin: str,
        path: str,
        method: str,
        *,
        has_extracted_data: bool,
    ) -> tuple[EndpointDefinition | None, bool]:
        """Resolve (origin, path, method) to (EndpointDefinition, matched_via_template).

        Exact literal matches take priority. Otherwise checks parameterized route templates.
        """
        norm_origin, norm_path, norm_method = endpoint_key(origin, path, method)
        exact = self.endpoints_by_norm_key.get((norm_origin, norm_path, norm_method))
        if exact is not None:
            t_params, _ = _extract_template_params_from_path(exact.path)
            return exact, bool(t_params)

        matches = [
            ep
            for ep in self.template_endpoints
            if normalize_origin(ep.origin) == norm_origin
            and normalize_method(ep.method) == norm_method
            and _path_matches_template(norm_path, ep.path)
        ]
        if len(matches) == 1:
            return matches[0], True
        if len(matches) > 1:
            match_desc = ", ".join(
                f"{ep.endpoint_id} ({normalize_path(ep.path)})" for ep in matches
            )
            self.add_limitation(
                f"Observation {obs_id} ({norm_method} {norm_origin}{norm_path}) "
                f"ambiguously matched multiple route templates [{match_desc}]; "
                "skipped parameter extraction"
            )
            return None, False

        if has_extracted_data:
            self.add_limitation(
                f"Observation {obs_id} references endpoint "
                f"{norm_method} {norm_origin}{norm_path} "
                "not present in TargetModel.endpoints; skipped parameter extraction"
            )
        return None, False

    def record_candidate(
        self,
        *,
        endpoint: EndpointDefinition,
        location: InputLocation,
        raw_name: str,
        data_type: str | None = None,
        required: bool | None = None,
        discovery_sources: list[DiscoverySource] | set[DiscoverySource] = (),
        evd_refs: set[str],
        obs_refs: set[str],
    ) -> None:
        clean_name = normalize_parameter_name(raw_name, location)
        if not clean_name:
            self.add_warning(
                f"Skipped blank parameter name at location {location.value} "
                f"on endpoint {endpoint.endpoint_id}"
            )
            return

        key = input_identity_key(endpoint.endpoint_id, location, clean_name)
        if not evd_refs and not obs_refs:
            # Isolate unverified candidate: do not contaminate verified accumulators
            self.unverified_candidates.setdefault(key, []).append(
                _UnverifiedCandidate(
                    endpoint=endpoint,
                    location=location,
                    parameter_name=clean_name,
                    data_type=data_type,
                    required=required,
                    discovery_sources=set(discovery_sources),
                )
            )
            return

        acc = self.accumulators.get(key)
        if acc is None:
            acc = _InputAccumulator(
                endpoint_id=endpoint.endpoint_id,
                location=location,
                parameter_name=clean_name,
            )
            self.accumulators[key] = acc

        norm_type = _normalize_data_type(data_type)
        if norm_type is not None:
            acc.data_types.add(norm_type)

        if location is InputLocation.PATH:
            acc.required_flags.add(True)
        elif required is not None:
            acc.required_flags.add(required)

        acc.discovery_sources.update(discovery_sources)
        acc.evidence_refs.update(evd_refs)
        acc.observation_refs.update(obs_refs)

    def process_unverified_candidates(self) -> None:
        """Report unverified candidates as limitations without altering verified metadata."""
        for key in sorted(self.unverified_candidates):
            unverified_list = self.unverified_candidates[key]
            first = unverified_list[0]
            ep = first.endpoint
            # Unverified candidates never override, conflict with, or pollute verified metadata
            self.add_limitation(
                f"Skipped ungrounded parameter {first.parameter_name!r} "
                f"({first.location.value}) on endpoint {ep.endpoint_id} "
                f"({normalize_method(ep.method)} {normalize_path(ep.path)}): "
                "no verified parameter-level evidence_refs or observation_refs"
            )


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
