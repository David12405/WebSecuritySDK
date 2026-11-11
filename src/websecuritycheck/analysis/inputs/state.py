"""Stateful extraction accumulator and verified reference resolution for inputs."""

from __future__ import annotations

from collections.abc import Set

from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.domain.enums import DiscoverySource, InputLocation
from websecuritycheck.domain.models import EndpointDefinition, EndpointId
from websecuritycheck.recon.endpoints import (
    endpoint_key,
    normalize_method,
    normalize_origin,
    normalize_path,
)

from .models import (
    _EVIDENCE_ID_RE,
    _OBSERVATION_ID_RE,
    _extract_template_params_from_path,
    _InputAccumulator,
    _normalize_data_type,
    _path_matches_template,
    _UnverifiedCandidate,
    input_identity_key,
    normalize_parameter_name,
)


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


__all__ = ["_ExtractionState"]

