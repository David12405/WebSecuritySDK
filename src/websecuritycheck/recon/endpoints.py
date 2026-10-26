"""Deterministic endpoint and observed-parameter normalization."""

from __future__ import annotations

import contextlib
from urllib.parse import urlsplit, urlunsplit

from websecuritycheck.domain import (
    DiscoverySource,
    EndpointDefinition,
    EndpointObservationPayload,
    InputLocation,
    ObservationRecord,
    ObservationSource,
    ObservedParameter,
)

from .evidence import RecordIdAllocator


def normalize_origin(value: str) -> str:
    parsed = urlsplit(value)
    if not parsed.scheme or not parsed.netloc:
        return value.rstrip("/").lower()
    host = (parsed.hostname or "").rstrip(".").lower()
    with contextlib.suppress(UnicodeError):
        host = host.encode("idna").decode("ascii")
    port = parsed.port
    default = (parsed.scheme.lower() == "http" and port == 80) or (
        parsed.scheme.lower() == "https" and port == 443
    )
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    netloc = host if port is None or default else f"{host}:{port}"
    return urlunsplit((parsed.scheme.lower(), netloc, "", "", ""))


def normalize_path(value: str) -> str:
    path = value or "/"
    if not path.startswith("/"):
        path = "/" + path
    parts = [part for part in path.split("/") if part not in {".", ""}]
    normalized = "/" + "/".join(parts)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized or "/"


def normalize_method(value: str) -> str:
    return value.upper().strip()


def endpoint_key(origin: str, path: str, method: str) -> tuple[str, str, str]:
    return normalize_origin(origin), normalize_path(path), normalize_method(method)


def _source(source: ObservationSource) -> DiscoverySource:
    return {
        ObservationSource.API_SPEC: DiscoverySource.API_SPEC,
        ObservationSource.ZAP: DiscoverySource.CRAWLER,
        ObservationSource.ZAP_PROXY: DiscoverySource.HTTP_OBSERVATION,
        ObservationSource.BROWSER: DiscoverySource.BROWSER,
        ObservationSource.HTTP_OBSERVATION: DiscoverySource.HTTP_OBSERVATION,
    }.get(source, DiscoverySource.OTHER)


def _parameter_key(parameter: ObservedParameter) -> tuple[str, str]:
    name = parameter.name.lower() if parameter.location is InputLocation.HEADER else parameter.name
    return parameter.location.value, name


def _merge_parameters(
    existing: list[ObservedParameter], incoming: list[ObservedParameter]
) -> list[ObservedParameter]:
    merged: dict[tuple[str, str], ObservedParameter] = {
        _parameter_key(item): item.model_copy(deep=True) for item in existing
    }
    for item in incoming:
        key = _parameter_key(item)
        if key not in merged:
            merged[key] = item.model_copy(deep=True)
            continue
        current = merged[key]
        current.evidence_refs = sorted(set(current.evidence_refs + item.evidence_refs))
        current.observation_refs = sorted(set(current.observation_refs + item.observation_refs))
        if current.data_type is None:
            current.data_type = item.data_type
        elif item.data_type and current.data_type != item.data_type:
            current.data_type = None
        if current.content_type is None:
            current.content_type = item.content_type
        if current.required is None:
            current.required = item.required
        elif item.required is True:
            current.required = True
    return sorted(merged.values(), key=lambda item: (item.location.value, item.name))


def endpoint_from_observation(
    observation: ObservationRecord,
    payload: EndpointObservationPayload,
    allocator: RecordIdAllocator,
) -> EndpointDefinition:
    parameters = []
    for parameter in payload.parameters:
        enriched = parameter.model_copy(deep=True)
        enriched.observation_refs = sorted({*enriched.observation_refs, observation.observation_id})
        enriched.evidence_refs = sorted(set(enriched.evidence_refs + observation.evidence_refs))
        parameters.append(enriched)
    return EndpointDefinition(
        endpoint_id=allocator.new("EP"),
        origin=normalize_origin(payload.origin),
        path=normalize_path(payload.path),
        method=normalize_method(payload.method),
        request_content_types=sorted(
            {item.lower().split(";", 1)[0].strip() for item in payload.request_content_types}
        ),
        response_content_types=sorted(
            {item.lower().split(";", 1)[0].strip() for item in payload.response_content_types}
        ),
        observed_parameters=_merge_parameters(parameters, []),
        declared_security=sorted(set(payload.declared_security)),
        discovery_sources=[_source(observation.source_type)],
        evidence_refs=sorted(set(observation.evidence_refs)),
        observation_refs=[observation.observation_id],
    )


def merge_endpoint(
    existing: EndpointDefinition, incoming: EndpointDefinition
) -> EndpointDefinition:
    if endpoint_key(existing.origin, existing.path, existing.method) != endpoint_key(
        incoming.origin, incoming.path, incoming.method
    ):
        raise ValueError("cannot merge endpoints with different identities")
    existing.request_content_types = sorted(
        set(existing.request_content_types + incoming.request_content_types)
    )
    existing.response_content_types = sorted(
        set(existing.response_content_types + incoming.response_content_types)
    )
    existing.observed_parameters = _merge_parameters(
        existing.observed_parameters, incoming.observed_parameters
    )
    existing.declared_security = sorted(
        set(existing.declared_security + incoming.declared_security)
    )
    existing.discovery_sources = sorted(
        set(existing.discovery_sources + incoming.discovery_sources), key=lambda item: item.value
    )
    existing.evidence_refs = sorted(set(existing.evidence_refs + incoming.evidence_refs))
    existing.observation_refs = sorted(set(existing.observation_refs + incoming.observation_refs))
    if existing.required_auth_role is None:
        existing.required_auth_role = incoming.required_auth_role
    return existing


def normalize_endpoints(
    observations: list[ObservationRecord],
    *,
    existing: list[EndpointDefinition] | None = None,
    allocator: RecordIdAllocator | None = None,
) -> list[EndpointDefinition]:
    allocator = allocator or RecordIdAllocator(item.endpoint_id for item in existing or [])
    merged: dict[tuple[str, str, str], EndpointDefinition] = {
        endpoint_key(item.origin, item.path, item.method): item.model_copy(deep=True)
        for item in (existing or [])
    }
    for observation in observations:
        if not isinstance(observation.payload, EndpointObservationPayload):
            continue
        incoming = endpoint_from_observation(observation, observation.payload, allocator)
        key = endpoint_key(incoming.origin, incoming.path, incoming.method)
        if key in merged:
            merge_endpoint(merged[key], incoming)
        else:
            merged[key] = incoming
    return sorted(
        merged.values(), key=lambda item: endpoint_key(item.origin, item.path, item.method)
    )
