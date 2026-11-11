"""InputCandidate result model, normalization helpers, and state accumulators."""

from __future__ import annotations

import re
from dataclasses import dataclass, field

from pydantic import Field

from websecuritycheck.domain.analysis_models import InputCandidate
from websecuritycheck.domain.enums import (
    DiscoverySource,
    InputLocation,
    ObservationSource,
)
from websecuritycheck.domain.models import (
    EndpointDefinition,
    EndpointId,
    StrictModel,
)
from websecuritycheck.recon.endpoints import normalize_path

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


__all__ = [
    "_EVIDENCE_ID_RE",
    "_OBSERVATION_ID_RE",
    "_ROUTE_SPEC_SOURCES",
    "InputExtractionResult",
    "_InputAccumulator",
    "_UnverifiedCandidate",
    "_extract_template_params_from_path",
    "_normalize_data_type",
    "_observation_to_discovery_source",
    "_path_matches_template",
    "input_identity_key",
    "normalize_parameter_name",
]
