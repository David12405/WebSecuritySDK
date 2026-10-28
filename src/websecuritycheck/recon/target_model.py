"""Deterministic TargetModel construction and incremental updates."""

from __future__ import annotations

from datetime import UTC, datetime

from websecuritycheck.domain import (
    AssessmentConfig,
    EndpointDefinition,
    TargetModel,
    TechnologyRecord,
)

from .endpoints import endpoint_key, merge_endpoint
from .technology import normalize_technologies


def create_target_model(
    *,
    assessment_id: str,
    target_id: str = "TGT-001",
    assessment: AssessmentConfig | None = None,
    assets: list[str] | None = None,
    now: datetime | None = None,
) -> TargetModel:
    return TargetModel(
        target_id=target_id,
        assessment_id=assessment_id,
        scope_rules=assessment,
        assets=sorted(set(assets or [])),
        last_updated=now or datetime.now(UTC),
    )


def update_target_model(
    current: TargetModel,
    *,
    endpoint_updates: list[EndpointDefinition] | None = None,
    technology_updates: list[TechnologyRecord] | None = None,
    assets: list[str] | None = None,
    now: datetime | None = None,
) -> tuple[TargetModel, bool]:
    endpoint_map = {
        endpoint_key(item.origin, item.path, item.method): item.model_copy(deep=True)
        for item in current.endpoints
    }
    for incoming in endpoint_updates or []:
        key = endpoint_key(incoming.origin, incoming.path, incoming.method)
        if key in endpoint_map:
            merge_endpoint(endpoint_map[key], incoming)
        else:
            endpoint_map[key] = incoming.model_copy(deep=True)
    endpoints = sorted(
        endpoint_map.values(), key=lambda item: endpoint_key(item.origin, item.path, item.method)
    )
    technologies = normalize_technologies(technology_updates or [], existing=current.technologies)
    next_assets = sorted(set(current.assets + (assets or [])))
    changed = (
        endpoints != current.endpoints
        or technologies != current.technologies
        or next_assets != current.assets
    )
    if not changed:
        return current, False
    updated = current.model_copy(deep=True)
    updated.endpoints = endpoints
    updated.technologies = technologies
    updated.assets = next_assets
    updated.revision += 1
    updated.last_updated = now or datetime.now(UTC)
    return updated, True
