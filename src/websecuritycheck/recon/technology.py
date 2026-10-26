"""Deterministic technology signal normalization."""

from __future__ import annotations

from websecuritycheck.domain import (
    ObservationRecord,
    TechnologyObservationPayload,
    TechnologyRecord,
)


def _key(category: str, name: str, version: str | None) -> tuple[str, str, str]:
    return category.upper(), name.casefold().strip(), (version or "").casefold().strip()


def normalize_technologies(
    observations: list[ObservationRecord | TechnologyRecord],
    *,
    existing: list[TechnologyRecord] | None = None,
) -> list[TechnologyRecord]:
    merged: dict[tuple[str, str, str], TechnologyRecord] = {
        _key(item.category.value, item.name, item.version): item.model_copy(deep=True)
        for item in (existing or [])
    }
    for observation in observations:
        if isinstance(observation, TechnologyRecord):
            key = _key(observation.category.value, observation.name, observation.version)
            incoming = observation
        else:
            if not isinstance(observation.payload, TechnologyObservationPayload):
                continue
            payload = observation.payload
            key = _key(payload.category.value, payload.name, payload.version)
            incoming = TechnologyRecord(
                category=payload.category,
                name=payload.name,
                version=payload.version,
                confidence=payload.confidence,
                observation_refs=[observation.observation_id],
                evidence_refs=sorted(set(observation.evidence_refs)),
            )
        if key not in merged:
            merged[key] = incoming.model_copy(deep=True)
            continue
        record = merged[key]
        record.observation_refs = sorted(set(record.observation_refs + incoming.observation_refs))
        record.evidence_refs = sorted(set(record.evidence_refs + incoming.evidence_refs))
        if record.confidence.value == "UNKNOWN" or incoming.confidence.value == "HIGH":
            record.confidence = incoming.confidence
    return sorted(merged.values(), key=lambda item: _key(item.category.value, item.name, item.version))
