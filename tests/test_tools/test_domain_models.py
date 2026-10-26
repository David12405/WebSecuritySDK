from datetime import UTC, datetime

import pytest

from websecuritycheck.domain import (
    ArtifactType,
    EndpointObservationPayload,
    EvidenceArtifactRecord,
    ObservationRecord,
    ObservationSource,
    ObservationType,
    TargetModel,
)


def test_artifact_reference_is_distinct_from_storage_uri():
    record = EvidenceArtifactRecord(
        evidence_id="EVD-001",
        assessment_id="ASM-001",
        artifact_type=ArtifactType.TOOL_RAW_OUTPUT,
        artifact_ref="exec-artifact-1",
        storage_uri="s3://bucket/object",
        sha256_hash="0" * 64,
        size_bytes=0,
        captured_at=datetime.now(UTC),
    )
    assert record.artifact_ref == "exec-artifact-1"
    assert record.storage_uri == "s3://bucket/object"


def test_artifact_ref_rejects_physical_uri():
    with pytest.raises(ValueError):
        EvidenceArtifactRecord(
            evidence_id="EVD-001",
            assessment_id="ASM-001",
            artifact_type=ArtifactType.TOOL_RAW_OUTPUT,
            artifact_ref="file:///tmp/result.json",
            sha256_hash="0" * 64,
            size_bytes=0,
            captured_at=datetime.now(UTC),
        )


def test_endpoint_observation_is_structured_and_cohesive():
    observation = ObservationRecord(
        observation_id="OBS-001",
        assessment_id="ASM-001",
        observation_type=ObservationType.ENDPOINT,
        payload=EndpointObservationPayload(
            origin="https://example.com",
            path="/api/search",
            method="POST",
            request_content_types=["application/json"],
            status=200,
        ),
        source_type=ObservationSource.HTTP_OBSERVATION,
        observed_at=datetime.now(UTC),
    )
    assert observation.payload.method == "POST"
    assert observation.payload.status == 200


def test_target_model_revision_fields_are_present():
    model = TargetModel(
        target_id="TGT-001",
        assessment_id="ASM-001",
        last_updated=datetime.now(UTC),
    )
    assert model.schema_version == "2.0.0"
    assert model.revision == 1
    assert not hasattr(model, "revision_history")
