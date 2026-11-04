"""Coordinator for deterministic processing of completed L6 results."""

from __future__ import annotations

from websecuritycheck.domain import (
    ArtifactManifest,
    AssessmentConfig,
    ReconProcessingResult,
    TargetModel,
    ToolExecutionResult,
)

from .endpoints import normalize_endpoints
from .evidence import RecordIdAllocator, create_evidence_records
from .observations import extract_observations
from .target_model import create_target_model, update_target_model
from .technology import normalize_technologies


def process_tool_result(
    execution: ToolExecutionResult,
    *,
    current_target_model: TargetModel | None = None,
    assessment: AssessmentConfig | None = None,
    target_id: str = "TGT-001",
    allocator: RecordIdAllocator | None = None,
) -> ReconProcessingResult:
    if execution.status.value in {"PENDING", "RUNNING"}:
        raise ValueError("only completed or partial tool results can be processed")
    if execution.result_schema_version != "1.0":
        raise ValueError(
            f"unsupported tool result schema version {execution.result_schema_version!r}"
        )
    if assessment is not None and assessment.assessment_id != execution.assessment_id:
        raise ValueError("execution assessment does not match the trusted assessment policy")
    if (
        current_target_model is not None
        and current_target_model.assessment_id != execution.assessment_id
    ):
        raise ValueError("execution assessment does not match the target model")
    if allocator is None:
        existing_ids: list[str] = []
        if current_target_model is not None:
            existing_ids.extend(item.endpoint_id for item in current_target_model.endpoints)
            existing_ids.extend(
                ref for item in current_target_model.endpoints for ref in item.observation_refs
            )
            existing_ids.extend(
                ref for item in current_target_model.endpoints for ref in item.evidence_refs
            )
            existing_ids.extend(
                ref for item in current_target_model.technologies for ref in item.observation_refs
            )
            existing_ids.extend(
                ref for item in current_target_model.technologies for ref in item.evidence_refs
            )
        allocator = RecordIdAllocator(existing_ids)
    if not execution.artifact_manifests:
        embedded = execution.result_data.get("artifact_manifests")
        if isinstance(embedded, list):
            manifests = [
                ArtifactManifest.model_validate(item) for item in embedded if isinstance(item, dict)
            ]
            if manifests:
                execution = execution.model_copy(update={"artifact_manifests": manifests})
    evidence = create_evidence_records(execution, allocator=allocator)
    observations = extract_observations(execution, evidence, allocator=allocator)
    endpoint_updates = normalize_endpoints(observations, allocator=allocator)
    technology_updates = normalize_technologies(observations)
    if current_target_model is None:
        model = create_target_model(
            assessment_id=execution.assessment_id,
            target_id=target_id,
            assessment=assessment,
            assets=[execution.target] if execution.target else [],
            now=execution.finished_at or execution.started_at,
        )
        model.endpoints = endpoint_updates
        model.technologies = technology_updates
        model_changed = bool(endpoint_updates or technology_updates or execution.target)
    else:
        model = current_target_model
        model, changed = update_target_model(
            model,
            endpoint_updates=endpoint_updates,
            technology_updates=technology_updates,
            assets=[execution.target] if execution.target else [],
            now=execution.finished_at or execution.started_at,
        )
        model_changed = changed
    return ReconProcessingResult(
        execution_ref=execution.execution_id,
        evidence_records=evidence,
        observation_records=observations,
        endpoint_updates=endpoint_updates,
        technology_updates=technology_updates,
        updated_target_model=model,
        model_changed=model_changed,
        warnings=list(execution.warnings),
        errors=list(execution.errors),
    )
