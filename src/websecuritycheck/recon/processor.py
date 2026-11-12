"""Coordinator for deterministic processing of completed L6 results."""

from __future__ import annotations

from collections.abc import Iterable, Sequence

from websecuritycheck.domain import (
    ArtifactManifest,
    AssessmentConfig,
    ReconProcessingResult,
    TargetModel,
    ToolExecutionResult,
)
from websecuritycheck.policy.scope_guard import in_scope, normalize_scope

from .endpoints import normalize_endpoints
from .evidence import RecordIdAllocator, create_evidence_records
from .observations import extract_observations
from .target_model import create_target_model, update_target_model
from .technology import normalize_technologies


def validate_assessment_config(
    assessment: AssessmentConfig,
    *,
    expected_assessment_id: str | None = None,
    target: str | None = None,
    configured_scope: Sequence[str] | None = None,
    allow_subdomains: bool = False,
    require_approved: bool = False,
) -> None:
    """Validate Module 1 security invariants for caller-supplied AssessmentConfig.

    Reuses policy scope parsing/matching without inventing defaults, silently
    broadening authorization, or locking policy lifecycle transitions.
    """
    if expected_assessment_id is not None and assessment.assessment_id != expected_assessment_id:
        raise ValueError("execution assessment does not match the trusted assessment policy")
    if require_approved and not assessment.scope_approval.is_approved:
        raise ValueError("assessment scope approval is required and must be approved")

    authorized_entries = normalize_scope(assessment.authorized_scope)
    excluded_entries = (
        normalize_scope(assessment.excluded_scope) if assessment.excluded_scope else []
    )

    def _ensure_within_scope(candidate: str, label: str) -> None:
        decision = in_scope(candidate, authorized_entries, allow_subdomains=allow_subdomains)
        if not decision:
            raise ValueError(
                f"{label} {candidate!r} is outside authorized_scope: {decision.reason}"
            )
        if excluded_entries and in_scope(
            candidate, excluded_entries, allow_subdomains=allow_subdomains
        ):
            raise ValueError(f"{label} {candidate!r} matches excluded_scope")

    _ensure_within_scope(str(assessment.target), "assessment target")
    if target is not None and target.strip():
        _ensure_within_scope(target, "execution target")
    for scope_entry in configured_scope or ():
        _ensure_within_scope(scope_entry, "configured scope")


def process_tool_result(
    execution: ToolExecutionResult,
    *,
    current_target_model: TargetModel | None = None,
    assessment: AssessmentConfig | None = None,
    target_id: str = "TGT-001",
    allocator: RecordIdAllocator | None = None,
    existing_evidence_ids: Iterable[str] = (),
    existing_observation_ids: Iterable[str] = (),
) -> ReconProcessingResult:
    if execution.status.value in {"PENDING", "RUNNING"}:
        raise ValueError("only completed or partial tool results can be processed")
    if execution.result_schema_version != "1.0":
        raise ValueError(
            f"unsupported tool result schema version {execution.result_schema_version!r}"
        )
    if assessment is not None:
        validate_assessment_config(
            assessment,
            expected_assessment_id=execution.assessment_id,
            target=execution.target,
        )
    if (
        current_target_model is not None
        and current_target_model.assessment_id != execution.assessment_id
    ):
        raise ValueError("execution assessment does not match the target model")
    if allocator is None:
        existing_ids: list[str] = [
            *existing_evidence_ids,
            *existing_observation_ids,
        ]
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
        model_changed = bool(
            endpoint_updates or technology_updates or execution.target or assessment is not None
        )
    else:
        model = current_target_model
        model, changed = update_target_model(
            model,
            endpoint_updates=endpoint_updates,
            technology_updates=technology_updates,
            assessment=assessment,
            assets=[execution.target] if execution.target else [],
            now=execution.finished_at or execution.started_at,
        )
        model_changed = changed
    merged_warnings: list[str] = []
    seen_warnings: set[str] = set()
    nested_data = execution.result_data.get("data")
    embedded_warnings = (
        nested_data.get("warnings")
        if isinstance(nested_data, dict)
        else execution.result_data.get("warnings")
    )
    for item in [*execution.warnings, *(embedded_warnings or [])]:
        text = str(item)
        if text and text not in seen_warnings:
            seen_warnings.add(text)
            merged_warnings.append(text)
    return ReconProcessingResult(
        execution_ref=execution.execution_id,
        evidence_records=evidence,
        observation_records=observations,
        endpoint_updates=endpoint_updates,
        technology_updates=technology_updates,
        updated_target_model=model,
        model_changed=model_changed,
        warnings=merged_warnings,
        errors=list(execution.errors),
    )
