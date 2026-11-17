"""Lightweight Module 1 -> Module 2 request assembly helper."""

from __future__ import annotations

from typing import TYPE_CHECKING

from websecuritycheck.domain import AssessmentConfig
from websecuritycheck.domain.analysis_models import Module2AnalysisRequest

from .processor import validate_assessment_config

if TYPE_CHECKING:
    from websecuritycheck.memory.target_store import SQLiteTargetStore


def build_module2_request(
    store: SQLiteTargetStore,
    assessment_id: str,
    target: str,
    *,
    assessment: AssessmentConfig | None = None,
    source_repo_path: str | None = None,
    require_scope_approval: bool = False,
) -> Module2AnalysisRequest:
    """Assemble a validated Module2AnalysisRequest from persisted Module 1 artifacts.

    Does not fabricate default AssessmentConfig policies or perform orchestration.
    """
    target_model = store.load_target(assessment_id, target)
    if target_model is None:
        raise ValueError(
            f"no target model recorded for assessment {assessment_id!r} and target {target!r}"
        )

    effective_rules = assessment if assessment is not None else target_model.scope_rules
    if effective_rules is not None:
        validate_assessment_config(
            effective_rules,
            expected_assessment_id=assessment_id,
            target=target,
            require_approved=require_scope_approval,
        )
        if assessment is not None and target_model.scope_rules != assessment:
            target_model = target_model.model_copy(update={"scope_rules": assessment})
    elif require_scope_approval:
        raise ValueError("assessment configuration with approved scope is required")

    observations, evidence_records = store.load_processing_records(assessment_id, target)
    return Module2AnalysisRequest(
        target_model=target_model,
        observations=observations,
        evidence_records=evidence_records,
        source_repo_path=source_repo_path,
    )
