"""Sink models, safe repository path helpers, confidence scoring, and identity keys."""

from __future__ import annotations

import re
from pathlib import PurePosixPath

from pydantic import Field

from websecuritycheck.domain import ArtifactManifest, EvidenceArtifactRecord
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CweId,
    SinkCandidate,
    SinkId,
    SinkKind,
    StrictModel,
)

from ..opengrep_adapter.snapshot import _IGNORED_DIRS


class SinkCorrelationMetadata(StrictModel):
    """Structured static metadata preserved for M2-T05 correlation."""

    sink_id: SinkId
    primary_rule_id: str = Field(min_length=1)
    all_rule_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[CweId] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)
    taint_source_snippet: str | None = None
    taint_source_file: str | None = None
    taint_source_line: int | None = Field(default=None, ge=1)
    all_taint_sources: list[str] = Field(default_factory=list)
    taint_origin: str | None = None
    candidate_input_names_in_handler: list[str] = Field(default_factory=list)
    ast_sanitized_or_parameterized: bool = False
    ast_sanitization_reason: str | None = None


class SinkExtractionResult(StrictModel):
    """Deterministic output of Module 2 Opengrep sink candidate extraction."""

    sink_candidates: list[SinkCandidate] = Field(default_factory=list)
    analysis_evidence_records: list[EvidenceArtifactRecord] = Field(default_factory=list)
    artifact_manifests: list[ArtifactManifest] = Field(default_factory=list)
    sink_metadata: dict[SinkId, SinkCorrelationMetadata] = Field(default_factory=dict)
    scanned_files: list[str] = Field(default_factory=list)
    opengrep_version: str | None = None
    ruleset_sha256: str | None = None
    execution_ref: str | None = None
    source_revision: str | None = None
    source_repository_ref: str | None = None
    source_repo_path: str | None = None
    source_tree_sha256: str | None = None
    worktree_dirty: bool | None = None
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def normalize_sink_file_path(path_str: str) -> str:
    """Normalize a sink file path to a clean forward-slash relative path."""
    cleaned = path_str.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = re.sub(r"/+", "/", cleaned)
    return cleaned.strip("/")


def is_safe_sink_path(path_str: str) -> bool:
    """Validate that a relative path stays within the repository and avoids ignored dirs."""
    if not path_str or path_str.startswith(("/", "\\")) or ":" in path_str:
        return False
    parts = PurePosixPath(path_str).parts
    if not parts or ".." in parts:
        return False
    return not any(part in _IGNORED_DIRS for part in parts)


def _compute_confidence(
    raw_conf: str | None, raw_sev: str | None, has_taint_flow: bool
) -> ConfidenceLevel:
    conf_u = (raw_conf or "").upper()
    sev_u = (raw_sev or "").upper()

    if has_taint_flow:
        if conf_u == "HIGH" or (not conf_u and sev_u in {"ERROR", "HIGH"}):
            return ConfidenceLevel.HIGH
        if conf_u == "LOW":
            return ConfidenceLevel.LOW
        return ConfidenceLevel.MEDIUM

    if conf_u in {"HIGH", "MEDIUM"} or sev_u in {"ERROR", "HIGH", "WARNING", "MEDIUM"}:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def sink_identity_key(
    file_path: str,
    start_line: int,
    end_line: int | None,
    sink_kind: SinkKind,
    *,
    canonical_span: tuple[int, int, int, int] | None = None,
    ambiguous_discriminator: str = "",
) -> tuple[str, str, int, int, int, int, str]:
    """Build a deterministic identity key for sink deduplication."""
    norm_path = normalize_sink_file_path(file_path)
    resolved_end = end_line if end_line is not None else start_line
    if canonical_span is not None:
        s_line, e_line, s_col, e_col = canonical_span
        return (norm_path, sink_kind.value, s_line, e_line, s_col, e_col, "")
    return (
        norm_path,
        sink_kind.value,
        start_line,
        resolved_end,
        0,
        0,
        ambiguous_discriminator,
    )


__all__ = [
    "SinkCorrelationMetadata",
    "SinkExtractionResult",
    "_compute_confidence",
    "is_safe_sink_path",
    "normalize_sink_file_path",
    "sink_identity_key",
]

