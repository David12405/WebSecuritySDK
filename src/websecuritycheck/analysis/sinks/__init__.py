"""Deterministic Opengrep static analysis and sink candidate extraction (M2-T03)."""

from __future__ import annotations

from .classifier import classify_sink_kind, is_non_sink_finding
from .extractor import aextract_sink_candidates, extract_sink_candidates
from .integrity import enrich_sinks_with_ast_taint, verify_sink_evidence_integrity
from .models import (
    SinkCorrelationMetadata,
    SinkExtractionResult,
    is_safe_sink_path,
    normalize_sink_file_path,
    sink_identity_key,
)
from .trace_parser import sanitize_sink_text

__all__ = [
    "SinkCorrelationMetadata",
    "SinkExtractionResult",
    "aextract_sink_candidates",
    "classify_sink_kind",
    "enrich_sinks_with_ast_taint",
    "extract_sink_candidates",
    "is_non_sink_finding",
    "is_safe_sink_path",
    "normalize_sink_file_path",
    "sanitize_sink_text",
    "sink_identity_key",
    "verify_sink_evidence_integrity",
]

