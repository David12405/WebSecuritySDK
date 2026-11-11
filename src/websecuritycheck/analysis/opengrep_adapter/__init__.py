"""Concurrency-safe async adapter, strict offline ruleset guard, and scope validator for M2-T03."""

from __future__ import annotations

from .adapter import AsyncSourceAnalysisPort, LocalOpengrepAdapter
from .scope import (
    compute_ruleset_sha256,
    validate_offline_ruleset_path,
    validate_source_analysis_scope,
)
from .snapshot import (
    _IGNORED_DIRS as _IGNORED_DIRS,
)
from .snapshot import (
    SourceSnapshotInfo,
    resolve_source_snapshot,
)

__all__ = [
    "AsyncSourceAnalysisPort",
    "LocalOpengrepAdapter",
    "SourceSnapshotInfo",
    "compute_ruleset_sha256",
    "resolve_source_snapshot",
    "validate_offline_ruleset_path",
    "validate_source_analysis_scope",
]
