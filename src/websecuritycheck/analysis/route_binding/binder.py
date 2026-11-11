"""Deterministic route-to-endpoint binder and evidence artifact packager."""

from __future__ import annotations

import hashlib
import json
import uuid
from collections.abc import Set
from datetime import UTC, datetime
from pathlib import Path

from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    EndpointDefinition,
    EvidenceArtifactRecord,
    Id,
    TestingMode,
)
from websecuritycheck.domain.analysis_models import EvidenceId, Module2AnalysisRequest
from websecuritycheck.recon.evidence import RecordIdAllocator

from ..opengrep_adapter import (
    _IGNORED_DIRS,
    resolve_source_snapshot,
    validate_source_analysis_scope,
)
from ..sinks import is_safe_sink_path, normalize_sink_file_path
from .js_ts_extractor import _extract_js_ts_routes
from .models import (
    STATIC_ROUTE_PRODUCER_ID,
    ExtractedRawRoute,
    RouteBindingArtifactRef,
    RouteBindingExtractionResult,
    _normalize_path_segments,
)
from .python_extractor import _extract_python_routes


def extract_route_bindings(
    request: Module2AnalysisRequest,
    *,
    evidence_allocator: RecordIdAllocator | None = None,
    execution_ref: str | None = None,
    captured_at: datetime | None = None,
    existing_evidence_ids: Set[str] | None = None,
) -> RouteBindingExtractionResult:
    """Deterministically extract RouteBindingArtifactRef items from repository source code."""
    # Step 1: Validate scope and authorization
    _auth_path, refusal = validate_source_analysis_scope(request, require_existing_filesystem=False)
    if refusal is not None:
        return RouteBindingExtractionResult(limitations=(refusal,))

    rules = request.target_model.scope_rules
    if rules is None or rules.testing_mode == TestingMode.BLACKBOX or not request.source_repo_path:
        return RouteBindingExtractionResult(limitations=("BLACKBOX_OR_MISSING_SOURCE_REPO",))

    repo_root = Path(request.source_repo_path).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        return RouteBindingExtractionResult(
            limitations=(f"Source repository path does not exist on disk: {repo_root}",)
        )

    # Step 2: Resolve snapshot identity
    snapshot = resolve_source_snapshot(repo_root)
    if snapshot.error:
        return RouteBindingExtractionResult(limitations=(f"Snapshot error: {snapshot.error}",))
    if not snapshot.source_revision:
        return RouteBindingExtractionResult(limitations=("MISSING_SOURCE_REVISION",))

    limitations: list[str] = []
    warnings: list[str] = []

    # Step 3: Scan and parse source files
    extracted_routes: list[ExtractedRawRoute] = []
    all_files: list[Path] = []
    for cand in sorted(repo_root.rglob("*")):
        if cand.is_file():
            try:
                rel = cand.relative_to(repo_root)
            except ValueError:
                continue
            if not any(part in _IGNORED_DIRS for part in rel.parts):
                all_files.append(cand)

    for file_path in all_files:
        rel_posix = normalize_sink_file_path(file_path.relative_to(repo_root).as_posix())
        if not is_safe_sink_path(rel_posix):
            continue

        suffix = file_path.suffix.lower()
        if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
            try:
                c_bytes = file_path.read_bytes()
            except OSError as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_js_ts_routes(
                file_path, rel_posix, c_bytes, is_ts=False
            )
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

        elif suffix in {".ts", ".tsx"}:
            try:
                c_bytes = file_path.read_bytes()
            except OSError as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_js_ts_routes(
                file_path, rel_posix, c_bytes, is_ts=True
            )
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

        elif suffix == ".py":
            try:
                c_str = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_python_routes(file_path, rel_posix, c_str)
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

    # Step 4: Deterministically match against TargetModel.endpoints
    known_endpoints = request.target_model.endpoints
    matched_bindings: list[tuple[EndpointDefinition, ExtractedRawRoute]] = []

    for ep in known_endpoints:
        ep_segments = _normalize_path_segments(ep.path)
        ep_method = ep.method.upper().strip()

        candidate_routes = []
        for r in extracted_routes:
            r_segments = _normalize_path_segments(r.path_template)
            if r_segments == ep_segments and (not r.methods or ep_method in r.methods):
                candidate_routes.append(r)

        if len(candidate_routes) == 1:
            matched_bindings.append((ep, candidate_routes[0]))
        elif len(candidate_routes) > 1:
            warnings.append(
                f"AMBIGUOUS_ROUTE_BINDING:{ep.endpoint_id} matches {len(candidate_routes)} handlers"
            )

    # Sort deterministically by endpoint_id
    matched_bindings.sort(
        key=lambda pair: (pair[0].endpoint_id, pair[1].file_path, pair[1].start_line)
    )

    # Seed allocator
    all_known_evidence: set[str] = set()
    for evd in request.evidence_records:
        all_known_evidence.add(str(evd.evidence_id))
    for ep in request.target_model.endpoints:
        all_known_evidence.update(str(r) for r in ep.evidence_refs)
    if existing_evidence_ids:
        all_known_evidence.update(str(x) for x in existing_evidence_ids)

    allocator = evidence_allocator or RecordIdAllocator(all_known_evidence)
    capture_time = captured_at or request.target_model.last_updated or datetime.now(UTC)
    exec_ref = execution_ref or f"EXEC-{uuid.uuid4().int}"

    route_artifacts: list[RouteBindingArtifactRef] = []
    evidence_records: list[EvidenceArtifactRecord] = []
    manifests: list[ArtifactManifest] = []

    for ep, r in matched_bindings:
        evd_id = Id(allocator.new("EVD"))
        art_ref = f"route-binding-{ep.endpoint_id.lower()}"

        payload = {
            "schema": "websecuritycheck.route_binding_artifact.v1",
            "assessment_id": request.target_model.assessment_id,
            "endpoint_id": ep.endpoint_id,
            "method": ep.method.upper().strip(),
            "path": ep.path.strip(),
            "file_path": r.file_path,
            "start_line": r.start_line,
            "end_line": r.end_line,
        }
        content_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        content_bytes = content_str.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        manifest = ArtifactManifest(
            artifact_ref=art_ref,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            content=content_str,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            metadata={
                "endpoint_id": ep.endpoint_id,
                "file_path": r.file_path,
                "start_line": r.start_line,
                "end_line": r.end_line,
            },
        )
        manifests.append(manifest)

        evd_record = EvidenceArtifactRecord(
            evidence_id=evd_id,
            assessment_id=request.target_model.assessment_id,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            artifact_ref=art_ref,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            captured_at=capture_time,
            execution_ref=Id(exec_ref),
            source_tool_id=STATIC_ROUTE_PRODUCER_ID,
            provenance={
                "extraction_method": r.extraction_method,
                "extraction_method_digest": r.extraction_method_digest,
                "source_repository_ref": rules.source_repository_ref,
                "source_repo_path": str(repo_root),
                "source_revision": snapshot.source_revision,
                "source_tree_sha256": snapshot.tree_sha256,
                "worktree_dirty": snapshot.is_dirty,
                "execution_ref": exec_ref,
                "derivation_modality": "static_source_snapshot",
            },
            metadata={
                "endpoint_id": ep.endpoint_id,
                "file_path": r.file_path,
                "start_line": r.start_line,
                "end_line": r.end_line,
            },
        )
        evidence_records.append(evd_record)

        rb_ref = RouteBindingArtifactRef(
            evidence_ref=EvidenceId(str(evd_id)),
            manifest=manifest,
        )
        route_artifacts.append(rb_ref)

    return RouteBindingExtractionResult(
        route_binding_artifacts=tuple(route_artifacts),
        analysis_evidence_records=tuple(evidence_records),
        artifact_manifests=tuple(manifests),
        source_revision=snapshot.source_revision,
        source_tree_sha256=snapshot.tree_sha256,
        execution_ref=exec_ref,
        limitations=tuple(sorted(set(limitations))),
        warnings=tuple(sorted(set(warnings))),
    )


__all__ = ["extract_route_bindings"]
