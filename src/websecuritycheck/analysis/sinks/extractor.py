"""Synchronous and asynchronous sink candidate extraction orchestration (M2-T03)."""

from __future__ import annotations

import hashlib
import inspect
import json
import re
from collections.abc import Mapping, Set
from datetime import UTC, datetime
from pathlib import PurePosixPath
from typing import Any

from mcp_servers.websec_tools.errors import ToolError
from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    EvidenceArtifactRecord,
    Id,
)
from websecuritycheck.domain.analysis_models import (
    EvidenceId,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkId,
)
from websecuritycheck.recon.evidence import RecordIdAllocator

from ..opengrep_adapter import (
    AsyncSourceAnalysisPort,
    LocalOpengrepAdapter,
    validate_source_analysis_scope,
)
from .classifier import classify_sink_kind
from .integrity import _SinkAccumulator, enrich_sinks_with_ast_taint
from .models import (
    SinkCorrelationMetadata,
    SinkExtractionResult,
    _compute_confidence,
    is_safe_sink_path,
    normalize_sink_file_path,
    sink_identity_key,
)
from .trace_parser import _extract_dataflow_info, sanitize_sink_text


def extract_sink_candidates(
    request: Module2AnalysisRequest,
    opengrep_payload: Mapping[str, Any] | None = None,
    *,
    sink_allocator: RecordIdAllocator | None = None,
    evidence_allocator: RecordIdAllocator | None = None,
    existing_evidence_ids: Set[str] | None = None,
    captured_at: datetime | None = None,
    enable_ast_taint: bool = False,
) -> SinkExtractionResult:
    """Synchronously extract and normalize SinkCandidate objects from an Opengrep payload."""
    _authorized_path, refusal_reason = validate_source_analysis_scope(
        request, require_existing_filesystem=False
    )
    if refusal_reason is not None:
        return SinkExtractionResult(limitations=[refusal_reason])

    if opengrep_payload is None:
        return SinkExtractionResult(
            limitations=[
                "No Opengrep payload provided to extract_sink_candidates; skipped sink extraction"
            ]
        )

    raw_data = (
        opengrep_payload.get("data")
        if isinstance(opengrep_payload.get("data"), Mapping)
        else opengrep_payload
    )
    raw_results = raw_data.get("findings")
    if raw_results is None:
        raw_results = raw_data.get("results")
    if not isinstance(raw_results, list):
        return SinkExtractionResult(
            limitations=[
                "Malformed Opengrep output payload: missing valid 'findings' or 'results' list"
            ]
        )

    provenance_tool = str(raw_data.get("tool") or "opengrep")
    provenance_version = raw_data.get("version")
    provenance_ruleset = str(raw_data.get("ruleset") or "local-approved")
    provenance_ruleset_ref = str(
        raw_data.get("ruleset_ref") or raw_data.get("ruleset") or "local-ruleset"
    )
    provenance_ruleset_path = raw_data.get("ruleset_path")
    provenance_ruleset_sha256 = raw_data.get("ruleset_sha256")
    provenance_execution_ref = raw_data.get("execution_ref")
    provenance_source_revision = raw_data.get("source_revision")
    provenance_source_repository_ref = raw_data.get("source_repository_ref")
    provenance_source_repo_path = raw_data.get("source_repo_path")
    provenance_source_tree_sha256 = raw_data.get("source_tree_sha256")
    provenance_worktree_dirty = raw_data.get("worktree_dirty")
    scan_path = str(raw_data.get("path") or ".")
    scanned_files_raw = raw_data.get("scanned_files")
    scanned_files = (
        sorted({str(item) for item in scanned_files_raw})
        if isinstance(scanned_files_raw, list)
        and all(isinstance(item, str) for item in scanned_files_raw)
        else []
    )
    is_truncated = bool(opengrep_payload.get("truncated") or raw_data.get("truncated"))

    limitations: set[str] = set()
    warnings: set[str] = set()
    if raw_data.get("files_scanned") == 0:
        limitations.add("OPENGREP_SCAN_EMPTY")

    if scan_path and (scan_path.startswith("/") or bool(re.match(r"^[A-Za-z]:", scan_path))):
        approved_root = request.target_model.scope_rules.source_repository_ref  # type: ignore[union-attr]
        try:
            norm_scan = normalize_sink_file_path(scan_path)
            norm_app = normalize_sink_file_path(approved_root or "")
            if not PurePosixPath(norm_scan).is_relative_to(PurePosixPath(norm_app)):
                return SinkExtractionResult(
                    limitations=[
                        "Refused Opengrep payload: scan path "
                        f"{scan_path!r} lies outside approved scope {approved_root!r}"
                    ]
                )
        except (ValueError, TypeError):
            pass

    accumulators: dict[tuple[str, str, int, int, int, int, str], _SinkAccumulator] = {}

    for item in raw_results:
        if not isinstance(item, Mapping):
            continue
        rule_id = item.get("rule_id") or item.get("check_id")
        file_raw = item.get("file") or item.get("path")
        if not isinstance(rule_id, str) or not isinstance(file_raw, str):
            continue

        norm_file = normalize_sink_file_path(file_raw)

        if file_raw.startswith("/") or bool(re.match(r"^[A-Za-z]:", file_raw)):
            approved_root = request.target_model.scope_rules.source_repository_ref  # type: ignore[union-attr]
            try:
                norm_app = normalize_sink_file_path(approved_root or "")
                if not PurePosixPath(norm_file).is_relative_to(PurePosixPath(norm_app)):
                    warnings.add(
                        f"Skipped finding with path {file_raw!r} lying outside approved repository"
                    )
                    continue
                norm_file = str(PurePosixPath(norm_file).relative_to(PurePosixPath(norm_app)))
            except (ValueError, TypeError):
                warnings.add(f"Skipped finding with invalid absolute path {file_raw!r}")
                continue

        if not is_safe_sink_path(norm_file):
            warnings.add(
                f"Skipped finding from rule {rule_id!r}: unsafe repository file path {file_raw!r}"
            )
            continue

        start_line = item.get("start_line")
        if start_line is None and isinstance(item.get("start"), Mapping):
            start_line = item["start"].get("line")
        if not isinstance(start_line, int) or start_line < 1:
            continue

        end_line = item.get("end_line")
        if end_line is None and isinstance(item.get("end"), Mapping):
            end_line = item["end"].get("line")
        if isinstance(end_line, int) and end_line < start_line:
            end_line = start_line

        start_col = item.get("start_column")
        if start_col is None and isinstance(item.get("start"), Mapping):
            start_col = item["start"].get("col")
        if not isinstance(start_col, int) or start_col < 1:
            start_col = None

        end_col = item.get("end_column")
        if end_col is None and isinstance(item.get("end"), Mapping):
            end_col = item["end"].get("col")
        if not isinstance(end_col, int) or end_col < 1:
            end_col = None

        extra = item.get("extra") if isinstance(item.get("extra"), Mapping) else {}
        metadata = item.get("metadata") or extra.get("metadata")
        dataflow_trace = item.get("dataflow_trace") or extra.get("dataflow_trace")
        message_raw = item.get("message") or extra.get("message")
        severity_raw = item.get("severity") or extra.get("severity")
        snippet_raw = item.get("snippet") or extra.get("lines")

        (
            has_taint,
            steps,
            src_snip,
            src_file,
            src_line,
            taint_span,
            trace_redacted,
        ) = _extract_dataflow_info(dataflow_trace, norm_file)

        sink_kind, cwes, skip_reason = classify_sink_kind(
            rule_id, metadata, has_taint_trace=has_taint
        )
        if sink_kind is None:
            warnings.add(
                f"Skipped Opengrep finding from rule {rule_id!r} at "
                f"{norm_file}:{start_line}: {skip_reason}"
            )
            continue

        clean_snippet, snip_redacted = sanitize_sink_text(snippet_raw, norm_file, max_chars=500)
        clean_msg, msg_redacted = sanitize_sink_text(message_raw, norm_file, max_chars=300)
        item_redaction = trace_redacted or snip_redacted or msg_redacted

        confidence = _compute_confidence(
            metadata.get("confidence") if isinstance(metadata, Mapping) else None,
            severity_raw,
            has_taint,
        )

        canonical_span: tuple[int, int, int, int] | None = None
        ambiguous_discriminator = ""

        if taint_span is not None:
            canonical_span = taint_span
        elif start_col is not None and end_col is not None:
            canonical_span = (start_line, end_line or start_line, start_col, end_col)
        else:
            snip_hash = hashlib.sha256((clean_snippet or "").encode("utf-8")).hexdigest()[:12]
            ambiguous_discriminator = f"{rule_id}:{snip_hash}"

        key = sink_identity_key(
            norm_file,
            start_line,
            end_line,
            sink_kind,
            canonical_span=canonical_span,
            ambiguous_discriminator=ambiguous_discriminator,
        )

        if key in accumulators:
            accumulators[key].merge(
                rule_id=rule_id,
                confidence=confidence,
                has_static_taint_flow=has_taint,
                dataflow_steps=steps,
                snippet=clean_snippet,
                cwe_ids=cwes,
                severity=severity_raw,
                message=clean_msg,
                taint_source_snippet=src_snip,
                taint_source_file=src_file,
                taint_source_line=src_line,
                redaction_applied=item_redaction,
            )
        else:
            accumulators[key] = _SinkAccumulator(
                file_path=norm_file,
                start_line=start_line,
                end_line=end_line,
                start_column=start_col,
                end_column=end_col,
                sink_kind=sink_kind,
                rule_id=rule_id,
                confidence=confidence,
                has_static_taint_flow=has_taint,
                dataflow_steps=steps,
                snippet=clean_snippet,
                cwe_ids=cwes,
                severity=severity_raw,
                message=clean_msg,
                taint_source_snippet=src_snip,
                taint_source_file=src_file,
                taint_source_line=src_line,
                redaction_applied=item_redaction,
            )

    sorted_accs = sorted(
        accumulators.values(),
        key=lambda acc: (
            acc.file_path,
            acc.start_line,
            acc.end_line or acc.start_line,
            acc.sink_kind.value,
            sorted(acc.rule_ids)[0],
        ),
    )

    all_known_evidence: set[str] = set()
    for evd in request.evidence_records:
        all_known_evidence.add(str(evd.evidence_id))
    for ep in request.target_model.endpoints:
        all_known_evidence.update(str(r) for r in ep.evidence_refs)
        for p in ep.observed_parameters:
            all_known_evidence.update(str(r) for r in p.evidence_refs)
    for tech in request.target_model.technologies:
        all_known_evidence.update(str(r) for r in tech.evidence_refs)
    for obs in request.observations:
        all_known_evidence.update(str(r) for r in obs.evidence_refs)
    if existing_evidence_ids:
        all_known_evidence.update(str(x) for x in existing_evidence_ids)

    snk_alloc = sink_allocator or RecordIdAllocator()
    evd_alloc = evidence_allocator or RecordIdAllocator(all_known_evidence)

    capture_time = captured_at or request.target_model.last_updated or datetime.now(UTC)

    sink_candidates: list[SinkCandidate] = []
    evidence_records: list[EvidenceArtifactRecord] = []
    artifact_manifests: list[ArtifactManifest] = []
    sink_metadata_map: dict[SinkId, SinkCorrelationMetadata] = {}

    for acc in sorted_accs:
        sink_id = SinkId(snk_alloc.new("SNK"))
        evidence_id = Id(evd_alloc.new("EVD"))
        artifact_ref = f"opengrep-sink-{sink_id.lower()}"

        if acc.taint_rule_ids:
            primary_rule_id = sorted(acc.taint_rule_ids)[0]
        else:
            primary_rule_id = sorted(acc.rule_ids)[0]

        selected_snippet = sorted(acc.snippets)[0] if acc.snippets else None

        all_sources: list[str] = []
        for ts_snip, ts_f, ts_l in acc.taint_sources:
            if ts_snip and ts_f and ts_l:
                all_sources.append(f"{ts_f}:{ts_l}: {ts_snip}")
        all_sources = sorted(set(all_sources))

        canonical_payload: dict[str, Any] = {
            "schema": "websecuritycheck.opengrep_sink_artifact.v1",
            "assessment_id": request.target_model.assessment_id,
            "artifact_ref": artifact_ref,
            "sink_id": sink_id,
            "sink_kind": acc.sink_kind.value,
            "file_path": acc.file_path,
            "start_line": acc.start_line,
            "end_line": acc.end_line,
            "start_column": acc.start_column,
            "end_column": acc.end_column,
            "primary_rule_id": primary_rule_id,
            "rule_ids": sorted(acc.rule_ids),
            "cwe_ids": sorted(str(c) for c in acc.cwe_ids),
            "severities": sorted(acc.severities),
            "messages": sorted(acc.messages),
            "snippet": selected_snippet,
            "has_static_taint_flow": acc.has_static_taint_flow,
            "dataflow_steps": acc.dataflow_steps,
            "all_taint_sources": all_sources,
            "redaction_applied": acc.redaction_applied,
            "truncated": is_truncated,
            "provenance": {
                "tool": provenance_tool,
                "version": provenance_version,
                "ruleset": provenance_ruleset,
                "ruleset_ref": provenance_ruleset_ref,
                "ruleset_path": provenance_ruleset_path,
                "ruleset_sha256": provenance_ruleset_sha256,
                "source_revision": provenance_source_revision,
                "source_repository_ref": provenance_source_repository_ref,
                "source_repo_path": provenance_source_repo_path,
                "source_tree_sha256": provenance_source_tree_sha256,
                "worktree_dirty": provenance_worktree_dirty,
                "execution_ref": provenance_execution_ref,
                "scan_path": scan_path,
                "derivation_modality": "static_source_snapshot",
            },
        }

        content_str = json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        content_bytes = content_str.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        manifest = ArtifactManifest(
            artifact_ref=artifact_ref,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            content=content_str,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            redaction_applied=acc.redaction_applied,
            truncated=is_truncated,
            metadata={
                "sink_id": sink_id,
                "sink_kind": acc.sink_kind.value,
                "file_path": acc.file_path,
                "primary_rule_id": primary_rule_id,
            },
        )
        artifact_manifests.append(manifest)

        evd_record = EvidenceArtifactRecord(
            evidence_id=evidence_id,
            assessment_id=request.target_model.assessment_id,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            artifact_ref=artifact_ref,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            captured_at=capture_time,
            source_tool_id="opengrep",
            execution_ref=(Id(str(provenance_execution_ref)) if provenance_execution_ref else None),
            provenance={
                "tool": provenance_tool,
                "version": provenance_version,
                "ruleset": provenance_ruleset,
                "ruleset_ref": provenance_ruleset_ref,
                "ruleset_path": provenance_ruleset_path,
                "ruleset_sha256": provenance_ruleset_sha256,
                "source_revision": provenance_source_revision,
                "source_repository_ref": provenance_source_repository_ref,
                "source_repo_path": provenance_source_repo_path,
                "source_tree_sha256": provenance_source_tree_sha256,
                "worktree_dirty": provenance_worktree_dirty,
                "execution_ref": provenance_execution_ref,
                "scan_path": scan_path,
                "derivation_modality": "static_source_snapshot",
            },
            redaction_applied=acc.redaction_applied,
            truncated=is_truncated,
            metadata={
                "sink_id": sink_id,
                "sink_kind": acc.sink_kind.value,
                "file_path": acc.file_path,
                "start_line": acc.start_line,
                "end_line": acc.end_line,
                "primary_rule_id": primary_rule_id,
                "rule_ids": sorted(acc.rule_ids),
                "cwe_ids": sorted(str(c) for c in acc.cwe_ids),
                "severities": sorted(acc.severities),
                "has_static_taint_flow": acc.has_static_taint_flow,
            },
        )
        evidence_records.append(evd_record)

        sink_candidate = SinkCandidate(
            sink_id=sink_id,
            sink_kind=acc.sink_kind,
            file_path=acc.file_path,
            start_line=acc.start_line,
            end_line=acc.end_line,
            rule_id=primary_rule_id,
            snippet=selected_snippet,
            has_static_taint_flow=acc.has_static_taint_flow,
            dataflow_steps=acc.dataflow_steps,
            confidence=acc.confidence,
            evidence_refs=[EvidenceId(str(evidence_id))],
            observation_refs=[],
        )
        sink_candidates.append(sink_candidate)

        first_ts_snip = acc.taint_sources[0][0] if acc.taint_sources else None
        first_ts_file = acc.taint_sources[0][1] if acc.taint_sources else None
        first_ts_line = acc.taint_sources[0][2] if acc.taint_sources else None

        sink_metadata_map[sink_id] = SinkCorrelationMetadata(
            sink_id=sink_id,
            primary_rule_id=primary_rule_id,
            all_rule_ids=sorted(acc.rule_ids),
            cwe_ids=sorted(acc.cwe_ids),
            severities=sorted(acc.severities),
            messages=sorted(acc.messages),
            start_column=acc.start_column,
            end_column=acc.end_column,
            taint_source_snippet=first_ts_snip,
            taint_source_file=first_ts_file,
            taint_source_line=first_ts_line,
            all_taint_sources=all_sources,
            taint_origin="opengrep" if acc.has_static_taint_flow else None,
        )

    result = SinkExtractionResult(
        sink_candidates=sink_candidates,
        analysis_evidence_records=evidence_records,
        artifact_manifests=artifact_manifests,
        sink_metadata=sink_metadata_map,
        scanned_files=scanned_files,
        opengrep_version=(str(provenance_version) if provenance_version is not None else None),
        ruleset_sha256=(str(provenance_ruleset_sha256) if provenance_ruleset_sha256 else None),
        execution_ref=(str(provenance_execution_ref) if provenance_execution_ref else None),
        source_revision=(str(provenance_source_revision) if provenance_source_revision else None),
        source_repository_ref=(
            str(provenance_source_repository_ref) if provenance_source_repository_ref else None
        ),
        source_repo_path=(
            str(provenance_source_repo_path) if provenance_source_repo_path else None
        ),
        source_tree_sha256=(
            str(provenance_source_tree_sha256) if provenance_source_tree_sha256 else None
        ),
        worktree_dirty=(
            bool(provenance_worktree_dirty) if provenance_worktree_dirty is not None else None
        ),
        limitations=sorted(limitations),
        warnings=sorted(warnings),
    )

    if enable_ast_taint:
        result = enrich_sinks_with_ast_taint(request, result)
    return result


async def aextract_sink_candidates(
    request: Module2AnalysisRequest,
    *,
    analyzer: AsyncSourceAnalysisPort | None = None,
    opengrep_payload: Mapping[str, Any] | None = None,
    subpath: str = ".",
    sink_allocator: RecordIdAllocator | None = None,
    evidence_allocator: RecordIdAllocator | None = None,
    existing_evidence_ids: Set[str] | None = None,
    captured_at: datetime | None = None,
    enable_ast_taint: bool = True,
) -> SinkExtractionResult:
    """Asynchronously execute Opengrep analysis or process a pre-captured payload."""
    if opengrep_payload is not None:
        return extract_sink_candidates(
            request,
            opengrep_payload=opengrep_payload,
            sink_allocator=sink_allocator,
            evidence_allocator=evidence_allocator,
            existing_evidence_ids=existing_evidence_ids,
            captured_at=captured_at,
            enable_ast_taint=False,
        )

    authorized_path, refusal_reason = validate_source_analysis_scope(
        request, require_existing_filesystem=True
    )
    if refusal_reason is not None:
        return SinkExtractionResult(limitations=[refusal_reason])

    active_analyzer = analyzer or LocalOpengrepAdapter()

    approved_repo = None
    if request.target_model.scope_rules:
        approved_repo = request.target_model.scope_rules.source_repository_ref

    try:
        sig = inspect.signature(active_analyzer.analyze)
        if "source_repository_ref" in sig.parameters:
            payload = await active_analyzer.analyze(
                authorized_path or "", subpath=subpath, source_repository_ref=approved_repo
            )
        else:
            payload = await active_analyzer.analyze(authorized_path or "", subpath=subpath)
    except ToolError as exc:
        return SinkExtractionResult(
            limitations=[f"Opengrep static analysis failed ({exc.code}): {exc.message}"]
        )

    return extract_sink_candidates(
        request,
        opengrep_payload=payload,
        sink_allocator=sink_allocator,
        evidence_allocator=evidence_allocator,
        existing_evidence_ids=existing_evidence_ids,
        captured_at=captured_at,
        enable_ast_taint=enable_ast_taint,
    )


__all__ = ["aextract_sink_candidates", "extract_sink_candidates"]

