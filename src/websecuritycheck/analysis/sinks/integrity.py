"""Sink deduplication accumulator, artifact integrity verification, and AST taint enrichment."""

from __future__ import annotations

import hashlib
import json
import re
from pathlib import Path
from typing import Any

from websecuritycheck.domain import ArtifactManifest, ArtifactType, EvidenceArtifactRecord
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CweId,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkId,
    SinkKind,
)

from ..ast_taint import (
    AST_TAINT_PRODUCER_ID,
    METHOD_AST_TAINT_V1,
    METHOD_DIGEST_AST_TAINT_V1,
    AstTaintTraceResult,
    trace_intraprocedural_sink_taint,
)
from ..opengrep_adapter import validate_source_analysis_scope
from .models import SinkCorrelationMetadata, SinkExtractionResult, _compute_confidence
from .trace_parser import _WHOLE_BODY_READER_RE, sanitize_sink_text


class _SinkAccumulator:
    """Internal grouping accumulator for deduplicating identical sinks."""

    def __init__(
        self,
        *,
        file_path: str,
        start_line: int,
        end_line: int | None,
        start_column: int | None,
        end_column: int | None,
        sink_kind: SinkKind,
        rule_id: str,
        confidence: ConfidenceLevel,
        has_static_taint_flow: bool,
        dataflow_steps: list[str],
        snippet: str | None,
        cwe_ids: list[CweId],
        severity: str | None,
        message: str | None,
        taint_source_snippet: str | None,
        taint_source_file: str | None,
        taint_source_line: int | None,
        redaction_applied: bool,
    ) -> None:
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.start_column = start_column
        self.end_column = end_column
        self.sink_kind = sink_kind

        self.rule_ids: set[str] = {rule_id}
        self.taint_rule_ids: set[str] = {rule_id} if has_static_taint_flow else set()
        self.confidence = confidence
        self.has_static_taint_flow = has_static_taint_flow
        self.dataflow_steps = dataflow_steps
        self.snippets: list[str] = [snippet] if snippet else []
        self.cwe_ids: set[CweId] = set(cwe_ids)
        self.severities: set[str] = {severity} if severity else set()
        self.messages: set[str] = {message} if message else set()
        self.taint_sources: list[tuple[str | None, str | None, int | None]] = (
            [(taint_source_snippet, taint_source_file, taint_source_line)]
            if taint_source_snippet
            else []
        )
        self.redaction_applied = redaction_applied

    def merge(
        self,
        *,
        rule_id: str,
        confidence: ConfidenceLevel,
        has_static_taint_flow: bool,
        dataflow_steps: list[str],
        snippet: str | None,
        cwe_ids: list[CweId],
        severity: str | None,
        message: str | None,
        taint_source_snippet: str | None,
        taint_source_file: str | None,
        taint_source_line: int | None,
        redaction_applied: bool,
    ) -> None:
        self.rule_ids.add(rule_id)
        if has_static_taint_flow:
            self.taint_rule_ids.add(rule_id)
            self.has_static_taint_flow = True

        order = {
            ConfidenceLevel.LOW: 1,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.HIGH: 3,
        }
        if order[confidence] > order[self.confidence]:
            self.confidence = confidence

        if has_static_taint_flow and (
            not self.dataflow_steps
            or len(dataflow_steps) > len(self.dataflow_steps)
            or (
                len(dataflow_steps) == len(self.dataflow_steps)
                and tuple(dataflow_steps) < tuple(self.dataflow_steps)
            )
        ):
            self.dataflow_steps = dataflow_steps

        if snippet:
            self.snippets.append(snippet)
        self.cwe_ids.update(cwe_ids)
        if severity:
            self.severities.add(severity)
        if message:
            self.messages.add(message)
        if taint_source_snippet:
            self.taint_sources.append((taint_source_snippet, taint_source_file, taint_source_line))
        self.redaction_applied = self.redaction_applied or redaction_applied


def verify_sink_evidence_integrity(
    record: EvidenceArtifactRecord, manifest: ArtifactManifest
) -> bool:
    """Verify that an EvidenceArtifactRecord matches its ArtifactManifest content and hash."""
    if record.artifact_ref != manifest.artifact_ref:
        return False
    if (
        record.artifact_type != ArtifactType.SOURCE_ARTIFACT
        or manifest.artifact_type != ArtifactType.SOURCE_ARTIFACT
    ):
        return False
    if manifest.content is None:
        return False
    content_bytes = manifest.content.encode("utf-8")
    actual_digest = hashlib.sha256(content_bytes).hexdigest()
    if record.sha256_hash.lower() != actual_digest:
        return False
    if manifest.sha256_hash and manifest.sha256_hash.lower() != actual_digest:
        return False
    if record.size_bytes != len(content_bytes) or (
        manifest.size_bytes is not None and manifest.size_bytes != len(content_bytes)
    ):
        return False
    try:
        parsed = json.loads(manifest.content)
        if (
            not isinstance(parsed, dict)
            or parsed.get("schema") != "websecuritycheck.opengrep_sink_artifact.v1"
        ):
            return False
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return True


def _repackage_sink_evidence(
    *,
    sink: SinkCandidate,
    meta: SinkCorrelationMetadata,
    manifest: ArtifactManifest,
    record: EvidenceArtifactRecord,
    ast_provenance: dict[str, Any] | None = None,
) -> tuple[ArtifactManifest, EvidenceArtifactRecord]:
    """Deterministically re-serialize manifest and recompute SHA-256 after AST enrichment."""
    try:
        payload = json.loads(manifest.content or "{}")
    except (json.JSONDecodeError, UnicodeDecodeError):
        payload = {}
    if not isinstance(payload, dict):
        payload = {}

    payload["snippet"] = sink.snippet
    payload["has_static_taint_flow"] = sink.has_static_taint_flow
    payload["dataflow_steps"] = list(sink.dataflow_steps)
    payload["all_taint_sources"] = list(meta.all_taint_sources)
    if meta.taint_origin:
        payload["taint_origin"] = meta.taint_origin
    if ast_provenance is not None:
        payload["ast_taint_provenance"] = ast_provenance

    content_str = json.dumps(
        payload,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
    )
    content_bytes = content_str.encode("utf-8")
    sha256_hash = hashlib.sha256(content_bytes).hexdigest()
    size_bytes = len(content_bytes)

    new_manifest = manifest.model_copy(
        update={
            "content": content_str,
            "sha256_hash": sha256_hash,
            "size_bytes": size_bytes,
        }
    )
    new_prov = dict(record.provenance or {})
    if meta.taint_origin:
        new_prov["taint_origin"] = meta.taint_origin
    if ast_provenance is not None:
        new_prov["ast_taint_provenance"] = ast_provenance

    new_meta = dict(record.metadata or {})
    new_meta["has_static_taint_flow"] = sink.has_static_taint_flow

    new_record = record.model_copy(
        update={
            "sha256_hash": sha256_hash,
            "size_bytes": size_bytes,
            "provenance": new_prov,
            "metadata": new_meta,
        }
    )
    return new_manifest, new_record


def _matching_endpoint_route_path(request: Module2AnalysisRequest) -> list[str]:
    """Return all unique endpoint paths from TargetModel for regex path-param matching."""
    return sorted({ep.path for ep in request.target_model.endpoints if ep.path})


def _infer_route_path_for_sink(
    repo_root: Path,
    sink: SinkCandidate,
    ast_res: AstTaintTraceResult,
    endpoint_paths: list[str],
) -> str | None:
    """Match an AST-inferred Cloudflare regex guard near handler_start to a known endpoint path."""
    if not endpoint_paths or not ast_res.handler_start_line:
        return None
    try:
        lines = (
            (repo_root / sink.file_path).read_text(encoding="utf-8", errors="replace").splitlines()
        )
    except OSError:
        return None
    lo = max(1, ast_res.handler_start_line - 5)
    hi = min(len(lines), ast_res.handler_start_line + 1)
    header_window = "\n".join(lines[lo - 1 : hi])
    m = re.search(r"/\^([^$]+)\$/", header_window)
    if not m:
        return None
    regex_tpl = re.sub(r"\([^)]+\)", "{}", m.group(1).replace(r"\/", "/")).strip("/")
    for ep_path in endpoint_paths:
        norm_ep = re.sub(r"\{[^}]+\}", "{}", ep_path.strip().strip("/"))
        if norm_ep == regex_tpl:
            return ep_path
    return None


def enrich_sinks_with_ast_taint(
    request: Module2AnalysisRequest,
    sink_result: SinkExtractionResult,
) -> SinkExtractionResult:
    """Enrich SinkExtractionResult with intra-procedural AST taint analysis on disk."""
    if not sink_result.sink_candidates:
        return sink_result

    authorized_path, refusal = validate_source_analysis_scope(
        request, require_existing_filesystem=True
    )
    if refusal is not None or not authorized_path:
        return sink_result

    repo_root = Path(authorized_path)
    evd_by_id = {str(r.evidence_id): r for r in sink_result.analysis_evidence_records}
    man_by_ref = {m.artifact_ref: m for m in sink_result.artifact_manifests}
    endpoint_paths = _matching_endpoint_route_path(request)

    new_sinks: list[SinkCandidate] = []
    new_meta_map: dict[SinkId, SinkCorrelationMetadata] = {}
    updated_evd_by_id = dict(evd_by_id)
    updated_man_by_ref = dict(man_by_ref)

    for snk in sink_result.sink_candidates:
        meta = sink_result.sink_metadata.get(snk.sink_id)
        if meta is None:
            new_sinks.append(snk)
            continue

        evd = updated_evd_by_id.get(str(snk.evidence_refs[0]))
        man = updated_man_by_ref.get(evd.artifact_ref) if evd else None

        ast_res = trace_intraprocedural_sink_taint(
            repo_root,
            file_path=snk.file_path,
            sink_line=snk.start_line,
            sink_kind=snk.sink_kind,
        )
        matched_route = _infer_route_path_for_sink(repo_root, snk, ast_res, endpoint_paths)
        if matched_route:
            ast_res = trace_intraprocedural_sink_taint(
                repo_root,
                file_path=snk.file_path,
                sink_line=snk.start_line,
                sink_kind=snk.sink_kind,
                route_path=matched_route,
            )

        updated_snk = snk
        updated_meta = meta.model_copy(
            update={
                "candidate_input_names_in_handler": list(ast_res.candidate_input_names_in_handler),
                "ast_sanitized_or_parameterized": ast_res.is_sanitized_or_parameterized,
                "ast_sanitization_reason": ast_res.sanitization_reason,
            }
        )
        ast_prov: dict[str, Any] | None = None
        modified_artifact = False

        if updated_snk.snippet is None and ast_res.sink_code_line:
            clean_snip, _redacted = sanitize_sink_text(
                ast_res.sink_code_line, snk.file_path, max_chars=500
            )
            if clean_snip:
                updated_snk = updated_snk.model_copy(update={"snippet": clean_snip})
                modified_artifact = True

        if not updated_snk.has_static_taint_flow:
            if (
                not ast_res.is_sanitized_or_parameterized
                and ast_res.has_taint_flow
                and ast_res.resolved_sources
            ):
                primary_src = ast_res.resolved_sources[0]
                formatted_sources = [
                    f"{src.source_file}:{src.source_line}: {src.accessor_snippet}"
                    for src in ast_res.resolved_sources
                ]
                upgraded_conf = _compute_confidence(
                    None,
                    meta.severities[0] if meta.severities else None,
                    has_taint_flow=True,
                )
                if (
                    meta.severities
                    and "ERROR" in meta.severities
                    and (
                        updated_snk.confidence != ConfidenceLevel.HIGH
                        or (
                            upgraded_conf == ConfidenceLevel.MEDIUM
                            and updated_snk.confidence == ConfidenceLevel.MEDIUM
                        )
                    )
                ):
                    upgraded_conf = ConfidenceLevel.HIGH

                updated_snk = updated_snk.model_copy(
                    update={
                        "has_static_taint_flow": True,
                        "dataflow_steps": list(ast_res.dataflow_steps),
                        "confidence": upgraded_conf,
                    }
                )
                updated_meta = updated_meta.model_copy(
                    update={
                        "taint_source_snippet": primary_src.accessor_snippet,
                        "taint_source_file": primary_src.source_file,
                        "taint_source_line": primary_src.source_line,
                        "all_taint_sources": formatted_sources,
                        "taint_origin": "ast_intraprocedural",
                    }
                )
                ast_prov = {
                    "producer_id": AST_TAINT_PRODUCER_ID,
                    "method": METHOD_AST_TAINT_V1,
                    "method_digest": METHOD_DIGEST_AST_TAINT_V1,
                }
                modified_artifact = True
        else:
            existing_src = meta.taint_source_snippet or ""
            is_coarse_existing = bool(_WHOLE_BODY_READER_RE.search(existing_src))
            if is_coarse_existing and ast_res.has_taint_flow and ast_res.resolved_sources:
                primary_src = ast_res.resolved_sources[0]
                formatted_sources = [
                    f"{src.source_file}:{src.source_line}: {src.accessor_snippet}"
                    for src in ast_res.resolved_sources
                ]
                updated_meta = updated_meta.model_copy(
                    update={
                        "taint_source_snippet": primary_src.accessor_snippet,
                        "taint_source_file": primary_src.source_file,
                        "taint_source_line": primary_src.source_line,
                        "all_taint_sources": formatted_sources,
                        "taint_origin": "opengrep_ast_refined",
                    }
                )
                ast_prov = {
                    "producer_id": AST_TAINT_PRODUCER_ID,
                    "method": METHOD_AST_TAINT_V1,
                    "method_digest": METHOD_DIGEST_AST_TAINT_V1,
                }
                modified_artifact = True
            else:
                updated_meta = updated_meta.model_copy(update={"taint_origin": "opengrep"})

        if modified_artifact and evd is not None and man is not None:
            new_man, new_evd = _repackage_sink_evidence(
                sink=updated_snk,
                meta=updated_meta,
                manifest=man,
                record=evd,
                ast_provenance=ast_prov,
            )
            updated_man_by_ref[new_man.artifact_ref] = new_man
            updated_evd_by_id[str(new_evd.evidence_id)] = new_evd

        new_sinks.append(updated_snk)
        new_meta_map[snk.sink_id] = updated_meta

    ordered_evd = [
        updated_evd_by_id[str(r.evidence_id)] for r in sink_result.analysis_evidence_records
    ]
    ordered_man = [updated_man_by_ref[m.artifact_ref] for m in sink_result.artifact_manifests]
    return sink_result.model_copy(
        update={
            "sink_candidates": new_sinks,
            "sink_metadata": new_meta_map,
            "analysis_evidence_records": ordered_evd,
            "artifact_manifests": ordered_man,
        }
    )


__all__ = [
    "_SinkAccumulator",
    "enrich_sinks_with_ast_taint",
    "verify_sink_evidence_integrity",
]
