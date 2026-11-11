"""Trusted AST taint verification, route binding verification, and independence checks."""

from __future__ import annotations

import hashlib
import json
from collections.abc import Mapping, Sequence
from typing import Any

from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.domain.enums import ArtifactType, TestingMode
from websecuritycheck.domain.models import EvidenceArtifactRecord, ObservationRecord

from ..sinks import is_safe_sink_path, normalize_sink_file_path
from .models import (
    IndependenceAssessment,
    RouteBindingArtifactRef,
    RouteHandlerBinding,
)
from .policy import CorrelationTrustPolicy, IndependenceStatus


def verify_ast_taint_provenance(
    ast_provenance: Any,
    trust_policy: CorrelationTrustPolicy,
) -> tuple[bool, str]:
    """Verify deterministic AST taint provenance against policy.trusted_taint_producers."""
    if not isinstance(ast_provenance, Mapping):
        return False, "MISSING_AST_TAINT_PROVENANCE"

    producer_id = str(ast_provenance.get("producer_id") or "").strip()
    method = str(ast_provenance.get("method") or "").strip()
    method_digest = str(ast_provenance.get("method_digest") or "").strip().lower()

    if not producer_id:
        return False, "MISSING_AST_TAINT_PRODUCER_ID"

    matched_producer = next(
        (tp for tp in trust_policy.trusted_taint_producers if tp.producer_id == producer_id),
        None,
    )
    if matched_producer is None:
        return False, f"UNTRUSTED_TAINT_PRODUCER:{producer_id}"
    if method not in matched_producer.approved_methods:
        return False, f"UNAPPROVED_TAINT_METHOD:{method}"
    if method_digest not in matched_producer.approved_method_digests:
        return False, f"UNAPPROVED_TAINT_METHOD_DIGEST:{method_digest}"
    return True, "VERIFIED"


def verify_route_binding_artifact(
    artifact_ref: RouteBindingArtifactRef,
    request: Module2AnalysisRequest,
    *,
    trust_policy: CorrelationTrustPolicy,
) -> tuple[RouteHandlerBinding | None, str]:
    """Verify and derive a RouteHandlerBinding against strict trust policy conditions."""
    manifest = artifact_ref.manifest
    evd_id = artifact_ref.evidence_ref

    rules = request.target_model.scope_rules
    if rules is None or rules.testing_mode == TestingMode.BLACKBOX or not request.source_repo_path:
        return None, "BLACKBOX_OR_MISSING_SOURCE_REPO"

    matched_evd = None
    for evd in request.evidence_records:
        if evd.evidence_id == evd_id:
            matched_evd = evd
            break
    if matched_evd is None or matched_evd.artifact_type != ArtifactType.SOURCE_ARTIFACT:
        return None, f"EVIDENCE_RECORD_NOT_FOUND_OR_NOT_SOURCE_ARTIFACT:{evd_id}"

    content = manifest.content or ""
    content_bytes = content.encode("utf-8")
    actual_hash = hashlib.sha256(content_bytes).hexdigest()
    if matched_evd.sha256_hash.lower() != actual_hash.lower():
        return None, f"HASH_MISMATCH:record={matched_evd.sha256_hash},actual={actual_hash}"
    if manifest.sha256_hash and manifest.sha256_hash.lower() != actual_hash.lower():
        return None, f"MANIFEST_HASH_MISMATCH:manifest={manifest.sha256_hash},actual={actual_hash}"

    try:
        payload = json.loads(content)
    except Exception:
        return None, "MALFORMED_JSON_CONTENT"

    if payload.get("schema") != "websecuritycheck.route_binding_artifact.v1":
        return None, f"UNSUPPORTED_SCHEMA:{payload.get('schema')}"

    producer_id = str(matched_evd.source_tool_id or "").strip()
    trusted_producer = None
    for tp in trust_policy.trusted_route_producers:
        if tp.producer_id == producer_id:
            trusted_producer = tp
            break
    if trusted_producer is None:
        return None, f"UNTRUSTED_PRODUCER:{producer_id}"

    prov = matched_evd.provenance or {}
    method = str(prov.get("extraction_method") or "").strip()
    method_digest = str(prov.get("extraction_method_digest") or "").strip().lower()

    if method not in trusted_producer.approved_methods:
        return None, f"UNAPPROVED_EXTRACTION_METHOD:{method}"
    if method_digest not in trusted_producer.approved_method_digests:
        return None, f"UNAPPROVED_METHOD_DIGEST:{method_digest}"

    exec_ref = str(matched_evd.execution_ref or "").strip()
    if not exec_ref:
        return None, "MISSING_EXECUTION_REF"

    src_repo_ref = str(prov.get("source_repository_ref") or "").strip()
    if not src_repo_ref or normalize_sink_file_path(src_repo_ref) != normalize_sink_file_path(
        rules.source_repository_ref or ""
    ):
        return None, f"SOURCE_REPO_MISMATCH:{src_repo_ref}"

    src_rev = str(prov.get("source_revision") or "").strip()
    if not src_rev:
        return None, "MISSING_SOURCE_REVISION"

    ep_id = payload.get("endpoint_id")
    method_name = str(payload.get("method") or "").upper().strip()
    path_text = str(payload.get("path") or "").strip()
    file_path = str(payload.get("file_path") or "").strip()
    start_line = payload.get("start_line")
    end_line = payload.get("end_line")

    matched_ep = None
    for ep in request.target_model.endpoints:
        if ep.endpoint_id == ep_id:
            matched_ep = ep
            break

    if matched_ep is None:
        return None, f"UNKNOWN_ENDPOINT_ID:{ep_id}"
    if matched_ep.method.upper().strip() != method_name or matched_ep.path.strip() != path_text:
        return None, f"ENDPOINT_SIGNATURE_MISMATCH:{ep_id}"

    if not is_safe_sink_path(file_path):
        return None, f"UNSAFE_FILE_PATH:{file_path}"
    if (
        not isinstance(start_line, int)
        or not isinstance(end_line, int)
        or start_line < 1
        or end_line < start_line
    ):
        return None, f"INVALID_LINE_SPAN:{start_line}-{end_line}"

    src_tree_hash = str(prov.get("source_tree_sha256") or "").strip() or None
    binding = RouteHandlerBinding(
        endpoint_id=ep_id,
        method=method_name,
        path=path_text,
        file_path=normalize_sink_file_path(file_path),
        start_line=start_line,
        end_line=end_line,
        evidence_ref=evd_id,
        execution_ref=exec_ref,
        source_revision=src_rev,
        source_tree_sha256=src_tree_hash,
        source_repository_ref=src_repo_ref or None,
    )
    return binding, "VERIFIED"


def assess_independence(
    evidence: Sequence[EvidenceArtifactRecord],
    observations: Sequence[ObservationRecord],
) -> IndependenceAssessment:
    """Evaluate whether supporting relation evidence represents truly independent executions."""
    reasons: list[str] = []

    for evd in evidence:
        if not evd.execution_ref or not str(evd.execution_ref).strip():
            reasons.append(f"MISSING_EXECUTION_REF:{evd.evidence_id}")
    for obs in observations:
        if not obs.execution_ref or not str(obs.execution_ref).strip():
            reasons.append(f"MISSING_EXECUTION_REF:{obs.observation_id}")

    if reasons:
        return IndependenceAssessment(
            status=IndependenceStatus.UNKNOWN,
            distinct_execution_count=0,
            reasons=tuple(sorted(reasons)),
        )

    seen_hashes: dict[str, str] = {}
    seen_artifacts: dict[str, str] = {}
    for evd in evidence:
        digest = evd.sha256_hash.lower().strip()
        if digest in seen_hashes:
            reasons.append(f"SHARED_ARTIFACT_DIGEST:{evd.evidence_id}_and_{seen_hashes[digest]}")
        else:
            seen_hashes[digest] = str(evd.evidence_id)

        aref = evd.artifact_ref.strip()
        if aref in seen_artifacts:
            reasons.append(f"SHARED_ARTIFACT_REF:{evd.evidence_id}_and_{seen_artifacts[aref]}")
        else:
            seen_artifacts[aref] = str(evd.evidence_id)

    evd_id_set = {str(e.evidence_id) for e in evidence}
    for obs in observations:
        for ref in obs.evidence_refs:
            if str(ref) in evd_id_set:
                reasons.append(f"SHARED_BACKING_EVIDENCE:{obs.observation_id}_backs_{ref}")

    exec_refs = set()
    for evd in evidence:
        exec_refs.add(str(evd.execution_ref).strip())
    for obs in observations:
        exec_refs.add(str(obs.execution_ref).strip())

    if len(exec_refs) <= 1:
        single_ref = next(iter(exec_refs)) if exec_refs else "none"
        reasons.append(f"SINGLE_EXECUTION_REF:{single_ref}")

    if (
        evidence
        and all(evd.artifact_type == ArtifactType.SOURCE_ARTIFACT for evd in evidence)
        and not observations
    ):
        snapshots = set()
        for evd in evidence:
            prov = evd.provenance or {}
            tree_hash = prov.get("source_tree_sha256")
            repo_ref = prov.get("source_repository_ref")
            rev = prov.get("source_revision")
            snapshots.add((repo_ref, rev, tree_hash))

        if len(snapshots) == 1:
            snap = next(iter(snapshots))
            rev_label = snap[1] or snap[2] or "unknown"
            reasons.append(f"SHARED_SOURCE_SNAPSHOT:{rev_label}")

    if reasons:
        return IndependenceAssessment(
            status=IndependenceStatus.SHARED,
            distinct_execution_count=len(exec_refs),
            reasons=tuple(sorted(reasons)),
        )

    return IndependenceAssessment(
        status=IndependenceStatus.INDEPENDENT,
        distinct_execution_count=len(exec_refs),
        reasons=(),
    )


__all__ = [
    "assess_independence",
    "verify_ast_taint_provenance",
    "verify_route_binding_artifact",
]

