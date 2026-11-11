"""Stage 3 correlation: INPUT_SINK (VERIFIED) and ENDPOINT_SINK (PARTIAL)."""

from __future__ import annotations

import hashlib
from collections.abc import Sequence
from pathlib import Path
from typing import Any

from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    EvidenceId,
    InputCandidate,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkRelationship,
)
from websecuritycheck.domain.enums import InputLocation, TestingMode
from websecuritycheck.domain.models import (
    ArtifactManifest,
    EndpointDefinition,
    EvidenceArtifactRecord,
)

from ..ast_taint import (
    extract_handler_code_slice,
    trace_intraprocedural_sink_taint,
)
from ..inputs import normalize_parameter_name
from ..opengrep_adapter import validate_source_analysis_scope
from ..sinks import (
    SinkCorrelationMetadata,
    normalize_sink_file_path,
    sanitize_sink_text,
)
from .accessors import parse_taint_source_accessor
from .models import (
    CorrelationDiagnostic,
    CorrelationRecord,
    InjectionSinkScope,
    RouteBindingArtifactRef,
    RouteHandlerBinding,
)
from .policy import (
    SUBTYPE_TO_CATEGORY,
    AccessorResolution,
    CorrelationId,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    FlowTrust,
    RuleProvenanceStatus,
)
from .stage_grounding import (
    _check_revision_alignment,
    _compute_caps_and_independence,
    correlation_identity_key,
    evaluate_correlation_confidence,
)
from .verifiers import verify_route_binding_artifact


def _endpoint_handler_context(
    repo_root: Path | None,
    snk: SinkCandidate,
    matched_b: RouteHandlerBinding,
    meta: SinkCorrelationMetadata | None,
    grounded_inputs: list[InputCandidate],
) -> tuple[tuple[str, ...], str | None, bool, str | None]:
    """Compute candidate input names, handler code slice, and pre-sink sanitization status."""
    handler_candidates: list[str] = list(meta.candidate_input_names_in_handler) if meta else []
    sanitized = bool(meta and meta.ast_sanitized_or_parameterized)
    san_reason = meta.ast_sanitization_reason if meta else None
    code_slice: str | None = None

    if repo_root is not None:
        if not handler_candidates and not sanitized:
            ast_res = trace_intraprocedural_sink_taint(
                repo_root,
                file_path=snk.file_path,
                sink_line=snk.start_line,
                sink_kind=snk.sink_kind,
                handler_span=(matched_b.start_line, matched_b.end_line),
                route_path=matched_b.path,
            )
            handler_candidates = list(ast_res.candidate_input_names_in_handler)
            sanitized = ast_res.is_sanitized_or_parameterized
            san_reason = ast_res.sanitization_reason

        raw_slice = extract_handler_code_slice(
            repo_root,
            matched_b.file_path,
            matched_b.start_line,
            matched_b.end_line,
            sink_line=snk.start_line,
        )
        if raw_slice:
            code_slice, _ = sanitize_sink_text(raw_slice, matched_b.file_path, max_chars=2000)

    if handler_candidates:
        ep_input_names = {
            normalize_parameter_name(inp.parameter_name, inp.location): inp.parameter_name
            for inp in grounded_inputs
            if inp.endpoint_id == matched_b.endpoint_id
        }
        matched_names = [
            ep_input_names.get(name.casefold().strip(), name)
            for name in handler_candidates
            if not ep_input_names or name.casefold().strip() in ep_input_names
        ]
        filtered = tuple(sorted(set(matched_names)))
    else:
        filtered = ()

    return filtered, code_slice, sanitized, san_reason


def _stage3_correlate_sinks(
    request: Module2AnalysisRequest,
    *,
    allowed_sinks: list[
        tuple[SinkCandidate, ArtifactManifest, EvidenceArtifactRecord, InjectionSinkScope]
    ],
    sink_metadata_map: dict[Any, SinkCorrelationMetadata],
    grounded_inputs: list[InputCandidate],
    route_binding_artifacts: Sequence[RouteBindingArtifactRef],
    policy: CorrelationTrustPolicy,
    all_request_evd: dict[str, EvidenceArtifactRecord],
    endpoint_map: dict[str, EndpointDefinition],
    diagnostics: list[CorrelationDiagnostic],
    limitations: list[str],
) -> list[CorrelationRecord]:
    verified_bindings: list[RouteHandlerBinding] = []
    if (
        request.target_model.scope_rules
        and request.target_model.scope_rules.testing_mode == TestingMode.BLACKBOX
    ):
        limitations.append("BLACKBOX_NO_SOURCE_CORRELATION")
    else:
        for r_art in route_binding_artifacts:
            binding, reason = verify_route_binding_artifact(r_art, request, trust_policy=policy)
            if binding:
                verified_bindings.append(binding)
            else:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=r_art.evidence_ref,
                        stage="route_binding",
                        outcome="EXCLUDED",
                        code="ROUTE_BINDING_REJECTED",
                        reason=reason,
                    )
                )

    auth_repo, _refusal = validate_source_analysis_scope(request, require_existing_filesystem=True)
    repo_root = Path(auth_repo) if auth_repo else None

    bindings_by_file: dict[str, list[RouteHandlerBinding]] = {}
    for b in verified_bindings:
        bindings_by_file.setdefault(b.file_path, []).append(b)

    inputs_by_key: dict[tuple[str, InputLocation, str], list[InputCandidate]] = {}
    for inp in grounded_inputs:
        norm_name = normalize_parameter_name(inp.parameter_name, inp.location)
        inputs_by_key.setdefault((inp.endpoint_id, inp.location, norm_name), []).append(inp)

    records: list[CorrelationRecord] = []

    for snk, man, evd, scope_res in allowed_sinks:
        meta = sink_metadata_map.get(snk.sink_id)
        taint_sources = list(meta.all_taint_sources) if meta and meta.all_taint_sources else []
        if (
            not taint_sources
            and meta
            and meta.taint_source_snippet
            and meta.taint_source_file
            and meta.taint_source_line
        ):
            taint_sources = [
                f"{meta.taint_source_file}:{meta.taint_source_line}: {meta.taint_source_snippet}"
            ]

        sink_records: list[CorrelationRecord] = []
        correlated_any = False

        for ts_entry in taint_sources:
            parts = ts_entry.split(":", 2)
            if len(parts) < 3:
                continue
            ts_file = normalize_sink_file_path(parts[0].strip())
            try:
                ts_line = int(parts[1].strip())
            except ValueError:
                continue
            ts_snippet = parts[2].strip()

            matching_bindings = [
                b
                for b in bindings_by_file.get(ts_file, [])
                if b.start_line <= ts_line <= b.end_line
            ]
            if not matching_bindings:
                continue
            if len(matching_bindings) > 1:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="AMBIGUOUS_ROUTE_BINDING",
                        reason=f"Taint source {ts_file}:{ts_line} intersects multiple bindings",
                    )
                )
                continue

            matched_b = matching_bindings[0]
            if not _check_revision_alignment(scope_res, matched_b, require_non_empty=True):
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="REVISION_UNLINKED",
                        reason=(
                            f"Revision mismatch between sink ({scope_res.source_revision}) "
                            f"and binding ({matched_b.source_revision})"
                        ),
                    )
                )
                continue

            accessor = parse_taint_source_accessor(ts_snippet)
            resolved_ts_entries: list[tuple[int, Any]] = []
            if (
                accessor.resolution == AccessorResolution.DYNAMIC_KEY
                and repo_root is not None
                and scope_res.flow_trust == FlowTrust.TRUSTED_TAINT
            ):
                ast_refined = trace_intraprocedural_sink_taint(
                    repo_root,
                    file_path=snk.file_path,
                    sink_line=snk.start_line,
                    sink_kind=snk.sink_kind,
                    handler_span=(matched_b.start_line, matched_b.end_line),
                    route_path=matched_b.path,
                )
                if ast_refined.has_taint_flow and ast_refined.resolved_sources:
                    for src_item in ast_refined.resolved_sources:
                        resolved_ts_entries.append(
                            (
                                src_item.source_line,
                                parse_taint_source_accessor(src_item.accessor_snippet),
                            )
                        )

            if not resolved_ts_entries:
                resolved_ts_entries.append((ts_line, accessor))

            rel_evd, ind_assess, caps = _compute_caps_and_independence(
                evd, man, matched_b, all_request_evd, endpoint_map
            )
            assert scope_res.subtype is not None

            for eff_line, eff_accessor in resolved_ts_entries:
                if (
                    scope_res.rule_provenance == RuleProvenanceStatus.VERIFIED
                    and scope_res.flow_trust == FlowTrust.TRUSTED_TAINT
                    and eff_accessor.resolution == AccessorResolution.RESOLVED
                    and eff_accessor.parameter_name
                ):
                    candidate_inputs: list[InputCandidate] = []
                    for loc in eff_accessor.locations:
                        norm_p = normalize_parameter_name(eff_accessor.parameter_name, loc)
                        candidate_inputs.extend(
                            inputs_by_key.get((matched_b.endpoint_id, loc, norm_p), [])
                        )

                    if len(candidate_inputs) == 1:
                        matched_inp = candidate_inputs[0]
                        conf, applied_caps = evaluate_correlation_confidence(
                            CorrelationKind.INPUT_SINK,
                            CorrelationStatus.VERIFIED,
                            base_confidence=ConfidenceLevel.HIGH,
                            caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
                        )
                        key = correlation_identity_key(
                            CorrelationKind.INPUT_SINK,
                            matched_b.endpoint_id,
                            matched_inp.location,
                            normalize_parameter_name(
                                matched_inp.parameter_name, matched_inp.location
                            ),
                            snk.file_path,
                            snk.start_line,
                            snk.sink_kind,
                            ts_file,
                            eff_line,
                            None,
                            None,
                        )
                        cor_id = CorrelationId(
                            f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                        )
                        sink_records.append(
                            CorrelationRecord(
                                correlation_id=cor_id,
                                kind=CorrelationKind.INPUT_SINK,
                                status=CorrelationStatus.VERIFIED,
                                confidence=conf,
                                injection_subtype=scope_res.subtype,
                                vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                                endpoint_id=matched_b.endpoint_id,
                                input_ref=matched_inp.input_id,
                                sink_ref=snk.sink_id,
                                sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
                                existence_evidence_refs=tuple(
                                    sorted(set(snk.evidence_refs) | set(matched_inp.evidence_refs))
                                ),
                                existence_observation_refs=tuple(
                                    sorted(set(matched_inp.observation_refs))
                                ),
                                relation_evidence_refs=tuple(
                                    sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                                ),
                                relation_observation_refs=(),
                                independent_relation_source_count=ind_assess.distinct_execution_count,
                                independence=ind_assess,
                                confidence_caps_applied=applied_caps,
                                rationale=(
                                    "Verified static taint flow from "
                                    f"{matched_b.endpoint_id} parameter "
                                    f"'{matched_inp.parameter_name}' to sink {snk.sink_id} "
                                    f"({snk.file_path}:{snk.start_line})"
                                ),
                            )
                        )
                        correlated_any = True
                        continue

                conf, applied_caps = evaluate_correlation_confidence(
                    CorrelationKind.ENDPOINT_SINK,
                    CorrelationStatus.PARTIAL,
                    base_confidence=(
                        ConfidenceLevel.MEDIUM
                        if scope_res.flow_trust == FlowTrust.TRUSTED_TAINT
                        else ConfidenceLevel.LOW
                    ),
                    caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
                )
                key = correlation_identity_key(
                    CorrelationKind.ENDPOINT_SINK,
                    matched_b.endpoint_id,
                    None,
                    None,
                    snk.file_path,
                    snk.start_line,
                    snk.sink_kind,
                    ts_file,
                    eff_line,
                    None,
                    None,
                )
                cor_id = CorrelationId(
                    f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                )
                missing_links = (
                    (f"ACCESSOR_{eff_accessor.resolution.value}",)
                    if eff_accessor.resolution != AccessorResolution.RESOLVED
                    else ("AMBIGUOUS_INPUT_MAPPING",)
                )
                cand_names, code_slice, _, _ = _endpoint_handler_context(
                    repo_root, snk, matched_b, meta, grounded_inputs
                )
                sink_records.append(
                    CorrelationRecord(
                        correlation_id=cor_id,
                        kind=CorrelationKind.ENDPOINT_SINK,
                        status=CorrelationStatus.PARTIAL,
                        confidence=conf,
                        injection_subtype=scope_res.subtype,
                        vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                        endpoint_id=matched_b.endpoint_id,
                        sink_ref=snk.sink_id,
                        sink_relationship=(
                            SinkRelationship.STATIC_TAINT_FLOW_FOUND
                            if snk.has_static_taint_flow
                            else SinkRelationship.UNVERIFIED_STATIC_SINK
                        ),
                        existence_evidence_refs=tuple(sorted(set(snk.evidence_refs))),
                        relation_evidence_refs=tuple(
                            sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                        ),
                        independent_relation_source_count=ind_assess.distinct_execution_count,
                        independence=ind_assess,
                        missing_links=missing_links,
                        confidence_caps_applied=applied_caps,
                        candidate_input_names_in_handler=cand_names,
                        handler_code_slice=code_slice,
                        rationale=(
                            f"Partial endpoint correlation between {matched_b.endpoint_id} "
                            f"and sink {snk.sink_id}; input parameter unresolved "
                            f"({eff_accessor.resolution.value})"
                        ),
                    )
                )
                correlated_any = True

        if any(r.kind == CorrelationKind.INPUT_SINK for r in sink_records):
            sink_records = [r for r in sink_records if r.kind == CorrelationKind.INPUT_SINK]

        if not correlated_any:
            snk_file = normalize_sink_file_path(snk.file_path)
            matching_bindings = [
                b
                for b in bindings_by_file.get(snk_file, [])
                if b.start_line <= snk.start_line <= b.end_line
            ]
            if len(matching_bindings) > 1:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="AMBIGUOUS_ROUTE_BINDING",
                        reason=(
                            f"Sink {snk.file_path}:{snk.start_line} intersects multiple bindings"
                        ),
                    )
                )
            elif len(matching_bindings) == 1:
                matched_b = matching_bindings[0]
                if not _check_revision_alignment(scope_res, matched_b, require_non_empty=False):
                    diagnostics.append(
                        CorrelationDiagnostic(
                            subject_ref=snk.sink_id,
                            stage="input_sink",
                            outcome="UNRESOLVED",
                            code="REVISION_UNLINKED",
                            reason=(
                                f"Revision/tree mismatch between sink "
                                f"({scope_res.source_revision}, {scope_res.source_tree_sha256}) "
                                f"and binding ({matched_b.source_revision}, "
                                f"{matched_b.source_tree_sha256})"
                            ),
                        )
                    )
                elif scope_res.rule_provenance == RuleProvenanceStatus.VERIFIED:
                    cand_names, code_slice, ast_sanitized, san_reason = _endpoint_handler_context(
                        repo_root, snk, matched_b, meta, grounded_inputs
                    )
                    if ast_sanitized and not snk.has_static_taint_flow:
                        diagnostics.append(
                            CorrelationDiagnostic(
                                subject_ref=snk.sink_id,
                                stage="input_sink",
                                outcome="EXCLUDED",
                                code="AST_PARAMETERIZED_OR_SANITIZED",
                                reason=san_reason or "Parameterized or sanitized before sink",
                            )
                        )
                        correlated_any = True
                    else:
                        rel_evd, ind_assess, caps = _compute_caps_and_independence(
                            evd, man, matched_b, all_request_evd, endpoint_map
                        )
                        conf, applied_caps = evaluate_correlation_confidence(
                            CorrelationKind.ENDPOINT_SINK,
                            CorrelationStatus.PARTIAL,
                            base_confidence=ConfidenceLevel.LOW,
                            caps=[(snk.confidence, "SINK_CONFIDENCE_CAP"), *caps],
                        )
                        key = correlation_identity_key(
                            CorrelationKind.ENDPOINT_SINK,
                            matched_b.endpoint_id,
                            None,
                            None,
                            snk.file_path,
                            snk.start_line,
                            snk.sink_kind,
                            None,
                            None,
                            None,
                            None,
                        )
                        cor_id = CorrelationId(
                            f"COR-{hashlib.sha256(key.encode('utf-8')).hexdigest()[:16]}"
                        )
                        assert scope_res.subtype is not None
                        sink_records.append(
                            CorrelationRecord(
                                correlation_id=cor_id,
                                kind=CorrelationKind.ENDPOINT_SINK,
                                status=CorrelationStatus.PARTIAL,
                                confidence=conf,
                                injection_subtype=scope_res.subtype,
                                vulnerability_category=SUBTYPE_TO_CATEGORY.get(scope_res.subtype),
                                endpoint_id=matched_b.endpoint_id,
                                sink_ref=snk.sink_id,
                                sink_relationship=SinkRelationship.UNVERIFIED_STATIC_SINK,
                                existence_evidence_refs=tuple(sorted(set(snk.evidence_refs))),
                                relation_evidence_refs=tuple(
                                    sorted({EvidenceId(str(e.evidence_id)) for e in rel_evd})
                                ),
                                independent_relation_source_count=ind_assess.distinct_execution_count,
                                independence=ind_assess,
                                missing_links=("MISSING_DATAFLOW_TRACE",),
                                confidence_caps_applied=applied_caps,
                                candidate_input_names_in_handler=cand_names,
                                handler_code_slice=code_slice,
                                rationale=(
                                    f"Verified sink {snk.sink_id} falls within route "
                                    f"{matched_b.endpoint_id} handler ({matched_b.file_path}:"
                                    f"{matched_b.start_line}-{matched_b.end_line}) "
                                    "but lacks dataflow trace"
                                ),
                            )
                        )
                        correlated_any = True

            if not correlated_any:
                diagnostics.append(
                    CorrelationDiagnostic(
                        subject_ref=snk.sink_id,
                        stage="input_sink",
                        outcome="UNRESOLVED",
                        code="NO_MATCHING_ROUTE_BINDING",
                        reason=f"Sink {snk.sink_id} has no matching verified route-handler binding",
                    )
                )

        records.extend(sink_records)

    return records


__all__ = ["_endpoint_handler_context", "_stage3_correlate_sinks"]

