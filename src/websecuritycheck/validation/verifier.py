"""Deterministic Module 3 SQLi proof verifier enforcing all 6 safety invariants."""

from __future__ import annotations

from mcp_servers.websec_tools.validation.sqlmap import redact_sensitive_text
from websecuritycheck.domain.models import _validate_opaque_artifact_ref

from .models import (
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpRequestCapabilityOutput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
)

_EXPECTED_METHODS = {
    SQLiTechnique.ERROR: "error_signature_match",
    SQLiTechnique.BOOLEAN: "boolean_differential_pairs",
    SQLiTechnique.UNION: "union_marker_reflection",
    SQLiTechnique.TIME: "timing_delay_contrast",
}


def _are_valid_opaque_refs(refs: list[str]) -> bool:
    if not refs:
        return False
    for ref in refs:
        if not isinstance(ref, str) or not ref.strip():
            return False
        try:
            _validate_opaque_artifact_ref(ref)
        except ValueError:
            return False
    return True


def _proof_passes_technique_rules(
    proof: SQLiProof,
    *,
    output: SqliDetectionCapabilityOutput,
    baseline: HttpRequestCapabilityOutput | None,
) -> bool:
    if proof.verification_method != _EXPECTED_METHODS[proof.technique]:
        return False

    if not (
        _are_valid_opaque_refs(proof.control_observation_refs)
        and _are_valid_opaque_refs(proof.test_observation_refs)
        and _are_valid_opaque_refs(proof.evidence_refs)
    ):
        return False

    if proof.technique == SQLiTechnique.ERROR:
        # Must carry DBMS fingerprint or be backed by non-empty evidence after anomaly check.
        return bool(output.dbms_identified and output.dbms_identified.strip())

    stability_ok = output.target_stable is True and (
        baseline is None or (baseline.baseline_ready and baseline.target_stable is True)
    )
    if proof.technique == SQLiTechnique.BOOLEAN:
        return stability_ok and proof.repeatable is True

    if proof.technique == SQLiTechnique.TIME:
        # Invariant #5: TIME requires target_stable == True and repeatable == True.
        return stability_ok and proof.repeatable is True

    if proof.technique == SQLiTechnique.UNION:
        return not output.auth_failure_detected and not output.rate_limited

    return False


def verify_sqli_proofs(
    output: SqliDetectionCapabilityOutput,
    *,
    baseline: HttpRequestCapabilityOutput | None = None,
    candidate_proofs: list[SQLiProof] | None = None,
) -> SqliDetectionCapabilityOutput:
    """Apply all 6 verification invariants deterministically and compute final status.

    Only this deterministic verifier is permitted to emit ``verified=True`` proofs
    and ``DetectionStatus.CONFIRMED``.
    """

    source_proofs = list(candidate_proofs if candidate_proofs is not None else output.proofs)
    anomalies_present = bool(
        output.auth_failure_detected
        or output.rate_limited
        or output.waf_or_filter_detected
        or output.target_stable is False
        or (
            baseline is not None
            and (
                not baseline.baseline_ready
                or baseline.auth_failure_detected
                or baseline.rate_limited
                or baseline.waf_or_filter_detected
                or baseline.target_stable is False
            )
        )
    )

    verified_proofs: list[SQLiProof] = []
    confirmed_techniques: list[SQLiTechnique] = []

    for proof in source_proofs:
        redacted_summary = (
            redact_sensitive_text(proof.redacted_payload_summary)
            if proof.redacted_payload_summary is not None
            else None
        )
        can_verify = (
            output.execution_status == CapabilityExecutionStatus.COMPLETED
            and not anomalies_present
            and _proof_passes_technique_rules(proof, output=output, baseline=baseline)
        )
        updated = proof.model_copy(
            update={
                "redacted_payload_summary": redacted_summary,
                "verified": can_verify,
            }
        )
        verified_proofs.append(updated)
        if can_verify and updated.technique not in confirmed_techniques:
            confirmed_techniques.append(updated.technique)

    if output.execution_status != CapabilityExecutionStatus.COMPLETED or anomalies_present:
        detection_status = DetectionStatus.INCONCLUSIVE
    elif confirmed_techniques:
        detection_status = DetectionStatus.CONFIRMED
    elif output.heuristic_signal_detected:
        detection_status = DetectionStatus.HEURISTIC_ONLY
    elif output.tested_techniques:
        detection_status = DetectionStatus.NOT_DETECTED
    else:
        detection_status = DetectionStatus.INCONCLUSIVE

    return output.model_copy(
        update={
            "confirmed_techniques": confirmed_techniques,
            "detection_status": detection_status,
            "proofs": verified_proofs,
        }
    )
