"""Module 3 SQLI_DETECTION adapter wrapping constrained Layer 6 SQLMap."""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from mcp_servers.websec_tools.errors import ToolError
from mcp_servers.websec_tools.validation import sqlmap as l6_sqlmap
from websecuritycheck.domain.models import ExecutionPolicy
from websecuritycheck.policy.scope_guard import in_scope

from .models import (
    SUPPORTED_SQLI_LOCATIONS,
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpRequestCapabilityOutput,
    RiskProfile,
    SqliDetectionCapabilityInput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
)
from .resolvers import InMemoryRequestMaterializer, RequestMaterializerProtocol
from .verifier import verify_sqli_proofs

L6DetectSqliFn = Callable[..., Awaitable[dict[str, Any]]]

_TECHNIQUE_VERIFICATION_METHOD = {
    SQLiTechnique.ERROR: "error_signature_match",
    SQLiTechnique.BOOLEAN: "boolean_differential_pairs",
    SQLiTechnique.UNION: "union_marker_reflection",
    SQLiTechnique.TIME: "timing_delay_contrast",
}


class SqlmapDetectionAdapter:
    """SDK adapter executing ``SQLI_DETECTION`` via Layer 6 ``sqlmap.detect_sqli``."""

    def __init__(
        self,
        *,
        authorized_scope: Sequence[str] | None = None,
        policy: ExecutionPolicy | None = None,
        materializer: RequestMaterializerProtocol | None = None,
        detect_fn: L6DetectSqliFn | None = None,
    ) -> None:
        self._scope = list(authorized_scope) if authorized_scope is not None else None
        self._policy = policy
        self._materializer = materializer or InMemoryRequestMaterializer()
        self._detect_fn = detect_fn or l6_sqlmap.detect_sqli

    @property
    def materializer(self) -> RequestMaterializerProtocol:
        return self._materializer

    def _check_policy_and_scope(self, request: SqliDetectionCapabilityInput) -> str | None:
        if self._scope is not None:
            decision = in_scope(request.target_url, self._scope)
            if not decision.allowed:
                return "E_SCOPE"

        if self._policy is not None:
            if request.method not in {m.upper() for m in self._policy.http_policy.allowed_methods}:
                return "E_INVALID_ARGUMENT"
            if (
                self._policy.allowed_tool_ids
                and "sqlmap" not in self._policy.allowed_tool_ids
                and "detect_sqli" not in self._policy.allowed_tool_ids
            ):
                return "E_SCOPE"
            if (
                "sqlmap" in self._policy.blocked_tool_ids
                or "detect_sqli" in self._policy.blocked_tool_ids
            ):
                return "E_SCOPE"

        if request.risk_profile != RiskProfile.LOW:
            return "E_INVALID_ARGUMENT"

        if request.parameter_location not in SUPPORTED_SQLI_LOCATIONS:
            return "E_UNSUPPORTED_INPUT"

        return None

    async def execute(
        self,
        request: SqliDetectionCapabilityInput,
        *,
        baseline: HttpRequestCapabilityOutput | None = None,
    ) -> SqliDetectionCapabilityOutput:
        """Execute bounded SQLMap detection and verify proofs deterministically."""

        policy_error = self._check_policy_and_scope(request)
        if policy_error is not None:
            return SqliDetectionCapabilityOutput(
                execution_status=CapabilityExecutionStatus.FAILED,
                detection_status=DetectionStatus.INCONCLUSIVE,
                error_code=policy_error,
            )

        materialized = self._materializer.resolve_request(
            request_artifact_ref=request.request_artifact_ref,
            auth_ref=request.auth_ref,
        )

        effective_timeout = float(request.timeout_seconds)
        if self._policy is not None:
            effective_timeout = min(effective_timeout, float(self._policy.max_execution_seconds))

        try:
            envelope_res = await self._detect_fn(
                request.target_url,
                request.parameter_name,
                parameter_location=request.parameter_location.value,
                method=request.method,
                techniques=[tech.value for tech in request.techniques],
                dbms_hint=request.dbms_hint,
                timeout_seconds=effective_timeout,
                risk_profile=request.risk_profile.value,
                headers=materialized.headers or None,
                cookies=materialized.cookies or None,
                body=materialized.body,
                raw_request=materialized.raw_request,
            )
        except ToolError as exc:
            exec_status = (
                CapabilityExecutionStatus.TIMEOUT
                if exc.code == "E_TIMEOUT"
                else CapabilityExecutionStatus.FAILED
            )
            return SqliDetectionCapabilityOutput(
                execution_status=exec_status,
                detection_status=DetectionStatus.INCONCLUSIVE,
                error_code=exc.code,
            )

        data = envelope_res.get("data") or {}
        artifact_refs: list[str] = []
        for manifest in data.get("artifact_manifests") or []:
            ref = self._materializer.record_artifact(manifest)
            if ref not in artifact_refs:
                artifact_refs.append(ref)

        target_stable = bool(data.get("target_stable", True))
        auth_failed = bool(data.get("auth_failure_detected", False))
        rate_limited = bool(data.get("rate_limited", False))
        waf_detected = bool(data.get("waf_or_filter_detected", False))
        anomalies = not target_stable or auth_failed or rate_limited or waf_detected

        candidate_proofs: list[SQLiProof] = []
        for raw_finding in data.get("findings") or []:
            technique = SQLiTechnique(raw_finding["technique"])
            evidence_refs = list(artifact_refs)
            test_refs = list(artifact_refs)
            repeatable = target_stable and not anomalies
            candidate_proofs.append(
                SQLiProof(
                    technique=technique,
                    parameter_name=raw_finding.get("parameter_name") or request.parameter_name,
                    verification_method=_TECHNIQUE_VERIFICATION_METHOD[technique],
                    control_observation_refs=list(request.baseline_artifact_refs),
                    test_observation_refs=test_refs,
                    evidence_refs=evidence_refs,
                    redacted_payload_summary=raw_finding.get("redacted_payload_summary"),
                    repeatable=repeatable,
                    verified=False,
                )
            )

        tested_techniques = [
            SQLiTechnique(item)
            for item in (data.get("requested_techniques") or [t.value for t in request.techniques])
        ]

        raw_output = SqliDetectionCapabilityOutput(
            execution_status=CapabilityExecutionStatus.COMPLETED,
            detection_status=DetectionStatus.INCONCLUSIVE,
            tested_techniques=tested_techniques,
            confirmed_techniques=[],
            heuristic_signal_detected=bool(data.get("heuristic_signal_detected", False)),
            target_stable=target_stable,
            auth_failure_detected=auth_failed,
            rate_limited=rate_limited,
            waf_or_filter_detected=waf_detected,
            dbms_identified=data.get("dbms_identified"),
            proofs=candidate_proofs,
            artifact_refs=artifact_refs,
            error_code=None,
        )

        return verify_sqli_proofs(
            raw_output,
            baseline=baseline,
            candidate_proofs=candidate_proofs,
        )
