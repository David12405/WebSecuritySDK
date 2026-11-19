"""Deterministic Module 3 executor for Stage B StructuredTestPlan handoff bundles."""

from __future__ import annotations

from collections.abc import Sequence
from typing import Any

from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import ExecutionPolicy

from .http_baseline import HttpBaselineAdapter
from .models import (
    SUPPORTED_SQLI_LOCATIONS,
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpRequestCapabilityInput,
    HttpRequestCapabilityOutput,
    PlanExecutionResult,
    RiskProfile,
    SqliDetectionCapabilityInput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
    TestCaseExecutionRecord,
    ValidationOutcome,
)
from .resolvers import InMemoryRequestMaterializer, RequestMaterializerProtocol
from .sqlmap_adapter import SqlmapDetectionAdapter

_INCONCLUSIVE_STOPS = frozenset(
    {
        "BASELINE_NOT_READY",
        "AUTH_FAILURE",
        "RATE_LIMITED",
        "WAF_OR_FILTER_DETECTED",
        "TARGET_UNSTABLE",
        "BUDGET_EXHAUSTED",
    }
)


def _evaluate_http_stops(
    output: HttpRequestCapabilityOutput, stop_conditions: list[str]
) -> list[str]:
    triggered: list[str] = []
    if "BASELINE_NOT_READY" in stop_conditions and not output.baseline_ready:
        triggered.append("BASELINE_NOT_READY")
    if "AUTH_FAILURE" in stop_conditions and output.auth_failure_detected:
        triggered.append("AUTH_FAILURE")
    if "RATE_LIMITED" in stop_conditions and output.rate_limited:
        triggered.append("RATE_LIMITED")
    if "WAF_OR_FILTER_DETECTED" in stop_conditions and output.waf_or_filter_detected:
        triggered.append("WAF_OR_FILTER_DETECTED")
    if "TARGET_UNSTABLE" in stop_conditions and output.target_stable is False:
        triggered.append("TARGET_UNSTABLE")
    return triggered


def _evaluate_sqli_stops(
    output: SqliDetectionCapabilityOutput, stop_conditions: list[str]
) -> list[str]:
    triggered: list[str] = []
    if "VERIFIED_PROOF_FOUND" in stop_conditions and any(p.verified for p in output.proofs):
        triggered.append("VERIFIED_PROOF_FOUND")
    if "AUTH_FAILURE" in stop_conditions and output.auth_failure_detected:
        triggered.append("AUTH_FAILURE")
    if "RATE_LIMITED" in stop_conditions and output.rate_limited:
        triggered.append("RATE_LIMITED")
    if "WAF_OR_FILTER_DETECTED" in stop_conditions and output.waf_or_filter_detected:
        triggered.append("WAF_OR_FILTER_DETECTED")
    if "TARGET_UNSTABLE" in stop_conditions and output.target_stable is False:
        triggered.append("TARGET_UNSTABLE")
    return triggered


def _append_unique(target: list[Any], items: Sequence[Any]) -> None:
    for item in items:
        if item not in target:
            target.append(item)


class ValidationPlanExecutor:
    """Executes one Stage B ``build_m3_handoff`` bundle through Module 3 adapters."""

    def __init__(
        self,
        *,
        authorized_scope: Sequence[str] | None = None,
        policy: ExecutionPolicy | None = None,
        materializer: RequestMaterializerProtocol | None = None,
        http_adapter: HttpBaselineAdapter | None = None,
        sqli_adapter: SqlmapDetectionAdapter | None = None,
    ) -> None:
        self._materializer = materializer or InMemoryRequestMaterializer()
        self._http_adapter = http_adapter or HttpBaselineAdapter(
            authorized_scope=authorized_scope,
            policy=policy,
            materializer=self._materializer,
        )
        self._sqli_adapter = sqli_adapter or SqlmapDetectionAdapter(
            authorized_scope=authorized_scope,
            policy=policy,
            materializer=self._materializer,
        )

    @property
    def materializer(self) -> RequestMaterializerProtocol:
        return self._materializer

    async def execute_handoff(self, handoff: dict[str, Any]) -> PlanExecutionResult:
        """Execute test cases sequentially, enforcing dependencies, budgets, and stop rules."""

        plan = handoff.get("plan") or {}
        plan_id = str(plan.get("plan_id") or "PLAN-000")
        hypothesis_ref = str(plan.get("hypothesis_ref") or "HYP-000")
        resolved = handoff.get("resolved_target") or {}
        endpoint = resolved.get("endpoint")
        target_input = resolved.get("input")

        if not isinstance(endpoint, dict) or not isinstance(target_input, dict):
            return PlanExecutionResult(
                plan_id=plan_id,
                hypothesis_ref=hypothesis_ref,
                outcome=ValidationOutcome.INCONCLUSIVE,
                stop_reason="MISSING_RESOLVED_TARGET",
            )

        target_url = str(endpoint.get("url") or "")
        method = str(endpoint.get("method") or "GET").upper()
        param_name = str(target_input.get("parameter") or "")
        location_raw = str(target_input.get("location") or "")
        try:
            param_location = InputLocation(location_raw)
        except ValueError:
            return PlanExecutionResult(
                plan_id=plan_id,
                hypothesis_ref=hypothesis_ref,
                outcome=ValidationOutcome.UNSUPPORTED,
                stop_reason=f"UNSUPPORTED_LOCATION:{location_raw}",
            )

        if param_location not in SUPPORTED_SQLI_LOCATIONS:
            return PlanExecutionResult(
                plan_id=plan_id,
                hypothesis_ref=hypothesis_ref,
                outcome=ValidationOutcome.UNSUPPORTED,
                stop_reason=f"UNSUPPORTED_LOCATION:{param_location.value}",
            )

        request_template_ref = resolved.get("request_template_ref")
        auth_ref = resolved.get("auth_ref")
        limits = plan.get("execution_limits") or {}
        aggregate_budget = int(limits.get("aggregate_max_requests") or 250)

        baseline_output: HttpRequestCapabilityOutput | None = None
        baseline_refs: list[str] = []
        executed_ok: set[str] = set()
        case_results: list[TestCaseExecutionRecord] = []
        all_proofs: list[SQLiProof] = []
        all_artifacts: list[str] = []
        tested_techniques: list[SQLiTechnique] = []
        confirmed_techniques: list[SQLiTechnique] = []
        dbms_identified: str | None = None
        heuristic_seen = False
        error_codes: list[str] = []
        stop_reason: str | None = None
        budget_used = 0

        for case in plan.get("test_cases") or []:
            tc_id = str(case["test_case_id"])
            step_ref = str(case.get("tactic_step_ref") or "")
            cap_id = str(case["capability_id"])
            deps = [str(dep) for dep in (case.get("dependencies") or [])]
            stop_conds = [str(cond) for cond in (case.get("stop_conditions") or [])]
            is_optional = bool(case.get("optional", False))
            case_max_req = int(case.get("max_requests") or 1)
            cap_args = dict(case.get("capability_arguments") or {})

            if any(dep not in executed_ok for dep in deps):
                case_results.append(
                    TestCaseExecutionRecord(
                        test_case_id=tc_id,
                        tactic_step_ref=step_ref,
                        capability_id=cap_id,
                        status="SKIPPED",
                        skip_reason="UNSATISFIED_DEPENDENCY",
                    )
                )
                continue

            if budget_used + case_max_req > aggregate_budget:
                stop_reason = "BUDGET_EXHAUSTED"
                case_results.append(
                    TestCaseExecutionRecord(
                        test_case_id=tc_id,
                        tactic_step_ref=step_ref,
                        capability_id=cap_id,
                        status="SKIPPED",
                        skip_reason="BUDGET_EXHAUSTED",
                        triggered_stop_conditions=["BUDGET_EXHAUSTED"],
                    )
                )
                break

            if cap_id == "HTTP_REQUEST":
                http_in = HttpRequestCapabilityInput(
                    request_artifact_ref=request_template_ref,
                    target_url=target_url,
                    method=method,  # type: ignore[arg-type]
                    auth_ref=auth_ref,
                    sample_count=min(3, max(1, int(cap_args.get("sample_count", 2)))),
                    timeout_seconds=min(60, max(1, int(cap_args.get("timeout_seconds", 15)))),
                )
                http_out = await self._http_adapter.execute(http_in)
                budget_used += http_in.sample_count
                _append_unique(all_artifacts, http_out.artifact_refs)

                if http_out.error_code:
                    error_codes.append(http_out.error_code)

                triggered = _evaluate_http_stops(http_out, stop_conds)
                case_results.append(
                    TestCaseExecutionRecord(
                        test_case_id=tc_id,
                        tactic_step_ref=step_ref,
                        capability_id=cap_id,
                        status="EXECUTED",
                        http_output=http_out,
                        triggered_stop_conditions=triggered,
                    )
                )
                if http_out.execution_status == CapabilityExecutionStatus.COMPLETED:
                    baseline_output = http_out
                    _append_unique(baseline_refs, http_out.artifact_refs)
                    if http_out.baseline_ready:
                        executed_ok.add(tc_id)
                if http_out.error_code == "E_SCOPE":
                    stop_reason = "E_SCOPE"
                    break
                if triggered:
                    stop_reason = triggered[0]
                    break
                if http_out.execution_status != CapabilityExecutionStatus.COMPLETED:
                    stop_reason = http_out.error_code or "HTTP_REQUEST_FAILED"
                    break
                continue

            if cap_id == "SQLI_DETECTION":
                if is_optional and (
                    confirmed_techniques
                    or baseline_output is None
                    or baseline_output.target_stable is not True
                ):
                    case_results.append(
                        TestCaseExecutionRecord(
                            test_case_id=tc_id,
                            tactic_step_ref=step_ref,
                            capability_id=cap_id,
                            status="SKIPPED",
                            skip_reason="OPTIONAL_PRECONDITION_NOT_MET",
                        )
                    )
                    continue

                if not baseline_refs:
                    stop_reason = "BASELINE_NOT_READY"
                    case_results.append(
                        TestCaseExecutionRecord(
                            test_case_id=tc_id,
                            tactic_step_ref=step_ref,
                            capability_id=cap_id,
                            status="SKIPPED",
                            skip_reason="BASELINE_NOT_READY",
                            triggered_stop_conditions=["BASELINE_NOT_READY"],
                        )
                    )
                    break

                raw_techniques = cap_args.get("techniques") or (
                    [case["technique"]] if case.get("technique") else ["ERROR", "BOOLEAN", "UNION"]
                )
                sqli_in = SqliDetectionCapabilityInput(
                    request_artifact_ref=request_template_ref,
                    target_url=target_url,
                    method=method,  # type: ignore[arg-type]
                    parameter_name=param_name,
                    parameter_location=param_location,
                    auth_ref=auth_ref,
                    baseline_artifact_refs=list(baseline_refs),
                    techniques=[SQLiTechnique(t) for t in raw_techniques],
                    dbms_hint=cap_args.get("dbms_hint"),
                    max_requests=min(500, max(10, int(cap_args.get("max_requests", case_max_req)))),
                    timeout_seconds=min(300, max(5, int(cap_args.get("timeout_seconds", 120)))),
                    risk_profile=RiskProfile(str(cap_args.get("risk_profile") or "LOW")),
                )
                sqli_out = await self._sqli_adapter.execute(sqli_in, baseline=baseline_output)
                budget_used += sqli_in.max_requests
                _append_unique(all_artifacts, sqli_out.artifact_refs)
                _append_unique(tested_techniques, sqli_out.tested_techniques)
                _append_unique(confirmed_techniques, sqli_out.confirmed_techniques)
                all_proofs.extend(sqli_out.proofs)
                if sqli_out.dbms_identified and not dbms_identified:
                    dbms_identified = sqli_out.dbms_identified
                if sqli_out.heuristic_signal_detected:
                    heuristic_seen = True
                if sqli_out.error_code:
                    error_codes.append(sqli_out.error_code)

                triggered = _evaluate_sqli_stops(sqli_out, stop_conds)
                case_results.append(
                    TestCaseExecutionRecord(
                        test_case_id=tc_id,
                        tactic_step_ref=step_ref,
                        capability_id=cap_id,
                        status="EXECUTED",
                        sqli_output=sqli_out,
                        triggered_stop_conditions=triggered,
                    )
                )
                if sqli_out.execution_status == CapabilityExecutionStatus.COMPLETED:
                    executed_ok.add(tc_id)
                if sqli_out.error_code == "E_SCOPE":
                    stop_reason = "E_SCOPE"
                    break
                if triggered:
                    stop_reason = triggered[0]
                    break
                if sqli_out.execution_status != CapabilityExecutionStatus.COMPLETED:
                    stop_reason = sqli_out.error_code or "SQLI_DETECTION_FAILED"
                    break
                continue

            return PlanExecutionResult(
                plan_id=plan_id,
                hypothesis_ref=hypothesis_ref,
                outcome=ValidationOutcome.UNSUPPORTED,
                stop_reason=f"UNSUPPORTED_CAPABILITY:{cap_id}",
                case_results=case_results,
                artifact_refs=all_artifacts,
                estimated_requests_budget_used=budget_used,
            )

        outcome = _resolve_final_outcome(
            confirmed_techniques=confirmed_techniques,
            all_proofs=all_proofs,
            tested_techniques=tested_techniques,
            heuristic_seen=heuristic_seen,
            error_codes=error_codes,
            stop_reason=stop_reason,
            case_results=case_results,
        )

        return PlanExecutionResult(
            plan_id=plan_id,
            hypothesis_ref=hypothesis_ref,
            outcome=outcome,
            stop_reason=stop_reason,
            dbms_identified=dbms_identified,
            tested_techniques=tested_techniques,
            confirmed_techniques=confirmed_techniques,
            proofs=all_proofs,
            artifact_refs=all_artifacts,
            case_results=case_results,
            estimated_requests_budget_used=budget_used,
        )


def _resolve_final_outcome(
    *,
    confirmed_techniques: list[SQLiTechnique],
    all_proofs: list[SQLiProof],
    tested_techniques: list[SQLiTechnique],
    heuristic_seen: bool,
    error_codes: list[str],
    stop_reason: str | None,
    case_results: list[TestCaseExecutionRecord],
) -> ValidationOutcome:
    if confirmed_techniques and any(p.verified for p in all_proofs):
        return ValidationOutcome.CONFIRMED
    if "E_SCOPE" in error_codes or stop_reason == "E_SCOPE":
        return ValidationOutcome.POLICY_BLOCKED
    if "E_UNSUPPORTED_INPUT" in error_codes:
        return ValidationOutcome.UNSUPPORTED
    if error_codes:
        return ValidationOutcome.ERROR
    if stop_reason in _INCONCLUSIVE_STOPS or heuristic_seen:
        return ValidationOutcome.INCONCLUSIVE
    has_inconclusive_sqli = any(
        rec.sqli_output is not None
        and rec.sqli_output.detection_status
        in {DetectionStatus.INCONCLUSIVE, DetectionStatus.HEURISTIC_ONLY}
        for rec in case_results
    )
    if has_inconclusive_sqli or not tested_techniques:
        return ValidationOutcome.INCONCLUSIVE
    return ValidationOutcome.NOT_CONFIRMED
