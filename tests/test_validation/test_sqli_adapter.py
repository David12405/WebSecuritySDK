"""Unit and contract invariant tests for Module 3 SQLi & HTTP baseline adapters."""

from __future__ import annotations

import asyncio
from functools import wraps

from mcp_servers.websec_tools.errors import envelope
from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import ExecutionPolicy
from websecuritycheck.validation import (
    CapabilityExecutionStatus,
    DetectionStatus,
    HttpBaselineAdapter,
    HttpRequestCapabilityInput,
    HttpRequestCapabilityOutput,
    InMemoryRequestMaterializer,
    ResolvedAuthContext,
    SqliDetectionCapabilityInput,
    SqliDetectionCapabilityOutput,
    SQLiProof,
    SQLiTechnique,
    SqlmapDetectionAdapter,
    verify_sqli_proofs,
)


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _fake_probe_envelope(
    *,
    status: int = 200,
    size: int = 120,
    body: str = "ok",
    headers: dict | None = None,
    ref: str = "http-exchange-001",
):
    return envelope(
        f"GET {status}",
        {
            "target": "https://shop.example.com/search?q=test",
            "method": "GET",
            "final_url": "https://shop.example.com/search?q=test",
            "status": status,
            "http_version": "HTTP/1.1",
            "redirects": [],
            "request_headers": {},
            "response_headers": headers or {},
            "request_content_type": None,
            "response_content_type": "text/html",
            "request_parameter_names": [],
            "response_body_size": size,
            "response_body_text": body,
            "body_truncated": False,
            "redacted_headers": [],
            "artifact_manifests": [
                {
                    "artifact_ref": ref,
                    "artifact_type": "HTTP_RAW_EXCHANGE",
                    "content": "{}",
                    "media_type": "application/json",
                    "redaction_applied": True,
                }
            ],
        },
        False,
    )


@async_test
async def test_http_baseline_adapter_evaluates_stability_and_three_valued_logic():
    counter = 0

    async def stable_probe(url, method="GET", headers=None, body=None):
        nonlocal counter
        counter += 1
        return _fake_probe_envelope(status=200, size=100, ref=f"http-exchange-00{counter}")

    adapter = HttpBaselineAdapter(
        authorized_scope=["https://shop.example.com"],
        probe_fn=stable_probe,
    )
    out2 = await adapter.execute(
        HttpRequestCapabilityInput(target_url="https://shop.example.com/search", sample_count=2)
    )
    assert out2.execution_status == CapabilityExecutionStatus.COMPLETED
    assert out2.reachable is True
    assert out2.target_stable is True
    assert out2.baseline_ready is True
    assert len(out2.artifact_refs) == 2

    # sample_count == 1 -> target_stable must be None (three-valued logic) and baseline_ready False
    out1 = await adapter.execute(
        HttpRequestCapabilityInput(target_url="https://shop.example.com/search", sample_count=1)
    )
    assert out1.target_stable is None
    assert out1.baseline_ready is False


@async_test
async def test_http_baseline_adapter_detects_auth_rate_limit_and_scope_errors():
    async def unauthorized_probe(url, method="GET", headers=None, body=None):
        return _fake_probe_envelope(status=401, body="Unauthorized")

    auth_adapter = HttpBaselineAdapter(
        authorized_scope=["https://shop.example.com"],
        probe_fn=unauthorized_probe,
    )
    res_auth = await auth_adapter.execute(
        HttpRequestCapabilityInput(target_url="https://shop.example.com/admin", sample_count=2)
    )
    assert res_auth.auth_failure_detected is True
    assert res_auth.baseline_ready is False

    async def rate_limited_probe(url, method="GET", headers=None, body=None):
        return _fake_probe_envelope(status=429, headers={"retry-after": "30"})

    rl_adapter = HttpBaselineAdapter(
        authorized_scope=["https://shop.example.com"],
        probe_fn=rate_limited_probe,
    )
    res_rl = await rl_adapter.execute(
        HttpRequestCapabilityInput(target_url="https://shop.example.com/search", sample_count=2)
    )
    assert res_rl.rate_limited is True
    assert res_rl.baseline_ready is False

    res_scope = await rl_adapter.execute(
        HttpRequestCapabilityInput(target_url="https://evil.example.net/search", sample_count=2)
    )
    assert res_scope.execution_status == CapabilityExecutionStatus.FAILED
    assert res_scope.error_code == "E_SCOPE"


@async_test
async def test_sqlmap_adapter_materializes_auth_and_verifies_confirmed_proof():
    captured_call: dict = {}

    async def fake_detect(target, parameter_name, **kwargs):
        captured_call["target"] = target
        captured_call["parameter_name"] = parameter_name
        captured_call.update(kwargs)
        return envelope(
            "confirmed",
            {
                "tool": "sqlmap",
                "target": target,
                "method": kwargs["method"],
                "parameter_name": parameter_name,
                "parameter_location": kwargs["parameter_location"],
                "requested_techniques": kwargs["techniques"],
                "findings": [
                    {
                        "parameter_name": parameter_name,
                        "location_label": "GET",
                        "technique": "ERROR",
                        "sqlmap_type": "error-based",
                        "title": "SQLite error-based",
                        "redacted_payload_summary": (
                            "id=1' AND Authorization: Bearer raw-leak-token"
                        ),
                        "dbms_identified": "SQLite",
                    }
                ],
                "dbms_identified": "SQLite",
                "heuristic_signal_detected": True,
                "target_stable": True,
                "auth_failure_detected": False,
                "rate_limited": False,
                "waf_or_filter_detected": False,
                "warnings": [],
                "artifact_manifests": [
                    {
                        "artifact_ref": "sqlmap-output-abc123",
                        "artifact_type": "TOOL_RAW_OUTPUT",
                        "content": "back-end DBMS: SQLite",
                        "media_type": "text/plain",
                        "redaction_applied": True,
                    }
                ],
            },
            False,
        )

    materializer = InMemoryRequestMaterializer()
    materializer.register_raw_request(
        "http-req-001",
        "GET /items?id=1 HTTP/1.1\r\nHost: shop.example.com\r\n\r\n",
    )
    materializer.register_auth(
        "VAULT-USER-1",
        ResolvedAuthContext(headers={"Authorization": "Bearer secret-user-jwt"}),
    )

    baseline = HttpRequestCapabilityOutput(
        execution_status=CapabilityExecutionStatus.COMPLETED,
        http_status=200,
        reachable=True,
        auth_failure_detected=False,
        rate_limited=False,
        waf_or_filter_detected=False,
        target_stable=True,
        baseline_ready=True,
        artifact_refs=["http-exchange-base-1"],
    )

    adapter = SqlmapDetectionAdapter(
        authorized_scope=["https://shop.example.com"],
        policy=ExecutionPolicy(),
        materializer=materializer,
        detect_fn=fake_detect,
    )
    output = await adapter.execute(
        SqliDetectionCapabilityInput(
            request_artifact_ref="http-req-001",
            target_url="https://shop.example.com/items?id=1",
            method="GET",
            parameter_name="id",
            parameter_location=InputLocation.QUERY,
            auth_ref="VAULT-USER-1",
            baseline_artifact_refs=["http-exchange-base-1"],
            techniques=[SQLiTechnique.ERROR, SQLiTechnique.BOOLEAN],
        ),
        baseline=baseline,
    )

    assert captured_call["headers"] == {"Authorization": "Bearer secret-user-jwt"}
    assert "GET /items?id=1 HTTP/1.1" in captured_call["raw_request"]
    assert output.execution_status == CapabilityExecutionStatus.COMPLETED
    assert output.detection_status == DetectionStatus.CONFIRMED
    assert output.confirmed_techniques == [SQLiTechnique.ERROR]
    assert len(output.proofs) == 1
    assert output.proofs[0].verified is True
    assert "raw-leak-token" not in (output.proofs[0].redacted_payload_summary or "")


def test_verifier_enforces_time_stability_and_heuristic_never_confirmed():
    unverified_baseline = HttpRequestCapabilityOutput(
        execution_status=CapabilityExecutionStatus.COMPLETED,
        http_status=200,
        reachable=True,
        auth_failure_detected=False,
        rate_limited=False,
        waf_or_filter_detected=False,
        target_stable=None,  # sample_count=1 -> cannot verify TIME
        baseline_ready=False,
        artifact_refs=["http-exchange-1"],
    )

    time_output = SqliDetectionCapabilityOutput(
        execution_status=CapabilityExecutionStatus.COMPLETED,
        detection_status=DetectionStatus.CONFIRMED,  # pre-claimed untruthfully
        tested_techniques=[SQLiTechnique.TIME],
        confirmed_techniques=[SQLiTechnique.TIME],
        target_stable=True,
        proofs=[
            SQLiProof(
                technique=SQLiTechnique.TIME,
                parameter_name="id",
                verification_method="timing_delay_contrast",
                control_observation_refs=["http-exchange-1"],
                test_observation_refs=["sqlmap-out-1"],
                evidence_refs=["sqlmap-out-1"],
                repeatable=True,
                verified=True,
            )
        ],
    )
    checked_time = verify_sqli_proofs(time_output, baseline=unverified_baseline)
    assert checked_time.detection_status == DetectionStatus.INCONCLUSIVE
    assert checked_time.confirmed_techniques == []
    assert checked_time.proofs[0].verified is False

    heuristic_output = SqliDetectionCapabilityOutput(
        execution_status=CapabilityExecutionStatus.COMPLETED,
        detection_status=DetectionStatus.CONFIRMED,
        tested_techniques=[SQLiTechnique.BOOLEAN],
        confirmed_techniques=[],
        heuristic_signal_detected=True,
        target_stable=True,
        proofs=[],
    )
    checked_heuristic = verify_sqli_proofs(heuristic_output)
    assert checked_heuristic.detection_status == DetectionStatus.HEURISTIC_ONLY
    assert checked_heuristic.confirmed_techniques == []
