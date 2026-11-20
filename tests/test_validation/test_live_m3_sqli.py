"""Opt-in live Module 3 SQLMap & Stage B -> M3 E2E tests (run on Kali with RUN_LIVE_M3=1)."""

from __future__ import annotations

import asyncio
import os
import shutil
from functools import wraps
from urllib.parse import urlsplit

import pytest

from websecuritycheck.domain.enums import InputLocation
from websecuritycheck.domain.models import ExecutionPolicy
from websecuritycheck.validation import (
    CapabilityExecutionStatus,
    HttpBaselineAdapter,
    HttpRequestCapabilityInput,
    InMemoryRequestMaterializer,
    SqliDetectionCapabilityInput,
    SQLiTechnique,
    SqlmapDetectionAdapter,
    ValidationOutcome,
    ValidationPlanExecutor,
)

LIVE_M3_REQUIRED = pytest.mark.skipif(
    os.getenv("RUN_LIVE_M3") != "1",
    reason="set RUN_LIVE_M3=1 on Kali with sqlmap installed to run live Module 3 tests",
)

DEFAULT_API_TARGET = "https://api-target.7an6rando.workers.dev"


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _ensure_sqlmap_available() -> None:
    configured = os.getenv("WEBSEC_SQLMAP_PATH", "").strip()
    if configured:
        return
    if shutil.which("sqlmap") is None:
        pytest.skip("sqlmap executable not found on PATH and WEBSEC_SQLMAP_PATH is unset")


def _live_target_config() -> dict[str, str | InputLocation | None]:
    base = os.getenv("M3_LIVE_TARGET_URL", DEFAULT_API_TARGET).strip().rstrip("/")
    parsed = urlsplit(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    target_url = base if (parsed.path and parsed.path != "/") else f"{origin}/api/users?id=1"

    param_name = os.getenv("M3_LIVE_PARAM", "id").strip() or "id"
    method = os.getenv("M3_LIVE_METHOD", "GET").strip().upper() or "GET"
    location_raw = os.getenv("M3_LIVE_LOCATION", "QUERY").strip().upper() or "QUERY"
    location = InputLocation(location_raw)
    dbms_hint = os.getenv("M3_LIVE_DBMS", "").strip() or None
    body = os.getenv("M3_LIVE_BODY")

    return {
        "target_url": target_url,
        "origin": origin,
        "parameter_name": param_name,
        "method": method,
        "parameter_location": location,
        "dbms_hint": dbms_hint,
        "body": body,
    }


def _build_materializer(
    cfg: dict,
) -> tuple[InMemoryRequestMaterializer, str | None, str | None, str | None]:
    materializer = InMemoryRequestMaterializer()
    body = cfg["body"]
    if not body:
        return materializer, None, None, None

    parsed = urlsplit(str(cfg["target_url"]))
    req_path = f"{parsed.path or '/'}{f'?{parsed.query}' if parsed.query else ''}"
    content_type = (
        "application/json"
        if cfg["parameter_location"] == InputLocation.JSON_BODY
        else "application/x-www-form-urlencoded"
    )
    raw_http = (
        f"{cfg['method']} {req_path} HTTP/1.1\r\n"
        f"Host: {parsed.netloc}\r\n"
        f"Content-Type: {content_type}\r\n"
        f"Content-Length: {len(body.encode('utf-8'))}\r\n"
        f"\r\n{body}"
    )
    materializer.register_raw_request("live-req-001", raw_http)
    materializer.register_headers("live-hdr-001", {"Content-Type": content_type})
    materializer.register_body("live-body-001", body)
    return materializer, "live-req-001", "live-hdr-001", "live-body-001"


@LIVE_M3_REQUIRED
@async_test
async def test_live_m3_sqlmap_standalone_on_api_target():
    _ensure_sqlmap_available()
    cfg = _live_target_config()
    materializer, req_ref, hdr_ref, body_ref = _build_materializer(cfg)
    origin = str(cfg["origin"])
    target_url = str(cfg["target_url"])
    method = str(cfg["method"])

    http_adapter = HttpBaselineAdapter(
        authorized_scope=[origin],
        policy=ExecutionPolicy(),
        materializer=materializer,
    )
    baseline = await http_adapter.execute(
        HttpRequestCapabilityInput(
            request_artifact_ref=req_ref,
            headers_ref=hdr_ref,
            body_ref=body_ref,
            target_url=target_url,
            method=method,  # type: ignore[arg-type]
            sample_count=2,
            timeout_seconds=15,
        )
    )
    print(f"\n[LIVE M3] baseline_ready={baseline.baseline_ready}, status={baseline.http_status}")
    assert baseline.execution_status == CapabilityExecutionStatus.COMPLETED
    assert baseline.reachable is True
    assert baseline.baseline_ready is True
    assert baseline.artifact_refs

    sqli_adapter = SqlmapDetectionAdapter(
        authorized_scope=[origin],
        policy=ExecutionPolicy(),
        materializer=materializer,
    )
    result = await sqli_adapter.execute(
        SqliDetectionCapabilityInput(
            request_artifact_ref=req_ref,
            target_url=target_url,
            method=method,  # type: ignore[arg-type]
            parameter_name=str(cfg["parameter_name"]),
            parameter_location=cfg["parameter_location"],  # type: ignore[arg-type]
            baseline_artifact_refs=baseline.artifact_refs,
            techniques=[SQLiTechnique.ERROR, SQLiTechnique.BOOLEAN, SQLiTechnique.UNION],
            dbms_hint=cfg["dbms_hint"],  # type: ignore[arg-type]
            timeout_seconds=120,
        ),
        baseline=baseline,
    )
    print(
        f"[LIVE M3] status={result.detection_status}, dbms={result.dbms_identified}, "
        f"confirmed={result.confirmed_techniques}, proofs={len(result.proofs)}"
    )
    assert result.execution_status == CapabilityExecutionStatus.COMPLETED
    assert result.artifact_refs


@LIVE_M3_REQUIRED
@async_test
async def test_live_e2e_stage_b_to_m3_executor_on_api_target():
    _ensure_sqlmap_available()
    cfg = _live_target_config()
    materializer, req_ref, _hdr_ref, _body_ref = _build_materializer(cfg)
    origin = str(cfg["origin"])
    target_url = str(cfg["target_url"])
    method = str(cfg["method"])
    location = cfg["parameter_location"]

    handoff = {
        "plan": {
            "plan_id": "PLAN-LIVE-001",
            "hypothesis_ref": "HYP-001",
            "execution_limits": {"aggregate_max_requests": 200, "detection_timeout_seconds": 120},
            "test_cases": [
                {
                    "test_case_id": "TC-001",
                    "tactic_step_ref": "baseline",
                    "capability_id": "HTTP_REQUEST",
                    "dependencies": [],
                    "capability_arguments": {"sample_count": 2, "timeout_seconds": 15},
                    "stop_conditions": ["BASELINE_NOT_READY"],
                    "max_requests": 2,
                    "timeout_seconds": 15,
                    "optional": False,
                },
                {
                    "test_case_id": "TC-002",
                    "tactic_step_ref": "primary_detection",
                    "capability_id": "SQLI_DETECTION",
                    "dependencies": ["TC-001"],
                    "capability_arguments": {
                        "techniques": ["ERROR", "BOOLEAN", "UNION"],
                        "risk_profile": "LOW",
                        "max_requests": 150,
                        "timeout_seconds": 120,
                        "dbms_hint": cfg["dbms_hint"],
                    },
                    "stop_conditions": ["VERIFIED_PROOF_FOUND", "TARGET_UNSTABLE", "RATE_LIMITED"],
                    "max_requests": 150,
                    "timeout_seconds": 120,
                    "optional": False,
                },
            ],
        },
        "resolved_target": {
            "endpoint": {"ref": "a" * 12, "method": method, "url": target_url},
            "input": {
                "ref": "INP-001",
                "parameter": str(cfg["parameter_name"]),
                "location": location.value,  # type: ignore[union-attr]
            },
            "request_template_ref": req_ref,
            "auth_ref": None,
        },
    }
    executor = ValidationPlanExecutor(
        authorized_scope=[origin],
        policy=ExecutionPolicy(),
        materializer=materializer,
    )
    verdict = await executor.execute_handoff(handoff)
    print(
        f"\n[LIVE E2E] outcome={verdict.outcome}, stop={verdict.stop_reason}, "
        f"dbms={verdict.dbms_identified}, confirmed={verdict.confirmed_techniques}"
    )
    assert verdict.outcome in {
        ValidationOutcome.CONFIRMED,
        ValidationOutcome.NOT_CONFIRMED,
        ValidationOutcome.INCONCLUSIVE,
    }
    assert verdict.artifact_refs
