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


def _live_target_url_and_scope() -> tuple[str, str]:
    base = os.getenv("M3_LIVE_TARGET_URL", DEFAULT_API_TARGET).strip().rstrip("/")
    parsed = urlsplit(base)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    if parsed.path and parsed.path != "/":
        return base, origin
    return f"{origin}/api/users?id=1", origin


@LIVE_M3_REQUIRED
@async_test
async def test_live_m3_sqlmap_standalone_on_api_target():
    _ensure_sqlmap_available()
    target_url, origin = _live_target_url_and_scope()
    materializer = InMemoryRequestMaterializer()

    http_adapter = HttpBaselineAdapter(
        authorized_scope=[origin],
        policy=ExecutionPolicy(),
        materializer=materializer,
    )
    baseline = await http_adapter.execute(
        HttpRequestCapabilityInput(
            target_url=target_url,
            method="GET",
            sample_count=2,
            timeout_seconds=15,
        )
    )
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
            target_url=target_url,
            method="GET",
            parameter_name="id",
            parameter_location=InputLocation.QUERY,
            baseline_artifact_refs=baseline.artifact_refs,
            techniques=[SQLiTechnique.ERROR, SQLiTechnique.BOOLEAN, SQLiTechnique.UNION],
            timeout_seconds=120,
        ),
        baseline=baseline,
    )
    assert result.execution_status == CapabilityExecutionStatus.COMPLETED
    assert result.artifact_refs


@LIVE_M3_REQUIRED
@async_test
async def test_live_e2e_stage_b_to_m3_executor_on_api_target():
    _ensure_sqlmap_available()
    target_url, origin = _live_target_url_and_scope()
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
                        "dbms_hint": None,
                    },
                    "stop_conditions": ["VERIFIED_PROOF_FOUND", "TARGET_UNSTABLE", "RATE_LIMITED"],
                    "max_requests": 150,
                    "timeout_seconds": 120,
                    "optional": False,
                },
            ],
        },
        "resolved_target": {
            "endpoint": {"ref": "a" * 12, "method": "GET", "url": target_url},
            "input": {"ref": "INP-001", "parameter": "id", "location": "QUERY"},
            "request_template_ref": None,
            "auth_ref": None,
        },
    }
    executor = ValidationPlanExecutor(
        authorized_scope=[origin],
        policy=ExecutionPolicy(),
    )
    verdict = await executor.execute_handoff(handoff)
    assert verdict.outcome in {
        ValidationOutcome.CONFIRMED,
        ValidationOutcome.NOT_CONFIRMED,
        ValidationOutcome.INCONCLUSIVE,
    }
    assert verdict.artifact_refs
