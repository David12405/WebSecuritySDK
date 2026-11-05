"""Opt-in live WHITEBOX integration tests for the M1 -> M2 handoff."""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from test_analysis.m1_m2_live_support import (
    TARGET_CASES,
    IntegrationReport,
    LiveDependencyError,
    PrimaryRulesetContractError,
    TargetCase,
    audit_community_rules,
    resolve_primary_ruleset,
    run_target,
    verify_primary_ruleset,
)

LIVE_REQUIRED = pytest.mark.skipif(
    os.getenv("RUN_LIVE_M1_M2") != "1",
    reason="set RUN_LIVE_M1_M2=1 to run the authorized WHITEBOX integration test",
)


@pytest.fixture(scope="session")
def live_m1_m2_context(request: pytest.FixtureRequest) -> tuple[IntegrationReport, Path]:
    try:
        ruleset = resolve_primary_ruleset()
    except LiveDependencyError as exc:
        pytest.skip(str(exc))
    report = IntegrationReport(ruleset)
    request.addfinalizer(report.write)
    try:
        report.data["preflight"]["primary_ruleset"] = asyncio.run(
            verify_primary_ruleset(ruleset, report.trace)
        )
    except PrimaryRulesetContractError as exc:
        report.data["preflight"]["primary_ruleset"] = exc.diagnostics
        raise
    asyncio.run(audit_community_rules(report))
    return report, ruleset


@pytest.mark.live_m1_m2
@LIVE_REQUIRED
@pytest.mark.parametrize("case", TARGET_CASES, ids=lambda case: case.name)
def test_live_whitebox_m1_to_m2_target(
    case: TargetCase,
    live_m1_m2_context: tuple[IntegrationReport, Path],
) -> None:
    report, ruleset = live_m1_m2_context
    try:
        target_report = asyncio.run(run_target(case, ruleset, report.trace))
    except LiveDependencyError as exc:
        target_report = {
            "name": case.name,
            "url": case.url,
            "source_root": str(case.source_root.resolve()),
            "status": "skipped_dependency",
            "skip_reason": str(exc),
        }
        report.record_target(target_report)
        report.trace.add(case.name, "target", "skipped_dependency", reason=str(exc))
        pytest.skip(str(exc))
    except Exception as exc:
        target_report = {
            "name": case.name,
            "url": case.url,
            "source_root": str(case.source_root.resolve()),
            "status": "contract_failed",
            "error": f"{type(exc).__name__}: {exc}",
        }
        report.record_target(target_report)
        report.trace.add(case.name, "target", "contract_failed", error=str(exc))
        raise
    report.record_target(target_report)
    serialized = json.dumps(report.data, ensure_ascii=False).casefold()
    assert "secret-token" not in serialized
