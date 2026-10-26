"""Opt-in Agent smoke tests; never part of the deterministic CI suite."""

from __future__ import annotations

import os

import pytest


pytestmark = [
    pytest.mark.live_agent,
    pytest.mark.skipif(
        not (
            os.getenv("RUN_LIVE_AGENT")
            and os.getenv("OPENAI_API_KEY")
            and os.getenv("WEBSEC_LIVE_URL")
        ),
        reason="set RUN_LIVE_AGENT=1, OPENAI_API_KEY and WEBSEC_LIVE_URL",
    ),
]


def test_registered_checks_return_structured_results_without_secret_leakage():
    from websecuritycheck import SecurityChecker

    target = os.environ["WEBSEC_LIVE_URL"]
    checker = SecurityChecker(
        model=os.getenv("WEBSEC_AGENT_MODEL", "openai:gpt-4o-mini"),
        scope=[target],
        trace_level="full",
    )

    for check_name in ("headers", "cookies", "tls", "cors", "fingerprint"):
        result = checker.run(check_name, target)
        assert result.check == check_name
        assert result.status in {"passed", "issues_found", "partial", "failed"}
        tool_step_ids = set()
        for step in result.trace:
            if step.kind == "tool_call":
                tool_step_ids.add(step.id)
                assert step.name in checker.checks or step.name.startswith("get_") or step.name.endswith("_web")
        for finding in result.findings:
            assert set(finding.tool_refs) <= tool_step_ids
        serialized = result.model_dump_json()
        assert "secret-token" not in serialized
