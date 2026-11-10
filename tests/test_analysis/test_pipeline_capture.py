"""Opt-in capture: run the real M1 -> M2 driver and save envelope fixtures.

This does two jobs at once. It proves `websecuritycheck.pipeline` works end to
end against an authorized lab target (recon tools + Semgrep + correlation), and
it writes the resulting `Module2CorrelationEnvelope` to a JSON fixture so the AI
hypothesis agent can be developed and unit-tested offline against real data
instead of hand-built mocks.

Gated exactly like the live integration test - nothing runs without
`RUN_LIVE_M1_M2=1` and a configured Semgrep. Fixtures land in
`tests/test_analysis/captured_envelopes/` and are redacted before writing.
"""

from __future__ import annotations

import asyncio
import json
import os
from pathlib import Path

import pytest

from test_analysis.m1_m2_live_support import (
    TARGET_CASES,
    LiveDependencyError,
    TargetCase,
    assessment,
    redact,
    resolve_primary_ruleset,
    trust_policy,
)
from websecuritycheck.analysis.semgrep_adapter import (
    LocalSemgrepAdapter,
    compute_ruleset_sha256,
)
from websecuritycheck.pipeline import build_default_recon_steps, run_pipeline

LIVE_REQUIRED = pytest.mark.skipif(
    os.getenv("RUN_LIVE_M1_M2") != "1",
    reason="set RUN_LIVE_M1_M2=1 to run the authorized WHITEBOX capture",
)

CAPTURE_DIR = Path(__file__).resolve().parent / "captured_envelopes"


def _target_id(case: TargetCase) -> str:
    return f"TGT-{int(case.assessment_id.split('-')[1]):03d}"


@pytest.mark.live_m1_m2
@LIVE_REQUIRED
@pytest.mark.parametrize("case", TARGET_CASES, ids=lambda case: case.name)
def test_capture_envelope_fixture(case: TargetCase) -> None:
    try:
        ruleset = resolve_primary_ruleset()
    except LiveDependencyError as exc:
        pytest.skip(str(exc))

    config = assessment(case)
    policy = trust_policy(compute_ruleset_sha256(ruleset))
    steps = build_default_recon_steps(case.url, specialized_tool=case.specialized_tool)

    try:
        envelope = asyncio.run(
            run_pipeline(
                config,
                steps,
                trust_policy=policy,
                source_repo_path=str(case.source_root.resolve()),
                target_id=_target_id(case),
                analyzer=LocalSemgrepAdapter(ruleset_path=ruleset),
            )
        )
    except LiveDependencyError as exc:
        pytest.skip(str(exc))

    # The driver handed over an unanalyzed envelope: hypotheses are the agent's job.
    assert envelope.output.hypotheses == []
    assert envelope.output.assessment_id == config.assessment_id

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    data = redact(envelope.model_dump(mode="json"))
    path = CAPTURE_DIR / f"envelope_{case.name}.json"
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[capture] wrote {path} ({len(envelope.correlation.records)} correlation records)")
