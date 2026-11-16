"""Opt-in capture: run the real M1 -> M2 driver and save envelope fixtures.

This does two jobs at once. It proves `websecuritycheck.pipeline` works end to
end against an authorized lab target (recon tools + Opengrep + correlation), and
it writes the resulting `Module2CorrelationEnvelope` to a JSON fixture so the AI
hypothesis agent can be developed and unit-tested offline against real data
instead of hand-built mocks.

Gated exactly like the live integration test - nothing runs without
`RUN_LIVE_M1_M2=1` and a configured Opengrep. Fixtures land in
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
from websecuritycheck.analysis.opengrep_adapter import (
    LocalOpengrepAdapter,
    compute_ruleset_sha256,
)
from websecuritycheck.pipeline import build_default_recon_steps, collect_m1, run_module2

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

    # Collected in two steps rather than through `run_pipeline`, because the
    # envelope does not carry the Module 1 request and the request is worth
    # keeping: it holds `TargetModel.endpoints`, the only place an endpoint id
    # can be turned back into `POST /api/search`.
    try:
        request = asyncio.run(
            collect_m1(
                config,
                steps,
                target_id=_target_id(case),
                source_repo_path=str(case.source_root.resolve()),
            )
        )
        envelope = asyncio.run(
            run_module2(
                request,
                trust_policy=policy,
                analyzer=LocalOpengrepAdapter(ruleset_path=ruleset),
            )
        )
    except LiveDependencyError as exc:
        pytest.skip(str(exc))

    # The driver handed over an unanalyzed envelope: hypotheses are the agent's job.
    assert envelope.output.hypotheses == []
    assert envelope.output.assessment_id == config.assessment_id

    CAPTURE_DIR.mkdir(parents=True, exist_ok=True)
    path = _write(CAPTURE_DIR / f"envelope_{case.name}.json", envelope)
    request_path = _write(CAPTURE_DIR / f"request_{case.name}.json", request)
    print(
        f"[capture] wrote {path} ({len(envelope.correlation.records)} correlation "
        f"records) and {request_path} ({len(request.target_model.endpoints)} endpoints)"
    )


def _write(path: Path, model: object) -> Path:
    data = redact(model.model_dump(mode="json"))
    path.write_text(
        json.dumps(data, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return path
