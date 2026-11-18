"""Deterministic tests for the M1 -> M2 driver (no network, no Opengrep).

`run_module2` is exercised with a pre-captured Opengrep payload so the whole
Module 2 pipeline runs offline; `collect_m1` is exercised with fake recon
steps so the orchestration (folding, optional-skip, failure) is tested without
touching a target.
"""

from __future__ import annotations

import asyncio
from functools import wraps

import pytest
from test_analysis.fixtures import (
    make_opengrep_envelope,
    make_scope_rules,
    make_shop_analysis_request_with_scope,
    make_taint_opengrep_finding,
    make_test_trust_policy,
)

from websecuritycheck.analysis.correlation import Module2CorrelationEnvelope
from websecuritycheck.domain.analysis_models import Module2AnalysisRequest
from websecuritycheck.pipeline import (
    ReconStep,
    build_default_recon_steps,
    collect_m1,
    run_module2,
    run_pipeline,
)


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _probe_envelope(url: str) -> dict:
    """A minimal Layer 6 HTTP probe envelope process_tool_result can canonicalize."""
    return {
        "summary": "probe ok",
        "data": {
            "url": url,
            "method": "GET",
            "status": 200,
            "response_content_type": "application/json",
        },
        "truncated": False,
    }


async def _probe(url: str) -> dict:
    return _probe_envelope(url)


async def _boom() -> dict:
    raise RuntimeError("boom")


# --------------------------------------------------------------------------- #
# run_module2
# --------------------------------------------------------------------------- #


@async_test
async def test_run_module2_seals_envelope_with_empty_hypotheses():
    request = make_shop_analysis_request_with_scope(source_repo_path="/repo/shop")
    payload = make_opengrep_envelope([make_taint_opengrep_finding()])

    envelope = await run_module2(
        request,
        trust_policy=make_test_trust_policy(),
        opengrep_payload=payload,
    )

    assert isinstance(envelope, Module2CorrelationEnvelope)
    # The AI agent's slot is handed over empty - it fills this in.
    assert envelope.output.hypotheses == []
    # Inputs were discovered from the shop endpoints' parameters.
    assert envelope.output.inputs, "expected inputs extracted from endpoint parameters"
    # The correlation half is present for the agent to read.
    assert envelope.correlation is not None
    # IDs round-trip: the request assessment is preserved for downstream validation.
    assert envelope.output.assessment_id == request.target_model.assessment_id


@async_test
async def test_run_module2_without_source_yields_no_sinks():
    request = make_shop_analysis_request_with_scope(source_repo_path="/repo/shop")

    envelope = await run_module2(request, trust_policy=make_test_trust_policy())

    assert isinstance(envelope, Module2CorrelationEnvelope)
    assert envelope.output.sink_candidates == []
    # Inputs are still mapped even with no static analysis.
    assert envelope.output.inputs


# --------------------------------------------------------------------------- #
# collect_m1
# --------------------------------------------------------------------------- #


@async_test
async def test_collect_m1_folds_steps_into_one_request():
    assessment = make_scope_rules(assessment_id="ASM-001")
    url = "https://shop.lab.local/api/users?id=1"
    steps = [ReconStep("probe_http", "HTTPProbeResult", url, lambda: _probe(url))]

    request = await collect_m1(assessment, steps, target_id="TGT-001")

    assert isinstance(request, Module2AnalysisRequest)
    assert request.target_model.target_id == "TGT-001"
    assert request.target_model.endpoints, "probe should have produced an endpoint"
    assert request.target_model.endpoints[0].path == "/api/users"


@async_test
async def test_collect_m1_skips_optional_failures_but_keeps_good_steps():
    assessment = make_scope_rules(assessment_id="ASM-001")
    good = "https://shop.lab.local/api/users?id=1"
    steps = [
        ReconStep("probe_http", "HTTPProbeResult", good, lambda: _probe(good)),
        ReconStep("parse_api_spec", "OPENAPI_SPEC", good + "/openapi.json", _boom, optional=True),
    ]

    request = await collect_m1(assessment, steps)

    # The optional failure was swallowed; the good step still shaped the model.
    assert request.target_model.endpoints


@async_test
async def test_collect_m1_propagates_required_step_failure():
    assessment = make_scope_rules(assessment_id="ASM-001")
    steps = [ReconStep("probe_http", "HTTPProbeResult", "https://x.lab.local", _boom)]

    with pytest.raises(RuntimeError, match="boom"):
        await collect_m1(assessment, steps)


@async_test
async def test_collect_m1_raises_when_no_step_produced_a_model():
    assessment = make_scope_rules(assessment_id="ASM-001")

    with pytest.raises(RuntimeError, match="no recon step"):
        await collect_m1(assessment, [])


# --------------------------------------------------------------------------- #
# run_pipeline + default steps
# --------------------------------------------------------------------------- #


@async_test
async def test_run_pipeline_collects_then_analyzes():
    assessment = make_scope_rules(assessment_id="ASM-001")
    url = "https://shop.lab.local/api/users?id=1"
    steps = [ReconStep("probe_http", "HTTPProbeResult", url, lambda: _probe(url))]

    envelope = await run_pipeline(assessment, steps, trust_policy=make_test_trust_policy())

    assert isinstance(envelope, Module2CorrelationEnvelope)
    assert envelope.output.hypotheses == []


def test_build_default_recon_steps_shapes():
    crawl = build_default_recon_steps("https://x.lab.local", specialized_tool="crawl_web")
    assert [s.tool_id for s in crawl] == ["probe_http", "crawl_web"]

    api = build_default_recon_steps("https://x.lab.local", specialized_tool="parse_api_spec")
    assert api[0].tool_id == "probe_http"
    assert all(s.optional for s in api[1:])
    assert all(s.tool_id == "parse_api_spec" for s in api[1:])

    with pytest.raises(ValueError, match="unknown specialized tool"):
        build_default_recon_steps("https://x.lab.local", specialized_tool="nope")
