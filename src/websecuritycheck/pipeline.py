"""Deterministic Module 1 -> Module 2 driver.

Productionizes the orchestration the live whitebox harness proved: run the
recon tools, canonicalize each result into one `TargetModel`, then run the
Module 2 analysis pipeline and return the `Module2CorrelationEnvelope` the AI
hypothesis agent consumes.

There is no model and no agent here. Module 1 and Module 2 are deterministic,
so the driver calls their public functions in the order Module 2's handoff
documents rather than letting an LLM decide. The core (`collect_m1`,
`run_module2`, `run_pipeline`) has no dependency on the Layer 6 tool package:
the caller supplies each recon tool as an awaitable via `ReconStep`.
`build_default_recon_steps` is the one place that reaches for the bundled
tools, and it does so with a lazy import so importing this module stays cheap.
"""

from __future__ import annotations

from collections.abc import Awaitable, Callable, Mapping, Sequence
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from .analysis.correlation import (
    CorrelationTrustPolicy,
    Module2CorrelationEnvelope,
    build_correlation_envelope,
    correlate_evidence,
)
from .analysis.cve import extract_cve_candidates
from .analysis.inputs import extract_input_candidates
from .analysis.opengrep_adapter import AsyncSourceAnalysisPort
from .analysis.route_binding import extract_route_bindings
from .analysis.sinks import aextract_sink_candidates
from .domain import (
    ArtifactManifest,
    AssessmentConfig,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from .domain.analysis_models import (
    Module2AnalysisRequest,
    Module2Output,
    validate_module2_handoff,
)
from .recon import process_tool_result
from .recon.evidence import RecordIdAllocator

# Spec paths the default recon tries, in order, for an API target. Each is
# optional: a 404 is skipped, not fatal. Kept identical to the live harness.
OPENAPI_PATHS = ("/openapi.json", "/openapi.yaml", "/swagger.json", "/v3/api-docs")


@dataclass(frozen=True)
class ReconStep:
    """One recon tool call the driver canonicalizes into the TargetModel.

    `call` is an awaitable returning the tool's Layer 6 envelope (a dict).
    A step that may legitimately find nothing - an OpenAPI spec that does not
    exist - sets `optional=True`: any error from `call` then skips the step
    instead of aborting the whole collection.
    """

    tool_id: str
    result_type: str
    target: str
    call: Callable[[], Awaitable[dict[str, Any]]]
    optional: bool = False


def _extract_manifests(envelope: Mapping[str, Any]) -> list[ArtifactManifest]:
    data = envelope.get("data")
    raw = data.get("artifact_manifests") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    return [ArtifactManifest.model_validate(item) for item in raw if isinstance(item, dict)]


async def collect_m1(
    assessment: AssessmentConfig,
    steps: Sequence[ReconStep],
    *,
    target_id: str = "TGT-001",
    source_repo_path: str | None = None,
    allocator: RecordIdAllocator | None = None,
) -> Module2AnalysisRequest:
    """Run recon `steps` and fold each result into one `Module2AnalysisRequest`.

    Each step's envelope is wrapped in a `ToolExecutionResult` and handed to
    `process_tool_result`, which canonicalizes it into the single growing
    `TargetModel` plus its observation and evidence records - the three things
    Module 2 consumes. The shared `RecordIdAllocator` keeps IDs unique across
    steps so one site stays one model.

    A non-optional step whose tool raises aborts the collection (the exception
    propagates); an optional step that raises is skipped. Raises if no step
    produced a model.
    """
    allocator = allocator or RecordIdAllocator()
    target_model = None
    observations: list[Any] = []
    evidence: list[Any] = []
    exec_seq = 1

    for step in steps:
        try:
            envelope = await step.call()
        except Exception:
            if step.optional:
                continue
            raise

        now = datetime.now(UTC)
        execution = ToolExecutionResult(
            execution_id=f"EXEC-{exec_seq:03d}",
            assessment_id=assessment.assessment_id,
            tool_id=step.tool_id,
            target=step.target,
            result_type=step.result_type,
            result_data=envelope,
            artifact_manifests=_extract_manifests(envelope),
            status=ToolExecutionStatus.COMPLETED,
            started_at=now,
            finished_at=now,
            truncated=bool(envelope.get("truncated")),
        )
        exec_seq += 1

        processed = process_tool_result(
            execution,
            current_target_model=target_model,
            assessment=assessment,
            target_id=target_id,
            allocator=allocator,
        )
        target_model = processed.updated_target_model
        observations.extend(processed.observation_records)
        evidence.extend(processed.evidence_records)

    if target_model is None:
        raise RuntimeError("no recon step produced a target model")

    return Module2AnalysisRequest(
        target_model=target_model,
        observations=observations,
        evidence_records=evidence,
        source_repo_path=source_repo_path,
    )


async def run_module2(
    request: Module2AnalysisRequest,
    *,
    trust_policy: CorrelationTrustPolicy,
    analyzer: AsyncSourceAnalysisPort | None = None,
    opengrep_payload: Mapping[str, Any] | None = None,
) -> Module2CorrelationEnvelope:
    """Run the Module 2 analysis pipeline over `request` and seal the envelope.

    The order follows Module 2's handoff section 11: extract inputs, CVEs and
    sinks, bind routes, correlate, then build the envelope. Sink extraction
    reads source either from a live `analyzer` (Opengrep) or from a pre-captured
    `opengrep_payload` - the latter is what makes this testable offline.

    `validate_module2_handoff` runs before the envelope is built: every ID the
    output references is checked back against the request, failing closed.
    """
    input_result = extract_input_candidates(request)
    cve_result = extract_cve_candidates(request)
    sink_result = await aextract_sink_candidates(
        request,
        analyzer=analyzer,
        opengrep_payload=opengrep_payload,
        existing_evidence_ids={item.evidence_id for item in request.evidence_records},
    )
    route_result = extract_route_bindings(
        request,
        existing_evidence_ids={
            item.evidence_id
            for item in [*request.evidence_records, *sink_result.analysis_evidence_records]
        },
    )
    # Route-binding evidence is itself analysis evidence; correlation must see
    # it among the request's records to ground an ENDPOINT_SINK relation.
    request_with_routes = request.model_copy(
        update={
            "evidence_records": [
                *request.evidence_records,
                *route_result.analysis_evidence_records,
            ]
        }
    )

    correlation = correlate_evidence(
        request_with_routes,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        route_binding_artifacts=route_result.route_binding_artifacts,
        trust_policy=trust_policy,
    )

    limitations = sorted(
        {
            *input_result.limitations,
            *sink_result.limitations,
            *cve_result.limitations,
            *route_result.limitations,
            *correlation.limitations,
        }
    )
    warnings = sorted(
        {
            *input_result.warnings,
            *sink_result.warnings,
            *getattr(cve_result, "warnings", ()),
            *route_result.warnings,
            *correlation.warnings,
        }
    )

    output = Module2Output(
        assessment_id=request.target_model.assessment_id,
        target_id=request.target_model.target_id,
        generated_at=datetime.now(UTC),
        analysis_evidence_records=[
            *sink_result.analysis_evidence_records,
            *route_result.analysis_evidence_records,
        ],
        inputs=input_result.inputs,
        sink_candidates=sink_result.sink_candidates,
        cve_candidates=list(cve_result.cve_candidates),
        hypotheses=[],
        limitations=limitations,
        warnings=warnings,
    )
    validate_module2_handoff(output, request)
    return build_correlation_envelope(
        output,
        correlation,
        request,
        expected_trust_policy_fingerprint=trust_policy.fingerprint,
    )


async def run_pipeline(
    assessment: AssessmentConfig,
    steps: Sequence[ReconStep],
    *,
    trust_policy: CorrelationTrustPolicy,
    source_repo_path: str | None = None,
    target_id: str = "TGT-001",
    analyzer: AsyncSourceAnalysisPort | None = None,
    opengrep_payload: Mapping[str, Any] | None = None,
) -> Module2CorrelationEnvelope:
    """Run M1 recon then M2 analysis end to end, returning the sealed envelope."""
    request = await collect_m1(
        assessment,
        steps,
        target_id=target_id,
        source_repo_path=source_repo_path,
    )
    return await run_module2(
        request,
        trust_policy=trust_policy,
        analyzer=analyzer,
        opengrep_payload=opengrep_payload,
    )


def build_default_recon_steps(url: str, *, specialized_tool: str) -> list[ReconStep]:
    """Build the standard recon steps: probe the origin, then one deep tool.

    Mirrors the live harness: `probe_http` first (required), then the one
    specialized tool for the target shape. For `parse_api_spec` the spec URL
    is not known ahead of time, so each candidate path is an optional step and
    the 404s are skipped. Reaches for the Layer 6 tool package lazily so this
    module imports without it.
    """
    from mcp_servers.websec_tools import probes
    from mcp_servers.websec_tools.recon import browser, openapi, zap

    steps: list[ReconStep] = [
        ReconStep("probe_http", "HTTPProbeResult", url, lambda: probes.probe_http(url)),
    ]
    if specialized_tool == "crawl_web":
        steps.append(ReconStep("crawl_web", "ZAP_CRAWL", url, lambda: zap.crawl_web(url)))
    elif specialized_tool == "explore_browser":
        steps.append(
            ReconStep(
                "explore_browser",
                "BROWSER_FLOW",
                url,
                lambda: browser.explore_browser(url, actions=[]),
            )
        )
    elif specialized_tool == "parse_api_spec":
        for suffix in OPENAPI_PATHS:
            candidate = url.rstrip("/") + suffix
            steps.append(
                ReconStep(
                    "parse_api_spec",
                    "OPENAPI_SPEC",
                    candidate,
                    lambda c=candidate: openapi.parse_api_spec(c),
                    optional=True,
                )
            )
    else:
        raise ValueError(f"unknown specialized tool: {specialized_tool!r}")
    return steps
