"""Opt-in WHITEBOX integration test for the deterministic Module 1 -> Module 2 handoff.

The test deliberately has no Agent/model dependency. It combines live, read-only
reconnaissance of the three owned Cloudflare Worker targets with local Semgrep
analysis of the exact source tree mapped to each deployment.
"""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

import pytest

from mcp_servers.websec_tools import probes
from mcp_servers.websec_tools.errors import ToolError
from mcp_servers.websec_tools.recon import browser, openapi, zap
from websecuritycheck.analysis.correlation import (
    ApprovedRulesetEntry,
    ApprovedRuleSpec,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    RuleMode,
    build_correlation_envelope,
    correlate_evidence,
)
from websecuritycheck.analysis.cve import InjectionSubtype, extract_cve_candidates
from websecuritycheck.analysis.inputs import extract_input_candidates
from websecuritycheck.analysis.semgrep_adapter import (
    LocalSemgrepAdapter,
    validate_offline_ruleset_path,
    validate_source_analysis_scope,
)
from websecuritycheck.analysis.sinks import aextract_sink_candidates
from websecuritycheck.domain import (
    ArtifactManifest,
    AssessmentConfig,
    ScopeApprovalRecord,
    TestingMode,
    ToolExecutionResult,
    ToolExecutionStatus,
)
from websecuritycheck.domain.analysis_models import (
    Module2AnalysisRequest,
    Module2Output,
    SinkKind,
    validate_module2_handoff,
)
from websecuritycheck.recon import process_tool_result
from websecuritycheck.recon.evidence import RecordIdAllocator

PROJECT_ROOT = Path(__file__).resolve().parents[2]
TARGETS_ROOT = PROJECT_ROOT / "test-targets" / "cloudflare" / "targets"
DEFAULT_RULESET = (
    PROJECT_ROOT / "tests" / "test_analysis" / "rules" / "cloudflare-workers-injection.yml"
)
RULESET_FIXTURE_ROOT = (
    PROJECT_ROOT / "tests" / "test_analysis" / "sample_sources" / "cloudflare_injection"
)
REPORT_PATH = PROJECT_ROOT / ".pytest_cache" / "reports" / "m1_m2_integration.json"
SOURCE_SUFFIXES = frozenset({".cjs", ".js", ".jsx", ".mjs", ".ts", ".tsx"})
IGNORED_SOURCE_PARTS = frozenset({".git", ".wrangler", "build", "dist", "node_modules"})
OPENAPI_PATHS = ("/openapi.json", "/openapi.yaml", "/swagger.json", "/v3/api-docs")
SENSITIVE_KEYS = ("authorization", "cookie", "password", "secret", "token", "api_key")
EXPECTED_RULE_IDS = frozenset(
    {
        "cloudflare-workers.tainted-code-injection",
        "cloudflare-workers.tainted-d1-sql-injection",
        "cloudflare-workers.tainted-command-injection",
    }
)

# Prevent pytest from treating the imported enum as a test class.
TestingMode.__test__ = False


@dataclass(frozen=True)
class TargetCase:
    name: str
    url: str
    source_root: Path
    assessment_id: str
    specialized_tool: str


TARGET_CASES = (
    TargetCase(
        "basic",
        "https://basic-target.7an6rando.workers.dev",
        TARGETS_ROOT / "basic",
        "ASM-101",
        "crawl_web",
    ),
    TargetCase(
        "spa",
        "https://spa-target.7an6rando.workers.dev",
        TARGETS_ROOT / "spa",
        "ASM-102",
        "explore_browser",
    ),
    TargetCase(
        "api",
        "https://api-target.7an6rando.workers.dev",
        TARGETS_ROOT / "api",
        "ASM-103",
        "parse_api_spec",
    ),
)

pytestmark = [
    pytest.mark.live_tools,
    pytest.mark.skipif(
        os.getenv("RUN_LIVE_M1_M2") != "1",
        reason="set RUN_LIVE_M1_M2=1 to run the authorized WHITEBOX integration test",
    ),
]


class Trace:
    def __init__(self) -> None:
        self.entries: list[dict[str, Any]] = []

    def add(self, target: str, stage: str, status: str, **details: Any) -> None:
        entry = {
            "sequence": len(self.entries) + 1,
            "target": target,
            "stage": stage,
            "status": status,
            **details,
        }
        self.entries.append(entry)
        print("[M1->M2] " + json.dumps(entry, ensure_ascii=False, sort_keys=True))


@dataclass
class M1State:
    target_model: Any = None
    observations: list[Any] = None  # type: ignore[assignment]
    evidence: list[Any] = None  # type: ignore[assignment]
    next_execution: int = 1

    def __post_init__(self) -> None:
        self.observations = []
        self.evidence = []


def _source_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        return []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and path.suffix.lower() in SOURCE_SUFFIXES
        and not any(part in IGNORED_SOURCE_PARTS for part in path.relative_to(root).parts)
    )


def _tracked_source_files(root: Path) -> set[str]:
    relative_root = root.resolve().relative_to(PROJECT_ROOT.resolve()).as_posix()
    completed = subprocess.run(
        [
            "git",
            "-c",
            f"safe.directory={PROJECT_ROOT.as_posix()}",
            "ls-files",
            "--",
            relative_root,
        ],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    if completed.returncode != 0:
        return set()
    prefix = relative_root.rstrip("/") + "/"
    return {
        line.removeprefix(prefix)
        for line in completed.stdout.splitlines()
        if line.startswith(prefix) and Path(line).suffix.lower() in SOURCE_SUFFIXES
    }


def _assessment(case: TargetCase) -> AssessmentConfig:
    hostname = urlsplit(case.url).hostname
    assert hostname is not None
    signature = hashlib.sha256(f"{case.url}|{case.source_root.resolve()}".encode()).hexdigest()
    return AssessmentConfig(
        assessment_id=case.assessment_id,
        target=case.url,
        authorized_scope=[hostname],
        scope_approval=ScopeApprovalRecord(
            is_approved=True,
            approved_by="live-whitebox-integration-test",
            approval_timestamp=datetime(2026, 1, 1, tzinfo=UTC),
            scope_signature_hash=signature,
        ),
        testing_mode=TestingMode.WHITEBOX,
        source_repository_ref=str(case.source_root.resolve()),
    )


def _extract_manifests(envelope: dict[str, Any]) -> list[ArtifactManifest]:
    data = envelope.get("data")
    if not isinstance(data, dict):
        return []
    raw = data.get("artifact_manifests")
    if not isinstance(raw, list):
        return []
    return [ArtifactManifest.model_validate(item) for item in raw if isinstance(item, dict)]


def _process_m1_envelope(
    case: TargetCase,
    assessment: AssessmentConfig,
    state: M1State,
    allocator: RecordIdAllocator,
    *,
    tool_id: str,
    result_type: str,
    invoked_target: str,
    envelope: dict[str, Any],
) -> dict[str, int]:
    now = datetime.now(UTC)
    execution = ToolExecutionResult(
        execution_id=f"EXEC-{state.next_execution:03d}",
        assessment_id=case.assessment_id,
        tool_id=tool_id,
        target=invoked_target,
        result_type=result_type,
        result_data=envelope,
        artifact_manifests=_extract_manifests(envelope),
        status=ToolExecutionStatus.COMPLETED,
        started_at=now,
        finished_at=now,
        truncated=bool(envelope.get("truncated")),
    )
    state.next_execution += 1
    processed = process_tool_result(
        execution,
        current_target_model=state.target_model,
        assessment=assessment,
        target_id=f"TGT-{int(case.assessment_id.split('-')[1]):03d}",
        allocator=allocator,
    )
    state.target_model = processed.updated_target_model
    state.observations.extend(processed.observation_records)
    state.evidence.extend(processed.evidence_records)
    return {
        "endpoints": len(processed.endpoint_updates),
        "observations": len(processed.observation_records),
        "evidence": len(processed.evidence_records),
    }


async def _run_tool(
    case: TargetCase,
    trace: Trace,
    *,
    tool_id: str,
    target: str,
    call: Callable[[], Awaitable[dict[str, Any]]],
) -> dict[str, Any] | None:
    started = time.perf_counter()
    trace.add(case.name, "m1_tool", "started", tool=tool_id, invoked_target=target)
    try:
        result = await call()
    except ToolError as exc:
        trace.add(
            case.name,
            "m1_tool",
            "unavailable",
            tool=tool_id,
            code=exc.code,
            message=exc.message,
            duration_ms=round((time.perf_counter() - started) * 1000, 2),
        )
        return None
    trace.add(
        case.name,
        "m1_tool",
        "completed",
        tool=tool_id,
        summary=str(result.get("summary") or ""),
        truncated=bool(result.get("truncated")),
        duration_ms=round((time.perf_counter() - started) * 1000, 2),
    )
    return result


async def _collect_m1(case: TargetCase, assessment: AssessmentConfig, trace: Trace) -> M1State:
    state = M1State()
    allocator = RecordIdAllocator()

    probe = await _run_tool(
        case,
        trace,
        tool_id="probe_http",
        target=case.url,
        call=lambda: probes.probe_http(case.url),
    )
    if probe is None:
        return state
    counts = _process_m1_envelope(
        case,
        assessment,
        state,
        allocator,
        tool_id="probe_http",
        result_type="HTTPProbeResult",
        invoked_target=case.url,
        envelope=probe,
    )
    trace.add(case.name, "m1_canonicalize", "completed", tool="probe_http", **counts)

    specialized: dict[str, Any] | None = None
    invoked_target = case.url
    result_type = ""
    if case.specialized_tool == "crawl_web":
        result_type = "ZAP_CRAWL"
        specialized = await _run_tool(
            case,
            trace,
            tool_id="crawl_web",
            target=case.url,
            call=lambda: zap.crawl_web(case.url),
        )
    elif case.specialized_tool == "explore_browser":
        result_type = "BROWSER_FLOW"
        specialized = await _run_tool(
            case,
            trace,
            tool_id="explore_browser",
            target=case.url,
            call=lambda: browser.explore_browser(case.url, actions=[]),
        )
    else:
        result_type = "OPENAPI_SPEC"
        for suffix in ("", *OPENAPI_PATHS):
            invoked_target = case.url.rstrip("/") + suffix
            specialized = await _run_tool(
                case,
                trace,
                tool_id="parse_api_spec",
                target=invoked_target,
                call=lambda candidate=invoked_target: openapi.parse_api_spec(candidate),
            )
            if specialized is not None:
                break

    if specialized is not None:
        counts = _process_m1_envelope(
            case,
            assessment,
            state,
            allocator,
            tool_id=case.specialized_tool,
            result_type=result_type,
            invoked_target=invoked_target,
            envelope=specialized,
        )
        trace.add(
            case.name,
            "m1_canonicalize",
            "completed",
            tool=case.specialized_tool,
            **counts,
        )
    return state


def _git_revision() -> str:
    completed = subprocess.run(
        ["git", "-c", f"safe.directory={PROJECT_ROOT.as_posix()}", "rev-parse", "HEAD"],
        cwd=PROJECT_ROOT,
        check=False,
        capture_output=True,
        text=True,
        timeout=5,
    )
    revision = completed.stdout.strip()
    return revision if completed.returncode == 0 and revision else "WORKTREE-UNKNOWN"


def _prerequisites() -> Path:
    executable = os.getenv("WEBSEC_SEMGREP_PATH", "").strip()
    configured_ruleset = os.getenv("WEBSEC_SEMGREP_RULESET", "").strip()
    if not executable or not configured_ruleset:
        pytest.skip("set WEBSEC_SEMGREP_PATH and WEBSEC_SEMGREP_RULESET for WHITEBOX scanning")
    if not (Path(executable).is_file() or shutil.which(executable)):
        pytest.skip(f"configured Semgrep executable is unavailable: {executable}")
    ruleset = Path(validate_offline_ruleset_path(configured_ruleset))
    if ruleset.resolve() != DEFAULT_RULESET.resolve():
        pytest.skip(f"configure WEBSEC_SEMGREP_RULESET={DEFAULT_RULESET.resolve()}")
    return ruleset


def _trust_policy(ruleset_digest: str) -> CorrelationTrustPolicy:
    return CorrelationTrustPolicy(
        approved_rulesets=(
            ApprovedRulesetEntry(
                ruleset_id="cloudflare-workers-injection-v1",
                sha256=ruleset_digest,
                review_ref="LOCAL-INTEGRATION-RULESET-001",
                rules=(
                    ApprovedRuleSpec(
                        rule_id="cloudflare-workers.tainted-code-injection",
                        mode=RuleMode.TAINT,
                        sink_kind=SinkKind.CODE_EVAL,
                        subtype=InjectionSubtype.CODE_INJECTION,
                        cwe_ids=frozenset({"CWE-95"}),
                    ),
                    ApprovedRuleSpec(
                        rule_id="cloudflare-workers.tainted-d1-sql-injection",
                        mode=RuleMode.TAINT,
                        sink_kind=SinkKind.SQL_QUERY,
                        subtype=InjectionSubtype.SQL_INJECTION,
                        cwe_ids=frozenset({"CWE-89"}),
                    ),
                    ApprovedRuleSpec(
                        rule_id="cloudflare-workers.tainted-command-injection",
                        mode=RuleMode.TAINT,
                        sink_kind=SinkKind.OS_COMMAND,
                        subtype=InjectionSubtype.OS_COMMAND_INJECTION,
                        cwe_ids=frozenset({"CWE-78"}),
                    ),
                ),
            ),
        ),
    )


def _redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if any(term in str(key).casefold() for term in SENSITIVE_KEYS)
                else _redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, list):
        return [_redact(item) for item in value]
    if isinstance(value, tuple):
        return [_redact(item) for item in value]
    return value


async def _verify_ruleset(ruleset: Path, trace: Trace) -> dict[str, Any]:
    """Run a positive control so an empty live scan cannot mask broken rules."""
    trace.add("ruleset", "semgrep_positive_control", "started")
    envelope = await LocalSemgrepAdapter(ruleset_path=ruleset).analyze(
        str(RULESET_FIXTURE_ROOT.resolve())
    )
    data = envelope.get("data")
    assert isinstance(data, dict), "Semgrep positive control returned malformed data"
    findings = data.get("findings")
    assert isinstance(findings, list), "Semgrep positive control omitted findings"
    detected_rule_ids = {
        finding.get("rule_id")
        for finding in findings
        if isinstance(finding, dict) and isinstance(finding.get("rule_id"), str)
    }
    missing = sorted(EXPECTED_RULE_IDS - detected_rule_ids)
    assert not missing, f"Semgrep rules failed their positive control: {missing}"
    errors = data.get("errors")
    assert isinstance(errors, list) and not errors, (
        f"Semgrep positive control reported errors: {errors!r}"
    )
    result = {
        "status": data.get("status"),
        "semgrep_version": data.get("version"),
        "files_scanned": data.get("files_scanned"),
        "finding_count": len(findings),
        "detected_rule_ids": sorted(detected_rule_ids),
        "fixture_root": str(RULESET_FIXTURE_ROOT.resolve()),
    }
    trace.add("ruleset", "semgrep_positive_control", "completed", **result)
    return result


async def _run_integration(ruleset: Path) -> tuple[dict[str, Any], list[str], int]:
    trace = Trace()
    revision = _git_revision()
    ruleset_digest = hashlib.sha256(ruleset.read_bytes()).hexdigest()
    policy = _trust_policy(ruleset_digest)
    report: dict[str, Any] = {
        "schema": "websecuritycheck.m1-m2-whitebox-integration.v1",
        "generated_at": datetime.now(UTC).isoformat(),
        "source_revision": revision,
        "ruleset": {"path": str(ruleset), "sha256": ruleset_digest},
        "targets": [],
        "trace": trace.entries,
    }
    failures: list[str] = []
    completed_targets = 0

    report["ruleset"]["positive_control"] = await _verify_ruleset(ruleset, trace)

    for case in TARGET_CASES:
        target_report: dict[str, Any] = {
            "name": case.name,
            "url": case.url,
            "source_root": str(case.source_root.resolve()),
        }
        report["targets"].append(target_report)
        trace.add(case.name, "target", "started", url=case.url)
        try:
            files = _source_files(case.source_root)
            if not files:
                raise AssertionError(
                    f"{case.name}: no JavaScript/TypeScript source found "
                    "outside ignored directories"
                )
            relative_files = [
                path.relative_to(case.source_root).as_posix() for path in files
            ]
            untracked = sorted(set(relative_files) - _tracked_source_files(case.source_root))
            assert not untracked, f"{case.name}: source files are not tracked by Git: {untracked}"
            target_report["source_files"] = relative_files
            assessment = _assessment(case)
            assert assessment.testing_mode is TestingMode.WHITEBOX

            state = await _collect_m1(case, assessment, trace)
            if state.target_model is None:
                target_report["status"] = "live_target_unavailable"
                trace.add(case.name, "target", "unavailable", reason="base HTTP probe failed")
                continue

            request = Module2AnalysisRequest(
                target_model=state.target_model,
                observations=state.observations,
                evidence_records=state.evidence,
                source_repo_path=str(case.source_root.resolve()),
            )
            authorized, refusal = validate_source_analysis_scope(
                request, require_existing_filesystem=True
            )
            assert refusal is None and authorized == str(case.source_root.resolve())
            other = next(item for item in TARGET_CASES if item.name != case.name)
            escaped = request.model_copy(
                update={"source_repo_path": str(other.source_root.resolve())}
            )
            escaped_path, escaped_reason = validate_source_analysis_scope(
                escaped, require_existing_filesystem=True
            )
            assert escaped_path is None and escaped_reason and "outside" in escaped_reason
            trace.add(
                case.name,
                "m2_request",
                "completed",
                endpoints=len(request.target_model.endpoints),
                observations=len(request.observations),
                evidence=len(request.evidence_records),
                source_root=authorized,
            )

            input_result = extract_input_candidates(request)
            cve_result = extract_cve_candidates(request)
            sink_result = await aextract_sink_candidates(
                request,
                analyzer=LocalSemgrepAdapter(ruleset_path=ruleset),
                existing_evidence_ids={item.evidence_id for item in request.evidence_records},
            )
            semgrep_failed = [
                item for item in sink_result.limitations if "Semgrep static analysis failed" in item
            ]
            assert not semgrep_failed, "; ".join(semgrep_failed)
            trace.add(
                case.name,
                "m2_extract",
                "completed",
                inputs=len(input_result.inputs),
                sinks=len(sink_result.sink_candidates),
                cves=len(cve_result.cve_candidates),
                semgrep_evidence=len(sink_result.analysis_evidence_records),
                limitations=[
                    *input_result.limitations,
                    *sink_result.limitations,
                    *cve_result.limitations,
                ],
            )

            correlation = correlate_evidence(
                request,
                input_result=input_result,
                sink_result=sink_result,
                cve_result=cve_result,
                route_binding_artifacts=(),
                trust_policy=policy,
            )
            forbidden_verified = [
                record.correlation_id
                for record in correlation.records
                if record.kind in {CorrelationKind.INPUT_SINK, CorrelationKind.ENDPOINT_SINK}
                and record.status is CorrelationStatus.VERIFIED
            ]
            assert not forbidden_verified, (
                "endpoint/sink correlation cannot be VERIFIED without a route binding: "
                f"{forbidden_verified}"
            )

            limitations = sorted(
                {
                    *input_result.limitations,
                    *sink_result.limitations,
                    *cve_result.limitations,
                    *correlation.limitations,
                }
            )
            warnings = sorted(
                {*input_result.warnings, *sink_result.warnings, *correlation.warnings}
            )
            output = Module2Output(
                assessment_id=request.target_model.assessment_id,
                target_id=request.target_model.target_id,
                generated_at=datetime.now(UTC),
                analysis_evidence_records=sink_result.analysis_evidence_records,
                inputs=input_result.inputs,
                sink_candidates=sink_result.sink_candidates,
                cve_candidates=list(cve_result.cve_candidates),
                hypotheses=[],
                limitations=limitations,
                warnings=warnings,
            )
            validate_module2_handoff(output, request)
            envelope = build_correlation_envelope(
                output,
                correlation,
                request,
                expected_trust_policy_fingerprint=policy.fingerprint,
            )
            target_report.update(
                {
                    "status": "completed",
                    "m1": {
                        "target_model": request.target_model.model_dump(mode="json"),
                        "observations": [
                            item.model_dump(mode="json") for item in request.observations
                        ],
                        "evidence": [
                            item.model_dump(mode="json") for item in request.evidence_records
                        ],
                    },
                    "m2": envelope.model_dump(mode="json"),
                }
            )
            completed_targets += 1
            trace.add(
                case.name,
                "handoff",
                "completed",
                inputs=len(output.inputs),
                sinks=len(output.sink_candidates),
                cves=len(output.cve_candidates),
                correlations=len(correlation.records),
                blocking_dependencies=list(correlation.coverage.blocking_dependencies),
            )
            trace.add(case.name, "target", "completed")
        except Exception as exc:  # keep the combined report when one contract fails
            message = f"{case.name}: {type(exc).__name__}: {exc}"
            failures.append(message)
            target_report["status"] = "contract_failed"
            target_report["error"] = message
            trace.add(case.name, "target", "contract_failed", error=message)

    return report, failures, completed_targets


def test_live_whitebox_m1_to_m2_handoff() -> None:
    missing_source = [case.name for case in TARGET_CASES if not _source_files(case.source_root)]
    assert not missing_source, (
        "tracked JavaScript/TypeScript source is missing for target(s): "
        + ", ".join(missing_source)
    )
    untracked_source = {
        case.name: sorted(
            path.relative_to(case.source_root).as_posix()
            for path in _source_files(case.source_root)
            if path.relative_to(case.source_root).as_posix()
            not in _tracked_source_files(case.source_root)
        )
        for case in TARGET_CASES
    }
    untracked_source = {name: paths for name, paths in untracked_source.items() if paths}
    assert not untracked_source, f"source files must be tracked by Git: {untracked_source}"
    ruleset = _prerequisites()
    report, failures, completed_targets = asyncio.run(_run_integration(ruleset))
    safe_report = _redact(report)
    REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
    REPORT_PATH.write_text(
        json.dumps(safe_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    print(f"[M1->M2] report={REPORT_PATH}")
    serialized = json.dumps(safe_report, ensure_ascii=False).casefold()
    assert "secret-token" not in serialized
    assert not failures, "\n".join(failures)
    if completed_targets == 0:
        pytest.skip("all three authorized live targets were temporarily unavailable")
