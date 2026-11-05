"""Support harness for deterministic and live M1 -> M2 WHITEBOX tests."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
import subprocess
import time
from collections.abc import Awaitable, Callable
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

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
    compute_ruleset_sha256,
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
RULES_ROOT = PROJECT_ROOT / "tests" / "test_analysis" / "rules"
DEFAULT_RULESET = RULES_ROOT / "cloudflare-workers-injection.yml"
DEFAULT_VENDOR_RULESET = RULES_ROOT / "vendor" / "semgrep-community"
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


class LiveDependencyError(RuntimeError):
    """An authorized live dependency is temporarily unavailable."""


class PrimaryRulesetContractError(AssertionError):
    """Primary ruleset preflight failed with report-safe diagnostics."""

    def __init__(self, message: str, diagnostics: dict[str, Any]) -> None:
        super().__init__(message)
        self.diagnostics = diagnostics


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
    observations: list[Any] = field(default_factory=list)
    evidence: list[Any] = field(default_factory=list)
    next_execution: int = 1


class IntegrationReport:
    def __init__(self, ruleset: Path) -> None:
        self.trace = Trace()
        self.data: dict[str, Any] = {
            "schema": "websecuritycheck.m1-m2-whitebox-integration.v2",
            "generated_at": datetime.now(UTC).isoformat(),
            "source_revision": git_revision(PROJECT_ROOT),
            "ruleset": {
                "path": str(ruleset.resolve()),
                "sha256": compute_ruleset_sha256(ruleset),
            },
            "preflight": {},
            "supplemental": {"community_rules": {"status": "not_configured"}},
            "targets": [],
            "trace": self.trace.entries,
        }

    def record_target(self, result: dict[str, Any]) -> None:
        targets = self.data["targets"]
        targets[:] = [item for item in targets if item.get("name") != result.get("name")]
        targets.append(result)
        targets.sort(key=lambda item: [case.name for case in TARGET_CASES].index(item["name"]))

    def write(self) -> None:
        self.data["generated_at"] = datetime.now(UTC).isoformat()
        safe_report = redact(self.data)
        REPORT_PATH.parent.mkdir(parents=True, exist_ok=True)
        temporary = REPORT_PATH.with_suffix(".json.tmp")
        temporary.write_text(
            json.dumps(safe_report, ensure_ascii=False, indent=2, sort_keys=True) + "\n",
            encoding="utf-8",
        )
        os.replace(temporary, REPORT_PATH)
        print(f"[M1->M2] report={REPORT_PATH}")


def source_files(root: Path) -> list[Path]:
    if not root.is_dir() or root.is_symlink():
        return []
    return sorted(
        path
        for path in root.rglob("*")
        if path.is_file()
        and not path.is_symlink()
        and path.suffix.lower() in SOURCE_SUFFIXES
        and not any(part in IGNORED_SOURCE_PARTS for part in path.relative_to(root).parts)
    )


def tracked_source_files(root: Path) -> set[str]:
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


def assert_source_contract(case: TargetCase) -> list[str]:
    assert case.source_root.is_dir(), f"{case.name}: source root does not exist"
    assert not case.source_root.is_symlink(), f"{case.name}: source root must not be a symlink"
    files = source_files(case.source_root)
    assert files, f"{case.name}: no JavaScript/TypeScript source found"
    relative = [path.relative_to(case.source_root).as_posix() for path in files]
    untracked = sorted(set(relative) - tracked_source_files(case.source_root))
    assert not untracked, f"{case.name}: source files are not tracked by Git: {untracked}"
    return relative


def assessment(case: TargetCase) -> AssessmentConfig:
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


def resolve_primary_ruleset() -> Path:
    executable = os.getenv("WEBSEC_SEMGREP_PATH", "").strip()
    configured = os.getenv("WEBSEC_SEMGREP_RULESET", "").strip()
    if not executable or not configured:
        raise LiveDependencyError(
            "set WEBSEC_SEMGREP_PATH and WEBSEC_SEMGREP_RULESET for WHITEBOX scanning"
        )
    if not (Path(executable).is_file() or shutil.which(executable)):
        raise LiveDependencyError(f"Semgrep executable is unavailable: {executable}")
    ruleset = Path(validate_offline_ruleset_path(configured))
    if ruleset.resolve() != DEFAULT_RULESET.resolve():
        raise AssertionError(f"configure WEBSEC_SEMGREP_RULESET={DEFAULT_RULESET.resolve()}")
    return ruleset


def git_revision(root: Path) -> str | None:
    try:
        completed = subprocess.run(
            ["git", "-c", f"safe.directory={root.as_posix()}", "rev-parse", "HEAD"],
            cwd=root,
            check=False,
            capture_output=True,
            text=True,
            timeout=5,
        )
    except (OSError, subprocess.TimeoutExpired):
        return None
    revision = completed.stdout.strip()
    return revision if completed.returncode == 0 and revision else None


def ruleset_file_digests(root: Path) -> dict[str, str]:
    """Return conventional per-file hashes for an optional vendored ruleset."""
    base = root if root.is_dir() else root.parent
    candidates = [root] if root.is_file() else sorted(root.rglob("*"))
    return {
        candidate.relative_to(base).as_posix(): hashlib.sha256(
            candidate.read_bytes()
        ).hexdigest()
        for candidate in candidates
        if candidate.is_file() and candidate.suffix.lower() in {".json", ".yaml", ".yml"}
    }


def trust_policy(ruleset_digest: str) -> CorrelationTrustPolicy:
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


def redact(value: Any) -> Any:
    if isinstance(value, dict):
        return {
            key: (
                "<redacted>"
                if any(term in str(key).casefold() for term in SENSITIVE_KEYS)
                else redact(item)
            )
            for key, item in value.items()
        }
    if isinstance(value, (list, tuple)):
        return [redact(item) for item in value]
    return value


def _extract_manifests(envelope: dict[str, Any]) -> list[ArtifactManifest]:
    data = envelope.get("data")
    raw = data.get("artifact_manifests") if isinstance(data, dict) else None
    if not isinstance(raw, list):
        return []
    return [ArtifactManifest.model_validate(item) for item in raw if isinstance(item, dict)]


def _process_m1_envelope(
    case: TargetCase,
    config: AssessmentConfig,
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
        assessment=config,
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
    allow_absence: bool = False,
) -> dict[str, Any] | None:
    started = time.perf_counter()
    trace.add(case.name, "m1_tool", "started", tool=tool_id, invoked_target=target)
    try:
        result = await call()
    except ToolError as exc:
        duration_ms = round((time.perf_counter() - started) * 1000, 2)
        trace.add(
            case.name,
            "m1_tool",
            "unavailable",
            tool=tool_id,
            code=exc.code,
            message=exc.message,
            duration_ms=duration_ms,
        )
        if allow_absence and exc.code in {"E_HTTP", "E_PARSE", "E_UNSUPPORTED_INPUT"}:
            return None
        if exc.code in {"E_TOOL_UNAVAILABLE", "E_CONNECT", "E_TIMEOUT"}:
            raise LiveDependencyError(f"{tool_id}: {exc.code}: {exc.message}") from exc
        raise
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


async def collect_m1(case: TargetCase, config: AssessmentConfig, trace: Trace) -> M1State:
    state = M1State()
    allocator = RecordIdAllocator()
    probe = await _run_tool(
        case,
        trace,
        tool_id="probe_http",
        target=case.url,
        call=lambda: probes.probe_http(case.url),
    )
    assert probe is not None
    counts = _process_m1_envelope(
        case,
        config,
        state,
        allocator,
        tool_id="probe_http",
        result_type="HTTPProbeResult",
        invoked_target=case.url,
        envelope=probe,
    )
    trace.add(case.name, "m1_canonicalize", "completed", tool="probe_http", **counts)

    specialized: dict[str, Any] | None
    invoked_target = case.url
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
        specialized = None
        for suffix in OPENAPI_PATHS:
            invoked_target = case.url.rstrip("/") + suffix
            specialized = await _run_tool(
                case,
                trace,
                tool_id="parse_api_spec",
                target=invoked_target,
                call=lambda candidate=invoked_target: openapi.parse_api_spec(candidate),
                allow_absence=True,
            )
            if specialized is not None:
                break
        assert specialized is not None, "API target did not expose a supported OpenAPI document"

    assert specialized is not None
    counts = _process_m1_envelope(
        case,
        config,
        state,
        allocator,
        tool_id=case.specialized_tool,
        result_type=result_type,
        invoked_target=invoked_target,
        envelope=specialized,
    )
    trace.add(case.name, "m1_canonicalize", "completed", tool=case.specialized_tool, **counts)
    return state


async def verify_primary_ruleset(ruleset: Path, trace: Trace) -> dict[str, Any]:
    started = time.perf_counter()
    requested_file = "positive/worker.js"
    trace.add(
        "ruleset",
        "semgrep_positive_control",
        "started",
        requested_file=requested_file,
    )
    diagnostics: dict[str, Any] = {
        "status": "contract_failed",
        "requested_file": requested_file,
        "expected_rule_ids": sorted(EXPECTED_RULE_IDS),
        "ruleset_sha256": compute_ruleset_sha256(ruleset),
    }

    def fail(code: str, message: str) -> None:
        diagnostics["failure_code"] = code
        diagnostics["error"] = message
        diagnostics["duration_ms"] = round((time.perf_counter() - started) * 1000, 2)
        trace.add(
            "ruleset",
            "semgrep_positive_control",
            "contract_failed",
            **{key: value for key, value in diagnostics.items() if key != "status"},
        )
        raise PrimaryRulesetContractError(f"{code}: {message}", dict(diagnostics))

    try:
        envelope = await LocalSemgrepAdapter(ruleset_path=ruleset).analyze(
            str(RULESET_FIXTURE_ROOT.resolve()), subpath=requested_file
        )
    except Exception as exc:
        fail("execution_failed", f"{type(exc).__name__}: {exc}")

    if not isinstance(envelope, dict):
        fail("malformed_envelope", "Semgrep positive control returned malformed data")
    data = envelope.get("data")
    if not isinstance(data, dict):
        fail("malformed_envelope", "Semgrep positive control returned malformed data")

    findings = data.get("findings")
    if not isinstance(findings, list):
        fail("malformed_findings", "Semgrep positive control omitted findings")

    errors = data.get("errors")
    scanned = data.get("scanned_files")
    detected = {
        item.get("rule_id")
        for item in findings
        if isinstance(item, dict) and isinstance(item.get("rule_id"), str)
    }
    missing = sorted(EXPECTED_RULE_IDS - detected)
    missing_trace = sorted(
        str(item.get("rule_id"))
        for item in findings
        if isinstance(item, dict)
        and item.get("rule_id") in EXPECTED_RULE_IDS
        and not item.get("dataflow_trace")
    )
    diagnostics.update(
        {
            "semgrep_version": data.get("version"),
            "files_scanned": data.get("files_scanned"),
            "scanned_files": scanned,
            "errors": errors,
            "finding_count": len(findings),
            "detected_rule_ids": sorted(detected),
            "missing_rule_ids": missing,
            "missing_trace_rule_ids": missing_trace,
            "ruleset_sha256": data.get("ruleset_sha256") or diagnostics["ruleset_sha256"],
            "execution_ref": data.get("execution_ref"),
            "source_revision": data.get("source_revision"),
        }
    )
    if not isinstance(errors, list):
        fail("malformed_errors", "Semgrep positive control omitted its errors list")
    if errors:
        fail("semgrep_error", f"Semgrep positive control reported errors: {errors!r}")
    if data.get("files_scanned") == 0:
        fail("zero_scan", "Semgrep positive control scanned zero files")
    if data.get("files_scanned") != 1:
        fail(
            "scan_count_mismatch",
            f"expected one scanned file, got {data.get('files_scanned')!r}",
        )
    if not isinstance(scanned, list) or requested_file not in scanned:
        fail(
            "missing_scanned_file",
            f"expected {requested_file!r} in scanned_files, got {scanned!r}",
        )
    if missing:
        fail(
            "missing_rule",
            f"missing={missing!r}, detected={sorted(detected)!r}",
        )
    if missing_trace:
        fail("missing_trace", f"rules without dataflow trace: {missing_trace!r}")

    result = {
        **diagnostics,
        "status": "completed",
        "semgrep_version": data.get("version"),
        "duration_ms": round((time.perf_counter() - started) * 1000, 2),
    }
    result.pop("failure_code", None)
    result.pop("error", None)
    trace.add(
        "ruleset",
        "semgrep_positive_control",
        "completed",
        **{key: value for key, value in result.items() if key != "status"},
    )
    return result


async def audit_community_rules(report: IntegrationReport) -> None:
    configured = os.getenv("WEBSEC_SEMGREP_VENDOR_RULESET", "").strip()
    candidate = Path(configured) if configured else DEFAULT_VENDOR_RULESET
    if not candidate.exists():
        report.data["supplemental"]["community_rules"] = {"status": "not_configured"}
        return
    try:
        approved = Path(validate_offline_ruleset_path(candidate.resolve()))
    except ToolError as exc:
        report.data["supplemental"]["community_rules"] = {
            "status": "invalid",
            "error": f"{exc.code}: {exc.message}",
            "trusted_for_m2": False,
        }
        return
    audit: dict[str, Any] = {
        "status": "completed",
        "path": str(approved),
        "sha256": compute_ruleset_sha256(approved),
        "file_sha256": ruleset_file_digests(approved),
        "upstream_revision": (
            os.getenv("WEBSEC_SEMGREP_VENDOR_REVISION", "").strip()
            or git_revision(approved)
        ),
        "trusted_for_m2": False,
        "targets": [],
    }
    for case in TARGET_CASES:
        try:
            payload = await LocalSemgrepAdapter(ruleset_path=approved).analyze(
                str(case.source_root.resolve())
            )
        except ToolError as exc:
            audit["targets"].append(
                {
                    "name": case.name,
                    "status": "failed",
                    "error": f"{exc.code}: {exc.message}",
                }
            )
            continue
        data = payload.get("data") if isinstance(payload.get("data"), dict) else {}
        audit["targets"].append(
            {
                "name": case.name,
                "status": "completed",
                "files_scanned": data.get("files_scanned"),
                "scanned_files": data.get("scanned_files"),
                "findings": data.get("findings"),
                "errors": data.get("errors"),
            }
        )
    report.data["supplemental"]["community_rules"] = audit


async def run_target(case: TargetCase, ruleset: Path, trace: Trace) -> dict[str, Any]:
    started = time.perf_counter()
    expected_files = assert_source_contract(case)
    target_report: dict[str, Any] = {
        "name": case.name,
        "url": case.url,
        "source_root": str(case.source_root.resolve()),
        "source_files": expected_files,
    }
    trace.add(case.name, "target", "started", url=case.url)
    config = assessment(case)
    assert config.testing_mode is TestingMode.WHITEBOX
    state = await collect_m1(case, config, trace)
    assert state.target_model is not None
    request = Module2AnalysisRequest(
        target_model=state.target_model,
        observations=state.observations,
        evidence_records=state.evidence,
        source_repo_path=str(case.source_root.resolve()),
    )
    authorized, refusal = validate_source_analysis_scope(request, require_existing_filesystem=True)
    assert refusal is None and authorized == str(case.source_root.resolve())
    other = next(item for item in TARGET_CASES if item.name != case.name)
    escaped = request.model_copy(update={"source_repo_path": str(other.source_root.resolve())})
    escaped_path, escaped_reason = validate_source_analysis_scope(
        escaped, require_existing_filesystem=True
    )
    assert escaped_path is None and escaped_reason and "outside" in escaped_reason

    input_result = extract_input_candidates(request)
    cve_result = extract_cve_candidates(request)
    sink_result = await aextract_sink_candidates(
        request,
        analyzer=LocalSemgrepAdapter(ruleset_path=ruleset),
        existing_evidence_ids={item.evidence_id for item in request.evidence_records},
    )
    failures = [
        item for item in sink_result.limitations if "Semgrep static analysis failed" in item
    ]
    assert not failures, "; ".join(failures)
    assert "SEMGREP_SCAN_EMPTY" not in sink_result.limitations
    missing_scanned = sorted(set(expected_files) - set(sink_result.scanned_files))
    assert not missing_scanned, f"Semgrep omitted approved source files: {missing_scanned}"

    policy = trust_policy(compute_ruleset_sha256(ruleset))
    correlation = correlate_evidence(
        request,
        input_result=input_result,
        sink_result=sink_result,
        cve_result=cve_result,
        route_binding_artifacts=(),
        trust_policy=policy,
    )
    forbidden = [
        record.correlation_id
        for record in correlation.records
        if record.kind in {CorrelationKind.INPUT_SINK, CorrelationKind.ENDPOINT_SINK}
        and record.status is CorrelationStatus.VERIFIED
    ]
    assert not forbidden, f"correlation cannot be VERIFIED without route binding: {forbidden}"

    limitations = sorted(
        {
            *input_result.limitations,
            *sink_result.limitations,
            *cve_result.limitations,
            *correlation.limitations,
        }
    )
    warnings = sorted({*input_result.warnings, *sink_result.warnings, *correlation.warnings})
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
            "duration_ms": round((time.perf_counter() - started) * 1000, 2),
            "scan": {
                "semgrep_version": sink_result.semgrep_version,
                "scanned_files": sink_result.scanned_files,
                "missing_files": missing_scanned,
                "ruleset_sha256": sink_result.ruleset_sha256,
                "execution_ref": sink_result.execution_ref,
                "source_revision": sink_result.source_revision,
            },
            "m1": {
                "target_model": request.target_model.model_dump(mode="json"),
                "observations": [item.model_dump(mode="json") for item in request.observations],
                "evidence": [item.model_dump(mode="json") for item in request.evidence_records],
            },
            "m2": envelope.model_dump(mode="json"),
        }
    )
    trace.add(
        case.name,
        "target",
        "completed",
        inputs=len(output.inputs),
        sinks=len(output.sink_candidates),
        cves=len(output.cve_candidates),
        correlations=len(correlation.records),
        scanned_files=len(sink_result.scanned_files),
    )
    return target_report


__all__ = [
    "DEFAULT_RULESET",
    "DEFAULT_VENDOR_RULESET",
    "EXPECTED_RULE_IDS",
    "REPORT_PATH",
    "RULESET_FIXTURE_ROOT",
    "TARGET_CASES",
    "IntegrationReport",
    "LiveDependencyError",
    "PrimaryRulesetContractError",
    "TargetCase",
    "assert_source_contract",
    "assessment",
    "audit_community_rules",
    "resolve_primary_ruleset",
    "run_target",
    "source_files",
    "verify_primary_ruleset",
]
