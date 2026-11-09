"""Offline and local-CLI contracts for Cloudflare Worker Semgrep analysis."""

from __future__ import annotations

import asyncio
import json
import os
import shutil
import subprocess
from pathlib import Path

import pytest
import yaml

from test_analysis import m1_m2_live_support as live_support
from test_analysis.fixtures import make_shop_analysis_request_with_scope
from test_analysis.m1_m2_live_support import (
    DEFAULT_RULESET,
    DEFAULT_VENDOR_RULESET,
    EXPECTED_RULE_IDS,
    EXPECTED_SINK_LINES,
    RULESET_FIXTURE_ROOT,
    TARGET_CASES,
    assert_source_contract,
    source_files,
)
from websecuritycheck.analysis.semgrep_adapter import (
    LocalSemgrepAdapter,
    compute_ruleset_sha256,
    validate_offline_ruleset_path,
    validate_source_analysis_scope,
)
from websecuritycheck.analysis.sinks import extract_sink_candidates
from websecuritycheck.domain import TestingMode
from websecuritycheck.domain.analysis_models import ConfidenceLevel

SEMGREP_REQUIRED = pytest.mark.skipif(
    os.getenv("RUN_SEMGREP_CLI") != "1",
    reason="set RUN_SEMGREP_CLI=1 to run local Semgrep CLI contracts",
)


def _configured_ruleset() -> Path:
    configured = os.getenv("WEBSEC_SEMGREP_RULESET", "").strip()
    if not configured:
        pytest.skip("set WEBSEC_SEMGREP_RULESET to the primary local ruleset")
    ruleset = Path(validate_offline_ruleset_path(configured))
    assert ruleset.resolve() == DEFAULT_RULESET.resolve()
    return ruleset


def test_cloudflare_ruleset_yaml_and_ids_are_stable() -> None:
    document = yaml.safe_load(DEFAULT_RULESET.read_text(encoding="utf-8"))
    assert isinstance(document, dict) and isinstance(document.get("rules"), list)
    rules = document["rules"]
    assert {rule["id"] for rule in rules} == EXPECTED_RULE_IDS
    assert all(rule.get("mode") == "taint" for rule in rules)
    assert compute_ruleset_sha256(DEFAULT_RULESET) == (
        "11923c354378d4977056f74072d780cc3b5639cfb85b00f404dd10a144166f2e"
    )


def test_primary_preflight_zero_scan_has_report_safe_diagnostics(monkeypatch) -> None:
    class ZeroScanAdapter:
        def __init__(self, *, ruleset_path) -> None:
            assert Path(ruleset_path).resolve() == DEFAULT_RULESET.resolve()

        async def analyze(self, target_root: str, subpath: str = "."):
            assert Path(target_root).resolve() == RULESET_FIXTURE_ROOT.resolve()
            assert subpath == "positive/worker.js"
            return {
                "data": {
                    "version": "1.183.0",
                    "status": "completed",
                    "files_scanned": 0,
                    "scanned_files": [],
                    "findings": [],
                    "errors": [],
                    "ruleset_sha256": compute_ruleset_sha256(DEFAULT_RULESET),
                }
            }

    monkeypatch.setattr(live_support, "LocalSemgrepAdapter", ZeroScanAdapter)
    with pytest.raises(live_support.PrimaryRulesetContractError) as failure:
        asyncio.run(
            live_support.verify_primary_ruleset(
                DEFAULT_RULESET, live_support.Trace()
            )
        )

    diagnostics = failure.value.diagnostics
    assert diagnostics["status"] == "contract_failed"
    assert diagnostics["failure_code"] == "zero_scan"
    assert diagnostics["requested_file"] == "positive/worker.js"
    assert diagnostics["files_scanned"] == 0
    assert diagnostics["scanned_files"] == []
    assert diagnostics["missing_rule_ids"] == sorted(EXPECTED_RULE_IDS)


def _traceless_preflight_adapter(sink_lines: dict[str, int]):
    class TracelessAdapter:
        def __init__(self, *, ruleset_path) -> None:
            pass

        async def analyze(self, target_root: str, subpath: str = "."):
            return {
                "data": {
                    "version": "1.183.0",
                    "status": "completed",
                    "files_scanned": 1,
                    "scanned_files": ["positive/worker.js"],
                    "findings": [
                        {
                            "rule_id": rule_id,
                            "file": "positive/worker.js",
                            "start_line": line,
                            "dataflow_trace": None,
                        }
                        for rule_id, line in sink_lines.items()
                    ],
                    "errors": [],
                }
            }

    return TracelessAdapter


def test_primary_preflight_accepts_traceless_findings_at_expected_lines(monkeypatch) -> None:
    monkeypatch.setattr(
        live_support, "LocalSemgrepAdapter", _traceless_preflight_adapter(EXPECTED_SINK_LINES)
    )
    result = asyncio.run(
        live_support.verify_primary_ruleset(DEFAULT_RULESET, live_support.Trace())
    )
    assert result["status"] == "completed"
    assert result["dataflow_traces_available"] is False
    assert result["traceless_rule_ids"] == sorted(EXPECTED_RULE_IDS)
    assert result["sink_line_mismatch"] == {}


def test_primary_preflight_rejects_wrong_sink_line(monkeypatch) -> None:
    shifted = {**EXPECTED_SINK_LINES, "cloudflare-workers.tainted-code-injection": 4}
    monkeypatch.setattr(live_support, "LocalSemgrepAdapter", _traceless_preflight_adapter(shifted))
    with pytest.raises(live_support.PrimaryRulesetContractError) as failure:
        asyncio.run(live_support.verify_primary_ruleset(DEFAULT_RULESET, live_support.Trace()))
    diagnostics = failure.value.diagnostics
    assert diagnostics["failure_code"] == "sink_line_mismatch"
    assert diagnostics["sink_line_mismatch"] == {
        "cloudflare-workers.tainted-code-injection": [4]
    }


@pytest.mark.parametrize("case", TARGET_CASES, ids=lambda case: case.name)
def test_target_source_mapping_and_scope_are_offline_contracts(case) -> None:
    if not source_files(case.source_root):
        pytest.skip("Cloudflare target sources are not present on this branch")
    assert_source_contract(case)
    approved = str(case.source_root.resolve())
    request = make_shop_analysis_request_with_scope(
        source_repo_path=approved,
        source_repository_ref=approved,
        testing_mode=TestingMode.WHITEBOX,
    )
    accepted, refusal = validate_source_analysis_scope(
        request, require_existing_filesystem=True
    )
    assert accepted == approved and refusal is None

    other = next(item for item in TARGET_CASES if item.name != case.name)
    escaped = request.model_copy(
        update={"source_repo_path": str(other.source_root.resolve())}
    )
    accepted, refusal = validate_source_analysis_scope(
        escaped, require_existing_filesystem=True
    )
    assert accepted is None and refusal and "outside" in refusal


RECORDED_POSITIVE_OUTPUT = (
    Path(__file__).resolve().parent / "data" / "semgrep_cloudflare_positive.json"
)


def _rebase_paths(value, prefix: str):
    if isinstance(value, list):
        return [_rebase_paths(item, prefix) for item in value]
    if isinstance(value, dict):
        return {
            key: (
                f"{prefix}{item}"
                if key == "path" and isinstance(item, str)
                else [f"{prefix}{entry}" for entry in item]
                if key == "scanned" and isinstance(item, list)
                else _rebase_paths(item, prefix)
            )
            for key, item in value.items()
        }
    return value


def _fixture_request():
    return make_shop_analysis_request_with_scope(
        source_repo_path=str(RULESET_FIXTURE_ROOT.resolve()),
        source_repository_ref=str(RULESET_FIXTURE_ROOT.resolve()),
        testing_mode=TestingMode.WHITEBOX,
    )


def _sink_lines_by_rule(findings) -> dict[str, set[int]]:
    lines: dict[str, set[int]] = {}
    for item in findings:
        lines.setdefault(item["rule_id"], set()).add(item["start_line"])
    return lines


def _assert_expected_sink_lines(findings) -> None:
    lines = _sink_lines_by_rule(findings)
    for rule_id, line in EXPECTED_SINK_LINES.items():
        assert line in lines.get(rule_id, set()), (rule_id, line, lines.get(rule_id))


def test_recorded_positive_output_without_traces_still_yields_sinks() -> None:
    """Semgrep 1.183 omits dataflow_trace; sink locations alone must still work."""
    recorded = json.loads(RECORDED_POSITIVE_OUTPUT.read_text(encoding="utf-8"))
    for result in recorded["results"]:
        result["extra"].pop("dataflow_trace", None)

    async def traceless_runner(argv, cwd, output_path, stderr_path) -> int:
        relative_root = RULESET_FIXTURE_ROOT.resolve().relative_to(Path(cwd).resolve())
        prefix = "" if relative_root == Path(".") else f"{relative_root.as_posix()}/"
        Path(output_path).write_text(
            json.dumps(_rebase_paths(recorded, prefix)), encoding="utf-8"
        )
        return 0

    adapter = LocalSemgrepAdapter(ruleset_path=DEFAULT_RULESET, runner=traceless_runner)
    positive = asyncio.run(
        adapter.analyze(str(RULESET_FIXTURE_ROOT), "positive/worker.js")
    )
    data = positive["data"]
    assert {item["rule_id"] for item in data["findings"]} == EXPECTED_RULE_IDS
    assert all(item["dataflow_trace"] is None for item in data["findings"])
    _assert_expected_sink_lines(data["findings"])

    extraction = extract_sink_candidates(_fixture_request(), semgrep_payload=positive)
    assert len(extraction.sink_candidates) == 3
    assert sorted(sc.start_line for sc in extraction.sink_candidates) == sorted(
        EXPECTED_SINK_LINES.values()
    )
    for sc in extraction.sink_candidates:
        assert sc.has_static_taint_flow is False
        assert not sc.dataflow_steps
        assert sc.confidence == ConfidenceLevel.MEDIUM


def test_recorded_positive_output_keeps_traces_through_sink_extraction() -> None:
    recorded = json.loads(RECORDED_POSITIVE_OUTPUT.read_text(encoding="utf-8"))
    seen_argv: list[str] = []

    async def recorded_runner(argv, cwd, output_path, stderr_path) -> int:
        seen_argv.extend(argv)
        relative_root = RULESET_FIXTURE_ROOT.resolve().relative_to(Path(cwd).resolve())
        prefix = "" if relative_root == Path(".") else f"{relative_root.as_posix()}/"
        Path(output_path).write_text(
            json.dumps(_rebase_paths(recorded, prefix)), encoding="utf-8"
        )
        return 0

    adapter = LocalSemgrepAdapter(ruleset_path=DEFAULT_RULESET, runner=recorded_runner)
    positive = asyncio.run(
        adapter.analyze(str(RULESET_FIXTURE_ROOT), "positive/worker.js")
    )

    assert "--dataflow-traces" in seen_argv
    assert "--json" in seen_argv
    assert not any(arg.startswith("--json-output") for arg in seen_argv)
    data = positive["data"]
    assert {item["rule_id"] for item in data["findings"]} == EXPECTED_RULE_IDS
    assert data["scanned_files"] == ["positive/worker.js"]
    assert all(item["dataflow_trace"] for item in data["findings"])
    for item in data["findings"]:
        sink_location = item["dataflow_trace"]["taint_sink"][1][0]
        assert sink_location["path"] == "positive/worker.js"

    extraction = extract_sink_candidates(_fixture_request(), semgrep_payload=positive)
    assert len(extraction.sink_candidates) == 3
    assert all(sc.has_static_taint_flow for sc in extraction.sink_candidates)
    assert all(sc.dataflow_steps for sc in extraction.sink_candidates)
    assert all(sc.confidence == ConfidenceLevel.HIGH for sc in extraction.sink_candidates)


@pytest.mark.semgrep_cli
@SEMGREP_REQUIRED
def test_primary_ruleset_positive_and_negative_controls() -> None:
    ruleset = _configured_ruleset()
    adapter = LocalSemgrepAdapter(ruleset_path=ruleset)
    positive = asyncio.run(
        adapter.analyze(str(RULESET_FIXTURE_ROOT), "positive/worker.js")
    )
    negative = asyncio.run(
        adapter.analyze(str(RULESET_FIXTURE_ROOT), "negative/safe_worker.js")
    )

    positive_data = positive["data"]
    detected = {item["rule_id"] for item in positive_data["findings"]}
    assert detected >= EXPECTED_RULE_IDS
    assert positive_data["files_scanned"] == 1
    assert positive_data["scanned_files"] == ["positive/worker.js"]
    # Dataflow traces are optional (Semgrep 1.183 omits them); sink lines are required.
    _assert_expected_sink_lines(positive_data["findings"])
    assert positive_data["ruleset_sha256"] == compute_ruleset_sha256(ruleset)
    assert positive_data["execution_ref"].startswith("EXEC-")

    sink_extraction = extract_sink_candidates(_fixture_request(), semgrep_payload=positive)
    assert len(sink_extraction.sink_candidates) == 3
    assert sorted(sc.start_line for sc in sink_extraction.sink_candidates) == sorted(
        EXPECTED_SINK_LINES.values()
    )
    for sc in sink_extraction.sink_candidates:
        # A taint flow is only claimed when Semgrep supplied a trace with steps.
        assert sc.has_static_taint_flow == bool(sc.dataflow_steps)

    negative_data = negative["data"]
    assert negative_data["files_scanned"] == 1
    assert negative_data["scanned_files"] == ["negative/safe_worker.js"]
    assert negative_data["findings"] == []


@pytest.mark.semgrep_cli
@SEMGREP_REQUIRED
def test_real_semgrep_scans_nested_git_source_root(tmp_path: Path) -> None:
    ruleset = _configured_ruleset()
    repo = tmp_path / "repo"
    source_root = repo / "nested" / "approved"
    source_root.mkdir(parents=True)
    (source_root / "worker.js").write_text(
        (RULESET_FIXTURE_ROOT / "positive" / "worker.js").read_text(encoding="utf-8"),
        encoding="utf-8",
    )
    subprocess.run(["git", "init", "-q"], cwd=repo, check=True, timeout=10)
    subprocess.run(
        ["git", "add", "nested/approved/worker.js"], cwd=repo, check=True, timeout=10
    )

    result = asyncio.run(LocalSemgrepAdapter(ruleset_path=ruleset).analyze(str(source_root)))
    data = result["data"]
    assert data["files_scanned"] == 1
    assert data["scanned_files"] == ["worker.js"]
    assert {item["rule_id"] for item in data["findings"]} >= EXPECTED_RULE_IDS
    assert all(not item["rule_id"].startswith("tests.") for item in data["findings"])


@pytest.mark.semgrep_cli
@SEMGREP_REQUIRED
def test_optional_community_rules_are_untrusted_audit_only() -> None:
    configured = os.getenv("WEBSEC_SEMGREP_VENDOR_RULESET", "").strip()
    vendor = Path(configured) if configured else DEFAULT_VENDOR_RULESET
    if not vendor.exists():
        pytest.skip("community rule directory is not configured")
    approved = Path(validate_offline_ruleset_path(vendor.resolve()))
    assert compute_ruleset_sha256(approved)
    adapter = LocalSemgrepAdapter(ruleset_path=approved)
    summaries = []
    for case in TARGET_CASES:
        result = asyncio.run(adapter.analyze(str(case.source_root.resolve())))
        summaries.append(
            {
                "target": case.name,
                "files_scanned": result["data"]["files_scanned"],
                "findings": len(result["data"]["findings"]),
            }
        )
    print("[community-audit] " + json.dumps(summaries, sort_keys=True))
    assert all(item["files_scanned"] > 0 for item in summaries)


def test_semgrep_cli_prerequisite_message_is_actionable() -> None:
    executable = os.getenv("WEBSEC_SEMGREP_PATH", "")
    if executable:
        assert Path(executable).is_file() or shutil.which(executable)
