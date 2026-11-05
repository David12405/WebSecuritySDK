"""Unit and integration test suites for Module 2 Semgrep Sink Extraction (M2-T03)."""

from __future__ import annotations

import asyncio
import json
import tempfile
from functools import wraps
from pathlib import Path
from typing import Any

import pytest

from mcp_servers.websec_tools.errors import ToolError
from test_analysis.fixtures import (
    FIXED_TIME,
    make_semgrep_envelope,
    make_semgrep_finding,
    make_shop_analysis_request_with_scope,
)
from websecuritycheck.analysis.inputs import extract_input_candidates
from websecuritycheck.analysis.semgrep_adapter import (
    LocalSemgrepAdapter,
    compute_ruleset_sha256,
    validate_offline_ruleset_path,
    validate_source_analysis_scope,
)
from websecuritycheck.analysis.sinks import (
    aextract_sink_candidates,
    classify_sink_kind,
    extract_sink_candidates,
    is_non_sink_finding,
    verify_sink_evidence_integrity,
)
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    ExpectedSignal,
    Hypothesis,
    Module2Output,
    SinkKind,
    SinkRelationship,
    TestingMode,
    ValidationCapability,
    ValidationCapabilityRequirement,
    VulnerabilityCategory,
    validate_module2_handoff,
)


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix="m2_t03_") as td:
        yield Path(td).resolve()


# 1. test_parse_valid_semgrep_envelope_and_raw_cli_json
def test_parse_valid_semgrep_envelope_and_raw_cli_json():
    req = make_shop_analysis_request_with_scope()

    # Format 1: Envelope
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(
                rule_id="python.django.security.injection.sql-injection",
                file="app/products.py",
                start_line=28,
                end_line=28,
                start_column=5,
                end_column=45,
                snippet="cursor.execute(query)",
            )
        ]
    )
    res1 = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res1.sink_candidates) == 1
    assert len(res1.analysis_evidence_records) == 1
    assert len(res1.artifact_manifests) == 1
    sc1 = res1.sink_candidates[0]
    assert sc1.sink_id == "SNK-001"
    assert sc1.sink_kind == SinkKind.SQL_QUERY
    assert sc1.file_path == "app/products.py"
    assert sc1.start_line == 28

    # Format 2: Raw Semgrep CLI JSON
    raw_cli = {
        "version": "1.90.0",
        "results": [
            {
                "check_id": "python.flask.security.xss",
                "path": "app/views.py",
                "start": {"line": 15, "col": 10},
                "end": {"line": 15, "col": 35},
                "extra": {
                    "message": "Direct HTML output",
                    "severity": "WARNING",
                    "lines": "response.write(html)",
                    "metadata": {"cwe": ["CWE-79"]},
                },
            }
        ],
        "errors": [],
    }
    res2 = extract_sink_candidates(req, semgrep_payload=raw_cli)
    assert len(res2.sink_candidates) == 1
    sc2 = res2.sink_candidates[0]
    assert sc2.sink_kind == SinkKind.HTML_OUTPUT
    assert sc2.file_path == "app/views.py"
    assert sc2.start_line == 15


# 2. test_empty_semgrep_findings_produces_no_orphan_evidence
def test_empty_semgrep_findings_produces_no_orphan_evidence():
    req = make_shop_analysis_request_with_scope()
    envelope = make_semgrep_envelope([])
    res = extract_sink_candidates(req, semgrep_payload=envelope)
    assert res.sink_candidates == []
    assert res.analysis_evidence_records == []
    assert res.artifact_manifests == []
    assert res.sink_metadata == {}
    assert res.limitations == []
    assert res.warnings == []

    raw_cli = {"results": [], "errors": []}
    res_cli = extract_sink_candidates(req, semgrep_payload=raw_cli)
    assert res_cli.sink_candidates == []
    assert res_cli.analysis_evidence_records == []


def test_semgrep_scan_coverage_and_provenance_reach_evidence():
    request = make_shop_analysis_request_with_scope()
    payload = make_semgrep_envelope([make_semgrep_finding()])
    payload["data"].update(
        {
            "scanned_files": ["app/routes.py"],
            "ruleset_sha256": "a" * 64,
            "source_revision": "revision-1",
            "execution_ref": "EXEC-123",
        }
    )
    result = extract_sink_candidates(request, semgrep_payload=payload)
    assert result.scanned_files == ["app/routes.py"]
    assert result.ruleset_sha256 == "a" * 64
    assert result.source_revision == "revision-1"
    assert result.execution_ref == "EXEC-123"
    assert result.analysis_evidence_records[0].execution_ref == "EXEC-123"
    assert result.analysis_evidence_records[0].provenance["ruleset_sha256"] == "a" * 64


def test_zero_file_semgrep_scan_is_explicit_limitation():
    request = make_shop_analysis_request_with_scope()
    payload = make_semgrep_envelope([])
    payload["data"]["files_scanned"] = 0
    payload["data"]["scanned_files"] = []
    result = extract_sink_candidates(request, semgrep_payload=payload)
    assert "SEMGREP_SCAN_EMPTY" in result.limitations


# 3. test_semgrep_execution_failure_and_malformed_json_fail_closed
@async_test
async def test_semgrep_execution_failure_and_malformed_json_fail_closed(tmp_path: Path):
    repo_dir = tmp_path / "repo"
    repo_dir.mkdir()
    req = make_shop_analysis_request_with_scope(
        source_repo_path=str(repo_dir),
        source_repository_ref=str(repo_dir),
    )

    class FailingPort:
        async def analyze(self, target_root: str, subpath: str = ".") -> dict[str, Any]:
            raise ToolError("E_TOOL_UNAVAILABLE", "Semgrep binary missing")

    res = await aextract_sink_candidates(req, analyzer=FailingPort())
    assert res.sink_candidates == []
    assert res.analysis_evidence_records == []
    assert any("E_TOOL_UNAVAILABLE" in lim for lim in res.limitations)

    class TimeoutPort:
        async def analyze(self, target_root: str, subpath: str = ".") -> dict[str, Any]:
            raise ToolError("E_TIMEOUT", "Semgrep timed out after 120s")

    res_timeout = await aextract_sink_candidates(req, analyzer=TimeoutPort())
    assert any("E_TIMEOUT" in lim for lim in res_timeout.limitations)

    # Malformed JSON payload
    malformed = {"unexpected": 123}
    res_malformed = extract_sink_candidates(req, semgrep_payload=malformed)
    assert res_malformed.sink_candidates == []
    assert any("Malformed Semgrep output payload" in lim for lim in res_malformed.limitations)


# 4. test_authorization_and_scope_guard_blocks_unapproved_or_bypass_attempts
def test_authorization_and_scope_guard_blocks_unapproved_or_bypass_attempts():
    # 4a: BLACKBOX mode
    req_bb = make_shop_analysis_request_with_scope()
    req_bb.target_model.scope_rules.testing_mode = TestingMode.BLACKBOX  # type: ignore[union-attr]
    req_bb.source_repo_path = None
    res_bb = extract_sink_candidates(req_bb, semgrep_payload=make_semgrep_envelope())
    assert any("BLACKBOX" in lim for lim in res_bb.limitations)

    # 4b: scope_rules missing
    req_no_rules = make_shop_analysis_request_with_scope()
    req_no_rules.target_model.scope_rules = None
    res_no_rules = extract_sink_candidates(req_no_rules, semgrep_payload=make_semgrep_envelope())
    assert any("scope_rules is missing" in lim for lim in res_no_rules.limitations)

    # 4c: source_repo_path None
    req_no_path = make_shop_analysis_request_with_scope(source_repo_path=None)
    res_no_path = extract_sink_candidates(req_no_path, semgrep_payload=make_semgrep_envelope())
    assert any("No source_repo_path provided" in lim for lim in res_no_path.limitations)

    # 4d: source_repository_ref None
    req_no_ref = make_shop_analysis_request_with_scope()
    req_no_ref.target_model.scope_rules.source_repository_ref = None  # type: ignore[union-attr]
    res_no_ref = extract_sink_candidates(req_no_ref, semgrep_payload=make_semgrep_envelope())
    assert any("source_repository_ref is not configured" in lim for lim in res_no_ref.limitations)

    # 4e: Path outside approved scope
    req_outside = make_shop_analysis_request_with_scope(
        source_repo_path="/unapproved/other/repo",
        source_repository_ref="/approved/shop",
    )
    res_outside = extract_sink_candidates(req_outside, semgrep_payload=make_semgrep_envelope())
    assert any("outside approved source_repository_ref" in lim for lim in res_outside.limitations)

    # 4f: Windows drive mismatch and path traversal
    valid_path, reason = validate_source_analysis_scope(
        make_shop_analysis_request_with_scope(
            source_repo_path="D:/repo/shop", source_repository_ref="C:/repo/shop"
        )
    )
    assert valid_path is None
    assert "outside approved" in str(reason)

    valid_path_trav, reason_trav = validate_source_analysis_scope(
        make_shop_analysis_request_with_scope(
            source_repo_path="C:/repo/shop/../outside", source_repository_ref="C:/repo/shop"
        )
    )
    assert valid_path_trav is None
    assert "invalid or relative" in str(reason_trav)

    # Case normalization on Windows drive
    valid_win, reason_win = validate_source_analysis_scope(
        make_shop_analysis_request_with_scope(
            source_repo_path="c:/repo/shop/app", source_repository_ref="C:/repo/shop"
        )
    )
    assert reason_win is None
    assert valid_win is not None

    # Payload with absolute path outside repository
    req_ok = make_shop_analysis_request_with_scope(
        source_repo_path="/repo/shop", source_repository_ref="/repo/shop"
    )
    payload_bad_file = make_semgrep_envelope([make_semgrep_finding(file="/etc/passwd")])
    res_bad_file = extract_sink_candidates(req_ok, semgrep_payload=payload_bad_file)
    assert res_bad_file.sink_candidates == []
    assert any("lying outside approved repository" in w for w in res_bad_file.warnings)


# 5. test_async_execution_interface_and_running_event_loop_safety
@async_test
async def test_async_execution_interface_and_running_event_loop_safety():
    req = make_shop_analysis_request_with_scope()
    envelope = make_semgrep_envelope([make_semgrep_finding()])

    # aextract with pre-captured payload
    res = await aextract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res.sink_candidates) == 1

    # extract_sink_candidates (sync) running cleanly inside running event loop
    res_sync = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res_sync.sink_candidates) == 1

    # Calling adapter.run_sync() inside running loop raises RuntimeError
    adapter = LocalSemgrepAdapter(ruleset_path="E:/Academic/Intern/WebSecuritySDK")
    with pytest.raises(RuntimeError, match="cannot be called inside a running asyncio event loop"):
        adapter.run_sync("/repo/shop")


# 6. test_strict_offline_ruleset_and_layer6_startup_env_validation
def test_strict_offline_ruleset_and_layer6_startup_env_validation(tmp_path: Path):
    # Missing ruleset -> ToolError
    with pytest.raises(
        ToolError, match="Strict offline Semgrep policy requires an explicit local ruleset"
    ):
        validate_offline_ruleset_path("")

    # Remote registry ruleset -> strictly prohibited
    with pytest.raises(
        ToolError, match=r"Remote Semgrep registry ruleset .* is strictly prohibited"
    ):
        validate_offline_ruleset_path("p/default")

    with pytest.raises(
        ToolError, match=r"Remote Semgrep registry ruleset .* is strictly prohibited"
    ):
        validate_offline_ruleset_path("https://semgrep.dev/p/default")

    # Invalid extension
    bad_txt = tmp_path / "rules.txt"
    bad_txt.write_text("rules", encoding="utf-8")
    with pytest.raises(ToolError, match=r"must have a \.yaml, \.yml, or \.json extension"):
        validate_offline_ruleset_path(str(bad_txt))

    # Empty directory
    empty_dir = tmp_path / "empty_rules"
    empty_dir.mkdir()
    with pytest.raises(ToolError, match="must contain at least one non-symlinked"):
        validate_offline_ruleset_path(str(empty_dir))

    # Valid YAML file
    valid_yaml = tmp_path / "my_rules.yaml"
    valid_yaml.write_text("rules: []", encoding="utf-8")
    resolved = validate_offline_ruleset_path(str(valid_yaml))
    assert Path(resolved).resolve() == valid_yaml.resolve()
    first_digest = compute_ruleset_sha256(valid_yaml)
    assert len(first_digest) == 64
    valid_yaml.write_text("rules:\n  - id: changed\n", encoding="utf-8")
    assert compute_ruleset_sha256(valid_yaml) != first_digest


# 7. test_concurrent_adapter_executions_with_different_local_rulesets_and_provenance
@async_test
async def test_concurrent_adapter_executions_with_different_local_rulesets_and_provenance(
    tmp_path: Path,
):
    rules_alpha = tmp_path / "rules_alpha.yaml"
    rules_alpha.write_text("rules: []", encoding="utf-8")
    rules_beta = tmp_path / "rules_beta.yaml"
    rules_beta.write_text("rules: []", encoding="utf-8")

    captured_configs: dict[str, str] = {}

    async def fake_runner_alpha(
        argv: list[str], cwd: Path, output_path: Path, stderr_path: Path
    ) -> int:
        await asyncio.sleep(0.01)
        for arg in argv:
            if arg.startswith("--config="):
                captured_configs["alpha"] = arg.split("=", 1)[1]
        output_path.write_text(
            json.dumps({"results": [], "errors": [], "paths": {"scanned": []}}), encoding="utf-8"
        )
        return 0

    async def fake_runner_beta(
        argv: list[str], cwd: Path, output_path: Path, stderr_path: Path
    ) -> int:
        await asyncio.sleep(0.01)
        for arg in argv:
            if arg.startswith("--config="):
                captured_configs["beta"] = arg.split("=", 1)[1]
        output_path.write_text(
            json.dumps({"results": [], "errors": [], "paths": {"scanned": []}}), encoding="utf-8"
        )
        return 0

    adapter_a = LocalSemgrepAdapter(ruleset_path=rules_alpha, runner=fake_runner_alpha)
    adapter_b = LocalSemgrepAdapter(ruleset_path=rules_beta, runner=fake_runner_beta)

    repo_dir = tmp_path / "repo"
    repo_dir.mkdir(exist_ok=True)

    res_a, res_b = await asyncio.gather(
        adapter_a.analyze(str(repo_dir)),
        adapter_b.analyze(str(repo_dir)),
    )

    assert captured_configs["alpha"] == str(rules_alpha.resolve())
    assert captured_configs["beta"] == str(rules_beta.resolve())
    assert res_a["data"]["ruleset_ref"] == "rules_alpha.yaml"
    assert res_b["data"]["ruleset_ref"] == "rules_beta.yaml"


# 8. test_sink_kind_classification_all_nine_kinds
def test_sink_kind_classification_all_nine_kinds():
    cases = [
        ("python.django.orm-injection", {"cwe": "CWE-89"}, SinkKind.ORM_QUERY),
        ("python.ldap.ldap-query", {"cwe": "CWE-90"}, SinkKind.LDAP_OR_XPATH),
        ("python.mongo.nosql-injection", {"cwe": "CWE-943"}, SinkKind.NOSQL_QUERY),
        ("python.flask.ssti", {"cwe": "CWE-1336"}, SinkKind.TEMPLATE_RENDER),
        ("python.db.sql-injection", {"cwe": "CWE-89"}, SinkKind.SQL_QUERY),
        ("python.os.cmdi", {"cwe": "CWE-78"}, SinkKind.OS_COMMAND),
        ("python.lang.code-injection", {"cwe": "CWE-94"}, SinkKind.CODE_EVAL),
        ("python.fs.path-traversal", {"cwe": "CWE-22"}, SinkKind.PATH_ACCESS),
        ("python.web.xss", {"cwe": "CWE-79"}, SinkKind.HTML_OUTPUT),
    ]
    for rule_id, meta, expected_kind in cases:
        kind, _cwes, skip = classify_sink_kind(rule_id, meta)
        assert kind == expected_kind, f"Failed for {rule_id}: got {kind}, expected {expected_kind}"
        assert skip is None


# 9. test_ambiguous_sink_classification_precedence_and_non_sink_exclusion
def test_ambiguous_sink_classification_precedence_and_non_sink_exclusion():
    # Ambiguity 1: ORM vs SQL
    kind, _, _ = classify_sink_kind("django-orm-extra-where", {"cwe": ["CWE-89"]})
    assert kind == SinkKind.ORM_QUERY

    # Ambiguity 2: Template render vs HTML output
    kind, _, _ = classify_sink_kind("flask-ssti-render", {"cwe": ["CWE-1336", "CWE-79"]})
    assert kind == SinkKind.TEMPLATE_RENDER

    # Ambiguity 3: LDAP/XPath vs NoSQL
    kind, _, _ = classify_sink_kind("ldap-search", {"cwe": ["CWE-943", "CWE-90"]})
    assert kind == SinkKind.LDAP_OR_XPATH

    # Ambiguity 4: OS Command vs Code Eval
    kind, _, _ = classify_sink_kind("child-process-exec", {"cwe": ["CWE-78"]})
    assert kind == SinkKind.OS_COMMAND

    # Non-sink exclusions
    is_non, reason = is_non_sink_finding(
        "cookie-missing-httponly", {"cwe": ["CWE-1004"]}, has_taint_trace=False
    )
    assert is_non is True
    assert "cookie-" in str(reason)

    is_non2, _reason2 = is_non_sink_finding(
        "hardcoded-password", {"cwe": ["CWE-798"]}, has_taint_trace=False
    )
    assert is_non2 is True

    is_non3, _reason3 = is_non_sink_finding(
        "code-style", {"category": "best-practice"}, has_taint_trace=False
    )
    assert is_non3 is True


# 10. test_unverified_sink_without_taint_flow_caps_confidence_and_steps
def test_unverified_sink_without_taint_flow_caps_confidence_and_steps():
    req = make_shop_analysis_request_with_scope()
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(
                confidence="HIGH",
                severity="ERROR",
                dataflow_trace=None,
            )
        ]
    )
    res = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res.sink_candidates) == 1
    sc = res.sink_candidates[0]
    assert sc.has_static_taint_flow is False
    assert sc.dataflow_steps == []
    # Confidence capped at MEDIUM when no taint flow exists
    assert sc.confidence == ConfidenceLevel.MEDIUM


# 11. test_verified_static_taint_flow_extraction_and_metadata
def test_verified_static_taint_flow_extraction_and_metadata():
    req = make_shop_analysis_request_with_scope()
    trace = {
        "taint_source": [
            {
                "location": {
                    "path": "app/routes.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 30},
                },
                "content": "request.args.get('sort')",
            }
        ],
        "intermediate_vars": [
            {
                "location": {
                    "path": "app/routes.py",
                    "start": {"line": 12, "col": 5},
                    "end": {"line": 12, "col": 20},
                },
                "content": "clean_sort = sort",
            }
        ],
        "taint_sink": [
            {
                "location": {
                    "path": "app/routes.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 40},
                },
                "content": "cursor.execute(clean_sort)",
            }
        ],
    }
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(
                file="app/routes.py",
                start_line=15,
                confidence="HIGH",
                dataflow_trace=trace,
            )
        ]
    )
    res = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res.sink_candidates) == 1
    sc = res.sink_candidates[0]
    assert sc.has_static_taint_flow is True
    assert len(sc.dataflow_steps) == 3
    assert sc.confidence == ConfidenceLevel.HIGH
    meta = res.sink_metadata[sc.sink_id]
    assert "request.args.get('sort')" in (meta.taint_source_snippet or "")
    assert meta.taint_source_line == 10


def test_verified_static_taint_flow_extraction_with_semgrep_cli_atd_format():
    req = make_shop_analysis_request_with_scope()
    trace = {
        "intermediate_vars": [
            [
                "CliLoc",
                [
                    {
                        "path": "app/routes.py",
                        "start": {"line": 12, "col": 5},
                        "end": {"line": 12, "col": 20},
                    },
                    "clean_sort = sort",
                ],
            ]
        ],
        "taint_source": [
            "CliLoc",
            [
                {
                    "path": "app/routes.py",
                    "start": {"line": 10, "col": 5},
                    "end": {"line": 10, "col": 30},
                },
                "request.args.get('sort')",
            ],
        ],
        "taint_sink": [
            "CliLoc",
            [
                {
                    "path": "app/routes.py",
                    "start": {"line": 15, "col": 5},
                    "end": {"line": 15, "col": 40},
                },
                "cursor.execute(clean_sort)",
            ],
        ],
    }
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(
                file="app/routes.py",
                start_line=15,
                confidence="HIGH",
                dataflow_trace=trace,
            )
        ]
    )
    res = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(res.sink_candidates) == 1
    sc = res.sink_candidates[0]
    assert sc.has_static_taint_flow is True
    assert len(sc.dataflow_steps) == 3
    assert sc.confidence == ConfidenceLevel.HIGH
    meta = res.sink_metadata[sc.sink_id]
    assert "request.args.get('sort')" in (meta.taint_source_snippet or "")
    assert meta.taint_source_line == 10


# 12. test_deduplication_merges_exact_sink_anchor_and_preserves_all_taint_and_metadata
def test_deduplication_merges_exact_sink_anchor_and_preserves_all_taint_and_metadata():
    req = make_shop_analysis_request_with_scope()
    f1 = make_semgrep_finding(
        rule_id="rule.pattern.sqli",
        file="app/db.py",
        start_line=30,
        end_line=30,
        start_column=10,
        end_column=45,
        snippet="cursor.execute(sql)",
        dataflow_trace=None,
    )
    trace = {
        "taint_source": [
            {
                "location": {"path": "app/db.py", "start": {"line": 5, "col": 2}},
                "content": "user_id",
            }
        ],
        "taint_sink": [
            {
                "location": {
                    "path": "app/db.py",
                    "start": {"line": 30, "col": 10},
                    "end": {"line": 30, "col": 45},
                },
                "content": "cursor.execute(sql)",
            }
        ],
    }
    f2 = make_semgrep_finding(
        rule_id="rule.taint.sqli",
        file="app/db.py",
        start_line=30,
        end_line=30,
        start_column=10,
        end_column=45,
        snippet="cursor.execute(sql)",
        dataflow_trace=trace,
    )
    res = extract_sink_candidates(req, semgrep_payload=make_semgrep_envelope([f1, f2]))
    assert len(res.sink_candidates) == 1
    sc = res.sink_candidates[0]
    assert sc.has_static_taint_flow is True
    assert sc.rule_id == "rule.taint.sqli"
    meta = res.sink_metadata[sc.sink_id]
    assert meta.all_rule_ids == ["rule.pattern.sqli", "rule.taint.sqli"]


# 13. test_deduplication_preserves_nested_sinks_and_separate_same_line_calls
def test_deduplication_preserves_nested_sinks_and_separate_same_line_calls():
    req = make_shop_analysis_request_with_scope()

    # Separate calls on same line
    f1 = make_semgrep_finding(
        file="app/api.py",
        start_line=42,
        start_column=5,
        end_column=25,
        snippet="cursor.execute(q1)",
    )
    f2 = make_semgrep_finding(
        file="app/api.py",
        start_line=42,
        start_column=30,
        end_column=50,
        snippet="cursor.execute(q2)",
    )

    # Nested calls on same line
    f3_outer = make_semgrep_finding(
        file="app/nested.py",
        start_line=10,
        start_column=5,
        end_column=60,
        snippet="cursor.execute(build_query(x))",
    )
    f3_inner = make_semgrep_finding(
        file="app/nested.py",
        start_line=10,
        start_column=20,
        end_column=55,
        snippet="build_query(x)",
    )

    res = extract_sink_candidates(
        req, semgrep_payload=make_semgrep_envelope([f1, f2, f3_outer, f3_inner])
    )
    # Separate calls must NOT be merged; nested calls must NOT be merged
    assert len(res.sink_candidates) == 4


# 14. test_deduplication_keeps_missing_column_findings_from_different_rules_separate
def test_deduplication_keeps_missing_column_findings_from_different_rules_separate():
    req = make_shop_analysis_request_with_scope()

    f_rule1 = make_semgrep_finding(
        rule_id="sqli-rule-1",
        file="app/views.py",
        start_line=50,
        start_column=None,
        end_column=None,
        snippet="query()",
    )
    f_rule2 = make_semgrep_finding(
        rule_id="sqli-rule-2",
        file="app/views.py",
        start_line=50,
        start_column=None,
        end_column=None,
        snippet="query()",
    )
    f_rule1_dup = make_semgrep_finding(
        rule_id="sqli-rule-1",
        file="app/views.py",
        start_line=50,
        start_column=None,
        end_column=None,
        snippet="query()",
    )

    res = extract_sink_candidates(
        req, semgrep_payload=make_semgrep_envelope([f_rule1, f_rule2, f_rule1_dup])
    )
    # f_rule1 and f_rule1_dup are merged; f_rule2 is kept distinct
    assert len(res.sink_candidates) == 2


# 15. test_evidence_integrity_canonical_payload_and_manifest_reverification
def test_evidence_integrity_canonical_payload_and_manifest_reverification():
    req = make_shop_analysis_request_with_scope()
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(rule_id="sqli.a", file="app/a.py", start_line=1),
            make_semgrep_finding(rule_id="sqli.b", file="app/b.py", start_line=2),
        ]
    )
    res = extract_sink_candidates(req, semgrep_payload=envelope)

    # Collision-free allocator check
    evd_ids = [r.evidence_id for r in res.analysis_evidence_records]
    assert len(evd_ids) == 2
    assert "EVD-001" not in evd_ids
    assert "EVD-002" not in evd_ids
    assert len(set(evd_ids)) == len(evd_ids)
    assert all(eid.startswith("EVD-") for eid in evd_ids)
    assert evd_ids == sorted(evd_ids)
    assert int(evd_ids[0].split("-")[1]) > 2

    # Verify every manifest matches its record
    for record, manifest in zip(
        res.analysis_evidence_records, res.artifact_manifests, strict=False
    ):
        assert verify_sink_evidence_integrity(record, manifest) is True

        # Tampering check
        tampered_manifest = manifest.model_copy(update={"content": manifest.content + " "})
        assert verify_sink_evidence_integrity(record, tampered_manifest) is False


# 16. test_unified_sensitive_data_redaction_and_fail_closed_suppression
def test_unified_sensitive_data_redaction_and_fail_closed_suppression():
    req = make_shop_analysis_request_with_scope()

    # Sensitive file (.env.production) -> snippet None
    f_env = make_semgrep_finding(
        file=".env.production", start_line=1, snippet="DATABASE_URL=postgres://user:pass@host/db"
    )

    # Regular file with secret assignment and PEM key
    f_secret = make_semgrep_finding(
        file="app/config.py",
        start_line=20,
        snippet="password = 'super_secret_value_12345'",
    )
    f_pem = make_semgrep_finding(
        file="app/crypto.py",
        start_line=5,
        snippet="""-----BEGIN RSA PRIVATE KEY-----
MIIEowIBAAKCAQEA0...
-----END RSA PRIVATE KEY-----""",
    )

    res = extract_sink_candidates(
        req, semgrep_payload=make_semgrep_envelope([f_env, f_secret, f_pem])
    )
    assert len(res.sink_candidates) == 3

    # Sensitive file snippet should be None
    assert res.sink_candidates[0].snippet is None

    # Secret assignment redacted
    assert "super_secret_value_12345" not in str(res.sink_candidates[1].snippet)
    assert "<redacted>" in str(res.sink_candidates[1].snippet)

    # PEM key fail closed -> snippet None
    assert res.sink_candidates[2].snippet is None

    # Ensure no raw secret in any artifact manifest content
    for m in res.artifact_manifests:
        assert "super_secret_value_12345" not in (m.content or "")
        assert "BEGIN RSA PRIVATE KEY" not in (m.content or "")


# 17. test_permutation_determinism_across_findings_order
def test_permutation_determinism_across_findings_order():
    req = make_shop_analysis_request_with_scope()
    f1 = make_semgrep_finding(rule_id="sqli.z", file="app/z.py", start_line=10)
    f2 = make_semgrep_finding(rule_id="sqli.a", file="app/a.py", start_line=5)
    f3 = make_semgrep_finding(rule_id="cmdi.m", file="app/m.py", start_line=20)
    f4 = make_semgrep_finding(rule_id="xss.b", file="app/b.py", start_line=1)

    res1 = extract_sink_candidates(
        req, semgrep_payload=make_semgrep_envelope([f1, f2, f3, f4], truncated=True)
    )
    res2 = extract_sink_candidates(
        req, semgrep_payload=make_semgrep_envelope([f4, f3, f2, f1], truncated=True)
    )

    assert [s.model_dump() for s in res1.sink_candidates] == [
        s.model_dump() for s in res2.sink_candidates
    ]
    assert [e.model_dump() for e in res1.analysis_evidence_records] == [
        e.model_dump() for e in res2.analysis_evidence_records
    ]
    assert [m.model_dump() for m in res1.artifact_manifests] == [
        m.model_dump() for m in res2.artifact_manifests
    ]
    assert res1.limitations == res2.limitations
    assert res1.warnings == res2.warnings


# 18. test_end_to_end_compatibility_with_m2_t01_and_m2_t02_handoff
def test_end_to_end_compatibility_with_m2_t01_and_m2_t02_handoff():
    req = make_shop_analysis_request_with_scope()

    # M2-T02 input candidate extraction
    inp_res = extract_input_candidates(req)
    assert len(inp_res.inputs) > 0

    # M2-T03 sink candidate extraction
    trace = {
        "taint_source": [
            {
                "location": {"path": "app/products.py", "start": {"line": 10, "col": 5}},
                "content": "sort_by",
            }
        ],
        "taint_sink": [
            {
                "location": {
                    "path": "app/products.py",
                    "start": {"line": 28, "col": 5},
                    "end": {"line": 28, "col": 40},
                },
                "content": "cursor.execute(sql)",
            }
        ],
    }
    envelope = make_semgrep_envelope(
        [
            make_semgrep_finding(
                rule_id="python.django.security.injection.sql-injection",
                file="app/products.py",
                start_line=28,
                end_line=28,
                start_column=5,
                end_column=40,
                dataflow_trace=trace,
            )
        ]
    )
    sink_res = extract_sink_candidates(req, semgrep_payload=envelope)
    assert len(sink_res.sink_candidates) == 1
    sink = sink_res.sink_candidates[0]
    assert sink.has_static_taint_flow is True

    # Build Hypothesis referencing both input and sink
    target_inp_obj = inp_res.inputs[0]
    target_ep_id = target_inp_obj.endpoint_id
    target_inp = target_inp_obj.input_id

    prop = ValidationCapabilityRequirement(
        proposal_id="VCR-001",
        hypothesis_ref="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        suggested_capability=ValidationCapability.SQLI_DETECTION,
        target_endpoint_id=target_ep_id,
        target_input_ref=target_inp,
        expected_signals=[ExpectedSignal.SQL_SYNTAX_ERROR],
        evidence_refs=list(sink.evidence_refs),
    )

    hyp = Hypothesis(
        hypothesis_id="HYP-001",
        vulnerability_category=VulnerabilityCategory.SQL_INJECTION,
        target_endpoint_id=target_ep_id,
        input_ref=target_inp,
        sink_ref=sink.sink_id,
        sink_relationship=SinkRelationship.STATIC_TAINT_FLOW_FOUND,
        confidence=ConfidenceLevel.HIGH,
        rationale="Demonstrated taint flow from sort parameter into SQL sink",
        supporting_evidence_refs=list(sink.evidence_refs),
        validation_proposals=[prop],
    )

    output = Module2Output(
        assessment_id=req.target_model.assessment_id,
        target_id=req.target_model.target_id,
        generated_at=FIXED_TIME,
        analysis_evidence_records=sink_res.analysis_evidence_records,
        inputs=inp_res.inputs,
        sink_candidates=sink_res.sink_candidates,
        hypotheses=[hyp],
    )

    # Validate handoff
    validated = validate_module2_handoff(output, req)
    assert len(validated.hypotheses) == 1
    assert len(validated.inputs) == len(inp_res.inputs)
    assert len(validated.sink_candidates) == 1
