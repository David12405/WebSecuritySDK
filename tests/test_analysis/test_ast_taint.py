"""Unit and end-to-end integration tests for intra-procedural AST taint tracing (Step 2)."""

from __future__ import annotations

import shutil
import subprocess
import tempfile
from datetime import UTC, datetime
from pathlib import Path

import pytest

from test_analysis.fixtures import (
    FIXED_TIME,
    make_endpoint,
    make_evidence_record,
    make_opengrep_envelope,
    make_opengrep_finding,
    make_scope_rules,
)
from websecuritycheck.analysis import (
    PINNED_CLOUDFLARE_RULESET_SHA256,
    REVIEWED_AST_TAINT_PRODUCER,
    REVIEWED_CLOUDFLARE_RULESET_ENTRY,
    REVIEWED_STATIC_ROUTE_PRODUCER,
    CorrelationKind,
    CorrelationStatus,
    CorrelationTrustPolicy,
    FlowTrust,
    correlate_evidence,
    extract_input_candidates,
    extract_route_bindings,
    extract_sink_candidates,
    trace_intraprocedural_sink_taint,
    verify_sink_evidence_integrity,
)
from websecuritycheck.domain.analysis_models import (
    Module2AnalysisRequest,
    Module2Output,
    SinkKind,
    SinkRelationship,
    validate_module2_handoff,
)
from websecuritycheck.domain.enums import (
    ArtifactType,
    InputLocation,
    TestingMode,
)
from websecuritycheck.domain.models import Id, ObservedParameter, TargetModel

CLOUDFLARE_TARGETS_ROOT = (
    Path(__file__).resolve().parents[2] / "test-targets" / "cloudflare" / "targets"
)
RULESET_FIXTURES_ROOT = (
    Path(__file__).resolve().parents[2]
    / "tests"
    / "test_analysis"
    / "sample_sources"
    / "cloudflare_injection"
)


def _git_init_and_commit(repo_dir: Path) -> str:
    subprocess.run(["git", "init", "-q"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_dir, check=True)
    subprocess.run(["git", "config", "user.email", "test@example.com"], cwd=repo_dir, check=True)
    subprocess.run(["git", "add", "."], cwd=repo_dir, check=True)
    subprocess.run(["git", "commit", "-m", "init", "-q"], cwd=repo_dir, check=True)
    rev = subprocess.run(
        ["git", "rev-parse", "HEAD"], cwd=repo_dir, check=True, capture_output=True, text=True
    )
    return rev.stdout.strip()


@pytest.fixture
def tmp_path():
    with tempfile.TemporaryDirectory(prefix="m2_ast_taint_") as td:
        yield Path(td).resolve()


# ---------------------------------------------------------------------------
# 1. Cloudflare API target AST backward slicing (line ordering & JSON fields)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (CLOUDFLARE_TARGETS_ROOT / "api" / "src" / "index.js").exists(),
    reason="Cloudflare api target not present",
)
def test_ast_taint_on_cloudflare_api_target() -> None:
    api_root = CLOUDFLARE_TARGETS_ROOT / "api"

    # Sink 1: GET /api/users (line 73), guard at line 75 comes AFTER sink -> stays tainted!
    res_users = trace_intraprocedural_sink_taint(
        api_root,
        file_path="src/index.js",
        sink_line=73,
        sink_kind=SinkKind.SQL_QUERY,
        handler_span=(65, 83),
    )
    assert res_users.has_taint_flow is True
    assert res_users.is_sanitized_or_parameterized is False
    assert len(res_users.resolved_sources) == 1
    assert res_users.resolved_sources[0].location == InputLocation.QUERY
    assert res_users.resolved_sources[0].parameter_name == "id"
    assert res_users.resolved_sources[0].source_line == 69

    # Sink 2: POST /api/search (line 125) reads body.keyword; filters.* never reach sink!
    res_search = trace_intraprocedural_sink_taint(
        api_root,
        file_path="src/index.js",
        sink_line=125,
        sink_kind=SinkKind.SQL_QUERY,
        handler_span=(104, 148),
    )
    assert res_search.has_taint_flow is True
    assert len(res_search.resolved_sources) == 1
    assert res_search.resolved_sources[0].location == InputLocation.JSON_BODY
    assert res_search.resolved_sources[0].parameter_name == "keyword"
    assert res_search.resolved_sources[0].accessor_snippet == "body.keyword"
    assert "filters.category" not in {s.parameter_name for s in res_search.resolved_sources}
    assert "filters.minPrice" not in {s.parameter_name for s in res_search.resolved_sources}
    # filters.category / filters.minPrice also appear strictly AFTER line 125
    assert "filters.category" not in res_search.candidate_input_names_in_handler
    assert "filters.minPrice" not in res_search.candidate_input_names_in_handler
    assert "keyword" in res_search.candidate_input_names_in_handler


@pytest.mark.skipif(
    not (CLOUDFLARE_TARGETS_ROOT / "basic" / "src" / "index.js").exists(),
    reason="Cloudflare basic target not present",
)
def test_ast_taint_on_cloudflare_basic_target() -> None:
    basic_root = CLOUDFLARE_TARGETS_ROOT / "basic"

    # new Function(rawQuery) at line 145
    res_search = trace_intraprocedural_sink_taint(
        basic_root,
        file_path="src/index.js",
        sink_line=145,
        sink_kind=SinkKind.CODE_EVAL,
        handler_span=(138, 166),
    )
    assert res_search.has_taint_flow is True
    assert res_search.resolved_sources[0].location == InputLocation.QUERY
    assert res_search.resolved_sources[0].parameter_name == "q"

    # childProcess.exec(rawComment) at line 281
    res_form = trace_intraprocedural_sink_taint(
        basic_root,
        file_path="src/index.js",
        sink_line=281,
        sink_kind=SinkKind.OS_COMMAND,
        handler_span=(269, 288),
    )
    assert res_form.has_taint_flow is True
    assert res_form.resolved_sources[0].location == InputLocation.FORM
    assert res_form.resolved_sources[0].parameter_name == "comment"


def test_ast_taint_handles_parameterized_bind_and_pre_sink_guards(tmp_path: Path) -> None:
    src = tmp_path / "worker.js"
    src.write_text(
        """export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const idMatch = path.match(/^\\/items\\/([^/]+)$/);

    if (path === "/safe-bind") {
      const uid = url.searchParams.get("uid");
      return await env.DB.prepare("SELECT * FROM users WHERE id = ?").bind(uid).first();
    }
    if (path === "/safe-guard") {
      const gid = url.searchParams.get("gid");
      if (!/^\\d+$/.test(gid)) { return new Response("bad", { status: 400 }); }
      return await env.DB.prepare(`SELECT * FROM items WHERE id = ${gid}`).all();
    }
    if (path === "/unsafe-destruct") {
      const body = await request.json();
      const { keyword, filters: { category } } = body;
      const sql = "SELECT * FROM items WHERE cat = '" + category + "'";
      return await env.DB.prepare(sql).all();
    }
    if (idMatch) {
      const rawId = idMatch[1];
      return await env.DB.prepare(`SELECT * FROM items WHERE id = ${rawId}`).all();
    }
  }
};
""",
        encoding="utf-8",
    )

    # 1. Safe .prepare("... ?").bind(...)
    res_bind = trace_intraprocedural_sink_taint(
        tmp_path, file_path="worker.js", sink_line=9, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_bind.has_taint_flow is False
    assert res_bind.is_sanitized_or_parameterized is True

    # 2. Safe pre-sink numeric regex guard
    res_guard = trace_intraprocedural_sink_taint(
        tmp_path, file_path="worker.js", sink_line=14, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_guard.has_taint_flow is False
    assert res_guard.is_sanitized_or_parameterized is True

    # 3. Nested object destructuring { keyword, filters: { category } } -> filters.category only
    res_destr = trace_intraprocedural_sink_taint(
        tmp_path, file_path="worker.js", sink_line=20, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_destr.has_taint_flow is True
    assert len(res_destr.resolved_sources) == 1
    assert res_destr.resolved_sources[0].location == InputLocation.JSON_BODY
    assert res_destr.resolved_sources[0].parameter_name == "filters.category"
    assert res_destr.resolved_sources[0].accessor_snippet == "body.filters.category"

    # 4. Path capture match[1] mapped via route_path="/items/{item_id}"
    res_path = trace_intraprocedural_sink_taint(
        tmp_path,
        file_path="worker.js",
        sink_line=24,
        sink_kind=SinkKind.SQL_QUERY,
        route_path="/items/{item_id}",
    )
    assert res_path.has_taint_flow is True
    assert res_path.resolved_sources[0].location == InputLocation.PATH
    assert res_path.resolved_sources[0].parameter_name == "item_id"


def test_python_ast_taint_slicing_and_guards(tmp_path: Path) -> None:
    app = tmp_path / "app.py"
    app.write_text(
        """import re

def unsafe_search(request, cursor):
    payload = request.get_json()
    cat = payload["filters"]["category"]
    sql = f"SELECT * FROM items WHERE category = '{cat}'"
    cursor.execute(sql)

def safe_param(request, cursor):
    q = request.args.get("q")
    cursor.execute("SELECT * FROM items WHERE name = %s", (q,))

def safe_guarded(request, cursor):
    uid = request.args.get("uid")
    if not re.match(r"^\\d+$", uid):
        return "bad"
    cursor.execute(f"SELECT * FROM users WHERE id = {uid}")
""",
        encoding="utf-8",
    )

    res_unsafe = trace_intraprocedural_sink_taint(
        tmp_path, file_path="app.py", sink_line=7, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_unsafe.has_taint_flow is True
    assert res_unsafe.resolved_sources[0].location == InputLocation.JSON_BODY
    assert res_unsafe.resolved_sources[0].parameter_name == "filters.category"

    res_param = trace_intraprocedural_sink_taint(
        tmp_path, file_path="app.py", sink_line=11, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_param.has_taint_flow is False
    assert res_param.is_sanitized_or_parameterized is True

    res_guard = trace_intraprocedural_sink_taint(
        tmp_path, file_path="app.py", sink_line=17, sink_kind=SinkKind.SQL_QUERY
    )
    assert res_guard.has_taint_flow is False
    assert res_guard.is_sanitized_or_parameterized is True


# ---------------------------------------------------------------------------
# 2. End-to-End Correlation on Real API Worker (HYP-001/002 -> VERIFIED, filters -> Pruned)
# ---------------------------------------------------------------------------


@pytest.mark.skipif(
    not (CLOUDFLARE_TARGETS_ROOT / "api" / "src" / "index.js").exists(),
    reason="Cloudflare api target not present",
)
def test_end_to_end_ast_enrichment_and_correlation_on_api_worker(tmp_path: Path) -> None:
    repo = tmp_path / "api_repo"
    shutil.copytree(CLOUDFLARE_TARGETS_ROOT / "api", repo)
    rev = _git_init_and_commit(repo)

    ep_users = make_endpoint(
        origin="https://api.lab.local",
        path="/api/users",
        method="GET",
        observed_parameters=[
            ObservedParameter(
                name="id",
                location=InputLocation.QUERY,
                evidence_refs=[Id("EVD-001")],
            )
        ],
    )
    ep_search = make_endpoint(
        origin="https://api.lab.local",
        path="/api/search",
        method="POST",
        observed_parameters=[
            ObservedParameter(
                name="keyword",
                location=InputLocation.JSON_BODY,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="filters.category",
                location=InputLocation.JSON_BODY,
                evidence_refs=[Id("EVD-001")],
            ),
            ObservedParameter(
                name="filters.minPrice",
                location=InputLocation.JSON_BODY,
                evidence_refs=[Id("EVD-001")],
            ),
        ],
    )
    evd1 = make_evidence_record("EVD-001", artifact_type=ArtifactType.HTTP_RAW_EXCHANGE)
    tm = TargetModel(
        target_id=Id("TGT-001"),
        assessment_id=Id("ASM-001"),
        last_updated=FIXED_TIME,
        endpoints=[ep_users, ep_search],
    )
    req = Module2AnalysisRequest(
        target_model=tm,
        observations=[],
        evidence_records=[evd1],
        source_repo_path=str(repo.resolve()),
    )
    req.target_model.scope_rules = make_scope_rules(
        testing_mode=TestingMode.WHITEBOX,
        source_repository_ref=str(repo.resolve()),
    )

    # Simulate Opengrep findings WITHOUT traces (plus 'requires login' placeholder on snippet!)
    f_users = make_opengrep_finding(
        rule_id="cloudflare-workers.tainted-d1-sql-injection",
        file="src/index.js",
        start_line=73,
        end_line=73,
        snippet="requires login",
        dataflow_trace=None,
    )
    # And simulate Opengrep finding with coarse `await request.json()` trace on /api/search
    f_search = make_opengrep_finding(
        rule_id="cloudflare-workers.tainted-d1-sql-injection",
        file="src/index.js",
        start_line=125,
        end_line=125,
        snippet="await db.prepare(searchSql).all();",
        dataflow_trace={
            "taint_source": [
                "CliLoc",
                [
                    {"path": "src/index.js", "start": {"line": 114, "col": 16}},
                    "await request.json()",
                ],
            ],
            "intermediate_vars": [
                {
                    "location": {"path": "src/index.js", "start": {"line": 114, "col": 9}},
                    "content": "body",
                }
            ],
            "taint_sink": [
                "CliLoc",
                [
                    {"path": "src/index.js", "start": {"line": 125, "col": 7}},
                    "db.prepare(searchSql)",
                ],
            ],
        },
    )
    env = make_opengrep_envelope([f_users, f_search], path=str(repo.resolve()))
    env["data"].update(
        {
            "ruleset_sha256": PINNED_CLOUDFLARE_RULESET_SHA256,
            "source_revision": rev,
            "source_repository_ref": str(repo.resolve()),
            "execution_ref": "EXEC-901",
        }
    )

    inp_res = extract_input_candidates(req)
    sink_res = extract_sink_candidates(req, opengrep_payload=env, enable_ast_taint=True)

    assert len(sink_res.sink_candidates) == 2
    # "requires login" was stripped and replaced with actual code line!
    assert sink_res.sink_candidates[0].snippet is not None
    assert "requires login" not in sink_res.sink_candidates[0].snippet.lower()
    assert all(sc.has_static_taint_flow for sc in sink_res.sink_candidates)
    for rec, man in zip(
        sink_res.analysis_evidence_records, sink_res.artifact_manifests, strict=False
    ):
        assert verify_sink_evidence_integrity(rec, man)

    route_res = extract_route_bindings(
        req,
        existing_evidence_ids={
            e.evidence_id for e in [*req.evidence_records, *sink_res.analysis_evidence_records]
        },
    )
    req_full = req.model_copy(
        update={"evidence_records": [*req.evidence_records, *route_res.analysis_evidence_records]}
    )

    # First verify fail-closed when trusted_taint_producers is EMPTY (line 73 relied on AST taint)
    policy_no_ast = CorrelationTrustPolicy(
        approved_rulesets=(REVIEWED_CLOUDFLARE_RULESET_ENTRY,),
        trusted_route_producers=(REVIEWED_STATIC_ROUTE_PRODUCER,),
    )
    cor_no_ast = correlate_evidence(
        req_full,
        input_result=inp_res,
        sink_result=sink_res,
        route_binding_artifacts=route_res.route_binding_artifacts,
        trust_policy=policy_no_ast,
    )
    users_scope_untrusted = next(s for s in cor_no_ast.sink_scopes if s.sink_id == "SNK-001")
    assert users_scope_untrusted.flow_trust == FlowTrust.UNTRUSTED_TAINT

    # Now with REVIEWED_AST_TAINT_PRODUCER trusted -> BOTH id & keyword become INPUT_SINK VERIFIED!
    policy_trusted = CorrelationTrustPolicy(
        approved_rulesets=(REVIEWED_CLOUDFLARE_RULESET_ENTRY,),
        trusted_route_producers=(REVIEWED_STATIC_ROUTE_PRODUCER,),
        trusted_taint_producers=(REVIEWED_AST_TAINT_PRODUCER,),
    )
    cor_res = correlate_evidence(
        req_full,
        input_result=inp_res,
        sink_result=sink_res,
        route_binding_artifacts=route_res.route_binding_artifacts,
        trust_policy=policy_trusted,
    )

    input_by_id = {i.input_id: i for i in inp_res.inputs}
    input_sink_recs = [r for r in cor_res.records if r.kind == CorrelationKind.INPUT_SINK]
    endpoint_sink_recs = [r for r in cor_res.records if r.kind == CorrelationKind.ENDPOINT_SINK]

    assert len(input_sink_recs) == 2
    assert len(endpoint_sink_recs) == 0
    matched_params = {
        input_by_id[r.input_ref].parameter_name for r in input_sink_recs if r.input_ref
    }
    assert matched_params == {"id", "keyword"}
    assert all(r.status == CorrelationStatus.VERIFIED for r in input_sink_recs)
    assert all(
        r.sink_relationship == SinkRelationship.STATIC_TAINT_FLOW_FOUND for r in input_sink_recs
    )

    # Full handoff validates cleanly
    output = Module2Output(
        assessment_id=req.target_model.assessment_id,
        target_id=req.target_model.target_id,
        generated_at=datetime.now(UTC),
        analysis_evidence_records=[
            *sink_res.analysis_evidence_records,
            *route_res.analysis_evidence_records,
        ],
        inputs=list(inp_res.inputs),
        sink_candidates=list(sink_res.sink_candidates),
    )
    validate_module2_handoff(output, req)


# ---------------------------------------------------------------------------
# 3. Fallback ENDPOINT_SINK carries candidate_input_names_in_handler & code slice
# ---------------------------------------------------------------------------


def test_fallback_endpoint_sink_attaches_handler_candidates_and_slice(tmp_path: Path) -> None:
    repo = tmp_path / "interproc_repo"
    (repo / "src").mkdir(parents=True)
    # Interprocedural helper obscures def-use edge so intra-procedural falls back to ENDPOINT_SINK,
    # yet AST still observes `keyword` BEFORE sink and excludes `postFilter` AFTER sink!
    (repo / "src" / "index.js").write_text(
        """function runHelper(val) {
  return val;
}
export default {
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    if (path === "/items" && request.method === "POST") {
      const body = await request.json();
      const k = body.keyword;
      const q = runHelper("SELECT * FROM items WHERE k = " + runHelper(k));
      await env.DB.prepare(q).all();
      if (body.postFilter) {
        return Response.json({ filtered: true });
      }
      return Response.json({ ok: true });
    }
  }
};
""",
        encoding="utf-8",
    )
    rev = _git_init_and_commit(repo)

    ep = make_endpoint(
        origin="https://api.lab.local",
        path="/items",
        method="POST",
        observed_parameters=[
            ObservedParameter(
                name="keyword", location=InputLocation.JSON_BODY, evidence_refs=[Id("EVD-001")]
            ),
            ObservedParameter(
                name="postFilter", location=InputLocation.JSON_BODY, evidence_refs=[Id("EVD-001")]
            ),
        ],
    )
    evd1 = make_evidence_record("EVD-001", artifact_type=ArtifactType.HTTP_RAW_EXCHANGE)
    tm = TargetModel(
        target_id=Id("TGT-001"),
        assessment_id=Id("ASM-001"),
        last_updated=FIXED_TIME,
        endpoints=[ep],
    )
    req = Module2AnalysisRequest(
        target_model=tm,
        evidence_records=[evd1],
        source_repo_path=str(repo.resolve()),
    )
    req.target_model.scope_rules = make_scope_rules(
        testing_mode=TestingMode.WHITEBOX,
        source_repository_ref=str(repo.resolve()),
    )

    finding = make_opengrep_finding(
        rule_id="cloudflare-workers.tainted-d1-sql-injection",
        file="src/index.js",
        start_line=12,
        snippet="await env.DB.prepare(q).all();",
        dataflow_trace=None,
    )
    env = make_opengrep_envelope([finding], path=str(repo.resolve()))
    env["data"].update(
        {
            "ruleset_sha256": PINNED_CLOUDFLARE_RULESET_SHA256,
            "source_revision": rev,
            "source_repository_ref": str(repo.resolve()),
            "execution_ref": "EXEC-902",
        }
    )

    inp_res = extract_input_candidates(req)
    sink_res = extract_sink_candidates(req, opengrep_payload=env, enable_ast_taint=True)
    route_res = extract_route_bindings(
        req,
        existing_evidence_ids={
            e.evidence_id for e in [*req.evidence_records, *sink_res.analysis_evidence_records]
        },
    )
    req_full = req.model_copy(
        update={"evidence_records": [*req.evidence_records, *route_res.analysis_evidence_records]}
    )
    policy = CorrelationTrustPolicy(
        approved_rulesets=(REVIEWED_CLOUDFLARE_RULESET_ENTRY,),
        trusted_route_producers=(REVIEWED_STATIC_ROUTE_PRODUCER,),
        trusted_taint_producers=(REVIEWED_AST_TAINT_PRODUCER,),
    )
    cor_res = correlate_evidence(
        req_full,
        input_result=inp_res,
        sink_result=sink_res,
        route_binding_artifacts=route_res.route_binding_artifacts,
        trust_policy=policy,
    )

    ep_sinks = [r for r in cor_res.records if r.kind == CorrelationKind.ENDPOINT_SINK]
    assert len(ep_sinks) == 1
    assert ep_sinks[0].candidate_input_names_in_handler == ("keyword",)
    assert ep_sinks[0].handler_code_slice is not None
    assert "env.DB.prepare(q)" in ep_sinks[0].handler_code_slice
