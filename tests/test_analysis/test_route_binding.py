"""Unit and integration tests for Deterministic AST Route Binding Extraction (M2-T03b)."""

from __future__ import annotations

import tempfile
from pathlib import Path

import pytest

from test_analysis.fixtures import make_endpoint, make_shop_analysis_request_with_scope
from websecuritycheck.analysis.correlation import (
    CorrelationTrustPolicy,
    RouteBindingArtifactRef,
    verify_route_binding_artifact,
)
from websecuritycheck.analysis.route_binding import (
    METHOD_CLOUDFLARE_WORKER,
    METHOD_DIGEST_CLOUDFLARE_WORKER,
    METHOD_DIGEST_JS_ROUTER,
    METHOD_DIGEST_PY_DECORATOR,
    METHOD_JS_ROUTER,
    METHOD_PY_DECORATOR,
    REVIEWED_STATIC_ROUTE_PRODUCER,
    _extract_js_ts_routes,
    _extract_python_routes,
    extract_route_bindings,
)
from websecuritycheck.analysis.semgrep_adapter import resolve_source_snapshot
from websecuritycheck.domain import TestingMode

CLOUDFLARE_TARGETS_ROOT = (
    Path(__file__).parents[2] / "test-targets" / "cloudflare" / "targets"
)

SYNTHETIC_CF_WORKER = b"""
export default {
    async fetch(request, env, ctx) {
        const url = new URL(request.url);
        const path = url.pathname;
        const method = request.method;

        if (path === "/search" && method === "GET") {
            const q = url.searchParams.get("q");
            eval(q); // line 11 sink
            return new Response("Search result");
        }

        if (path === "/form") {
            if (method === "POST") {
                const data = await request.formData();
                eval(data.get("name")); // line 18 sink
                return new Response("Form processed");
            }
            return new Response("Form page");
        }

        if (path === "/api/health") {
            return new Response(JSON.stringify({ status: "ok" }));
        }

        return new Response("Not Found", { status: 404 });
    }
};
"""


# ---------------------------------------------------------------------------
# 1. Cloudflare Workers AST Extraction (Tree-sitter JS)
# ---------------------------------------------------------------------------


def test_cloudflare_worker_ast_extraction_synthetic() -> None:
    dummy_path = Path("src/index.js")
    routes, limitations, warnings = _extract_js_ts_routes(
        dummy_path, "src/index.js", SYNTHETIC_CF_WORKER, is_ts=False
    )

    assert not limitations
    assert not warnings
    assert len(routes) == 3

    paths = {r.path_template: r for r in routes}
    assert "/search" in paths
    assert "/form" in paths
    assert "/api/health" in paths

    search_route = paths["/search"]
    assert search_route.methods == ("GET",)
    assert search_route.extraction_method == METHOD_CLOUDFLARE_WORKER
    assert search_route.extraction_method_digest == METHOD_DIGEST_CLOUDFLARE_WORKER
    # Line 11 sink falls within search route
    assert search_route.start_line <= 11 <= search_route.end_line

    form_route = paths["/form"]
    assert "POST" in form_route.methods
    # Line 18 sink falls within form route
    assert form_route.start_line <= 18 <= form_route.end_line


@pytest.mark.skipif(
    not (CLOUDFLARE_TARGETS_ROOT / "basic" / "src" / "index.js").exists(),
    reason="Cloudflare live targets only present on Kali or test/cloudflare-targets branch",
)
def test_cloudflare_worker_basic_target_extraction() -> None:
    basic_index = CLOUDFLARE_TARGETS_ROOT / "basic" / "src" / "index.js"
    c_bytes = basic_index.read_bytes()
    routes, limitations, _warnings = _extract_js_ts_routes(
        basic_index, "src/index.js", c_bytes, is_ts=False
    )

    assert not limitations
    paths = {r.path_template: r for r in routes}
    assert "/search" in paths
    assert paths["/search"].start_line <= 144 <= paths["/search"].end_line


# ---------------------------------------------------------------------------
# 2. Python AST Route Extraction (Standard Library AST)
# ---------------------------------------------------------------------------


def test_python_decorator_route_extraction() -> None:
    py_code = '''
from flask import Flask, request
app = Flask(__name__)

@app.route("/login", methods=["GET", "POST"])
def login_handler():
    username = request.form.get("username")
    return "ok"

@app.get("/api/v1/items")
def list_items():
    return {"items": []}

@app.post("/api/v1/items")
def create_item():
    return {"created": True}
'''
    dummy_path = Path("app.py")
    routes, limitations, warnings = _extract_python_routes(
        dummy_path, "app.py", py_code.encode("utf-8")
    )

    assert not limitations
    assert not warnings
    assert len(routes) == 3

    paths = {(r.path_template, frozenset(r.methods)): r for r in routes}
    assert ("/login", frozenset({"GET", "POST"})) in paths
    assert ("/api/v1/items", frozenset({"GET"})) in paths
    assert ("/api/v1/items", frozenset({"POST"})) in paths

    r_login = paths[("/login", frozenset({"GET", "POST"}))]
    assert r_login.extraction_method == METHOD_PY_DECORATOR
    assert r_login.extraction_method_digest == METHOD_DIGEST_PY_DECORATOR
    assert r_login.start_line == 6
    assert r_login.end_line == 8


# ---------------------------------------------------------------------------
# 3. JS/Express Router Call AST Extraction
# ---------------------------------------------------------------------------


def test_js_router_call_extraction() -> None:
    js_code = b"""
const express = require('express');
const app = express();

app.get('/users', (req, res) => {
    res.send('users list');
});

app.post('/users', (req, res) => {
    res.send('user created');
});

const apiRouter = express.Router();
apiRouter.delete('/items', (req, res) => {
    res.send('deleted');
});
"""
    dummy_path = Path("server.js")
    routes, limitations, _warnings = _extract_js_ts_routes(
        dummy_path, "server.js", js_code, is_ts=False
    )

    assert not limitations
    assert len(routes) == 3

    paths = {(r.path_template, frozenset(r.methods)): r for r in routes}
    assert ("/users", frozenset({"GET"})) in paths
    assert ("/users", frozenset({"POST"})) in paths
    assert ("/items", frozenset({"DELETE"})) in paths

    r_users = paths[("/users", frozenset({"GET"}))]
    assert r_users.extraction_method == METHOD_JS_ROUTER
    assert r_users.extraction_method_digest == METHOD_DIGEST_JS_ROUTER


# ---------------------------------------------------------------------------
# 4. Negative Cases & Error Resilience
# ---------------------------------------------------------------------------


def test_unanchored_regex_and_comments_are_ignored() -> None:
    js_code = b"""
export default {
    async fetch(request) {
        const url = new URL(request.url);
        // comment: if (url.pathname === "/commented/route") { return 1; }
        if (url.pathname.includes("/unanchored")) {
            return new Response("ok");
        }
        if (/api\\/v1/.test(url.pathname)) {
            return new Response("unanchored regex");
        }
        return new Response("fallback");
    }
}
"""
    dummy_path = Path("worker.js")
    routes, limitations, _warnings = _extract_js_ts_routes(
        dummy_path, "worker.js", js_code, is_ts=False
    )

    assert not limitations
    # None of the unanchored / commented routes should be extracted
    assert len(routes) == 0


def test_syntax_errors_handled_gracefully() -> None:
    broken_py = b"def syntax_error( unfinished business..."
    dummy_path = Path("broken.py")
    routes, _limitations, warnings = _extract_python_routes(
        dummy_path, "broken.py", broken_py
    )
    assert not routes
    assert any("SYNTAX" in w for w in warnings)


# ---------------------------------------------------------------------------
# 5. End-to-End extract_route_bindings & Verification Against Trust Policy
# ---------------------------------------------------------------------------


def test_extract_route_bindings_e2e_and_verification() -> None:
    import subprocess
    with tempfile.TemporaryDirectory(prefix="m2_route_test_") as tmp_dir:
        repo_path = Path(tmp_dir)
        src_dir = repo_path / "src"
        src_dir.mkdir(parents=True)
        (src_dir / "index.js").write_bytes(SYNTHETIC_CF_WORKER)

        subprocess.run(["git", "init", "-q"], cwd=repo_path, check=True)
        subprocess.run(["git", "config", "user.name", "Test"], cwd=repo_path, check=True)
        subprocess.run(
            ["git", "config", "user.email", "test@example.com"],
            cwd=repo_path,
            check=True,
        )
        subprocess.run(["git", "add", "."], cwd=repo_path, check=True)
        subprocess.run(["git", "commit", "-m", "init", "-q"], cwd=repo_path, check=True)

        endpoints = [
            make_endpoint(path="/search", method="GET"),
            make_endpoint(path="/form", method="POST"),
        ]

        snapshot = resolve_source_snapshot(repo_path)

        request = make_shop_analysis_request_with_scope(
            source_repo_path=str(repo_path.resolve()),
            source_repository_ref=str(repo_path.resolve()),
            testing_mode=TestingMode.GRAYBOX,
        )
        request.target_model.endpoints = endpoints

        result = extract_route_bindings(request)
        assert not result.limitations
        assert len(result.route_binding_artifacts) == 2
        assert len(result.analysis_evidence_records) == 2
        assert len(result.artifact_manifests) == 2

        # Verify artifacts and trust policy integration
        trust_policy = CorrelationTrustPolicy(
            trusted_route_producers=(REVIEWED_STATIC_ROUTE_PRODUCER,)
        )

        full_request = request.model_copy(
            update={"evidence_records": list(result.analysis_evidence_records)}
        )

        for art_ref in result.route_binding_artifacts:
            assert isinstance(art_ref, RouteBindingArtifactRef)
            binding, reason = verify_route_binding_artifact(
                art_ref, full_request, trust_policy=trust_policy
            )
            assert reason == "VERIFIED"
            assert binding is not None
            assert binding.source_revision == snapshot.source_revision
            assert binding.source_tree_sha256 == snapshot.tree_sha256
            assert binding.file_path == "src/index.js"
            if binding.path == "/search":
                assert binding.start_line <= 11 <= binding.end_line
            elif binding.path == "/form":
                assert binding.start_line <= 18 <= binding.end_line


def test_blackbox_testing_mode_refuses_route_extraction() -> None:
    request = make_shop_analysis_request_with_scope(
        source_repo_path=None,
        source_repository_ref=None,
        testing_mode=TestingMode.BLACKBOX,
    )

    result = extract_route_bindings(request)
    assert len(result.route_binding_artifacts) == 0
    assert any("BLACKBOX" in lim for lim in result.limitations)
