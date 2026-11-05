"""Deterministic, AST-based Route Binding Extraction (M2-T03b).

Extracts endpoint-to-source-handler bindings (RouteBindingArtifactRef) with
schema "websecuritycheck.route_binding_artifact.v1" using real AST parsers:
- Tree-sitter for JavaScript and TypeScript (Cloudflare Workers and JS/TS routers)
- Python ast module for framework route decorators (Flask, FastAPI, etc.)
"""

from __future__ import annotations

import ast
import hashlib
import json
import re
import uuid
from collections.abc import Set
from datetime import UTC, datetime
from pathlib import Path

from websecuritycheck.analysis.correlation import (
    RouteBindingArtifactRef,
    TrustedRouteProducer,
)
from websecuritycheck.analysis.semgrep_adapter import (
    _IGNORED_DIRS,
    resolve_source_snapshot,
    validate_source_analysis_scope,
)
from websecuritycheck.analysis.sinks import is_safe_sink_path, normalize_sink_file_path
from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    EndpointDefinition,
    EvidenceArtifactRecord,
    Id,
    TestingMode,
)
from websecuritycheck.domain.analysis_models import (
    EvidenceId,
    Module2AnalysisRequest,
    StrictModel,
)
from websecuritycheck.recon.evidence import RecordIdAllocator

# ---------------------------------------------------------------------------
# 1. Constants & Trusted Producer Registration
# ---------------------------------------------------------------------------

STATIC_ROUTE_PRODUCER_ID = "static_route_extractor"

METHOD_CLOUDFLARE_WORKER = "cloudflare_worker_ast_v1"
METHOD_JS_ROUTER = "js_router_call_ast_v1"
METHOD_PY_DECORATOR = "python_decorator_ast_v1"

METHOD_DIGEST_CLOUDFLARE_WORKER = hashlib.sha256(
    b"websecuritycheck.route_binding.cloudflare_worker_ast_v1"
).hexdigest()
METHOD_DIGEST_JS_ROUTER = hashlib.sha256(
    b"websecuritycheck.route_binding.js_router_call_ast_v1"
).hexdigest()
METHOD_DIGEST_PY_DECORATOR = hashlib.sha256(
    b"websecuritycheck.route_binding.python_decorator_ast_v1"
).hexdigest()

REVIEWED_STATIC_ROUTE_PRODUCER = TrustedRouteProducer(
    producer_id=STATIC_ROUTE_PRODUCER_ID,
    approved_methods=frozenset(
        {
            METHOD_CLOUDFLARE_WORKER,
            METHOD_JS_ROUTER,
            METHOD_PY_DECORATOR,
        }
    ),
    approved_method_digests=frozenset(
        {
            METHOD_DIGEST_CLOUDFLARE_WORKER,
            METHOD_DIGEST_JS_ROUTER,
            METHOD_DIGEST_PY_DECORATOR,
        }
    ),
    review_ref="SEC-REV-M2-T03B-001",
)

# ---------------------------------------------------------------------------
# 2. Result Models
# ---------------------------------------------------------------------------


class ExtractedRawRoute(StrictModel):
    """Raw route handler candidate extracted directly from an AST."""

    path_template: str
    methods: tuple[str, ...] = ()
    file_path: str
    start_line: int
    end_line: int
    extraction_method: str
    extraction_method_digest: str


class RouteBindingExtractionResult(StrictModel):
    """Deterministic output of Module 2 route binding extraction."""

    route_binding_artifacts: tuple[RouteBindingArtifactRef, ...] = ()
    analysis_evidence_records: tuple[EvidenceArtifactRecord, ...] = ()
    artifact_manifests: tuple[ArtifactManifest, ...] = ()
    source_revision: str | None = None
    source_tree_sha256: str | None = None
    execution_ref: str | None = None
    limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


# ---------------------------------------------------------------------------
# 3. Path & Parameter Normalization Helpers
# ---------------------------------------------------------------------------

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}|:[a-zA-Z0-9_-]+|<(?:[a-zA-Z0-9_-]+:)?[a-zA-Z0-9_-]+>")


def _normalize_path_segments(path_str: str) -> tuple[str, ...]:
    """Split path into normalized segments with dynamic parameters replaced by '{}'."""
    clean = path_str.strip().split("?")[0].strip("/")
    if not clean:
        return ("",)
    segments = []
    for part in clean.split("/"):
        if _PATH_PARAM_RE.fullmatch(part) or part == "{param}":
            segments.append("{}")
        else:
            segments.append(part)
    return tuple(segments)


# ---------------------------------------------------------------------------
# 4. JavaScript / TypeScript AST Route Extraction (Tree-sitter)
# ---------------------------------------------------------------------------


def _extract_js_ts_routes(
    file_path: Path, rel_path_str: str, content_bytes: bytes, is_ts: bool = False
) -> tuple[list[ExtractedRawRoute], list[str], list[str]]:
    """Parse JavaScript/TypeScript with Tree-sitter and extract route candidates."""
    try:
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except ImportError:
        return [], ["Tree-sitter dependencies unavailable"], []

    lang_func = tsts.language_typescript() if is_ts else tsjs.language()
    lang = Language(lang_func)
    parser = Parser(lang)
    tree = parser.parse(content_bytes)

    if tree.root_node.has_error:
        return [], [], [f"AST_SYNTAX_WARNING:{rel_path_str}"]

    # Collect all AST nodes iteratively to prevent deep recursion issues
    stack = [tree.root_node]
    all_nodes = []
    while stack:
        curr = stack.pop()
        all_nodes.append(curr)
        for child in reversed(curr.children):
            stack.append(child)

    routes: list[ExtractedRawRoute] = []
    warnings: list[str] = []

    # 1. Map regex variable declarations: const userMatch = path.match(/^\/api\/users\/([^/]+)$/)
    regex_vars: dict[str, str] = {}
    for node in all_nodes:
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            val_node = node.child_by_field_name("value")
            if name_node and val_node and val_node.type == "call_expression":
                fn = val_node.child_by_field_name("function")
                args = val_node.child_by_field_name("arguments")
                if fn and args and fn.type == "member_expression":
                    prop = fn.child_by_field_name("property")
                    if prop and prop.text == b"match":
                        for a in args.children:
                            if a.type == "regex":
                                regex_vars[name_node.text.decode("utf-8")] = a.text.decode("utf-8")

    # 2. Extract Cloudflare Worker fetch routes
    for node in all_nodes:
        if node.type != "if_statement":
            continue

        cond = node.child_by_field_name("condition")
        consequence = node.child_by_field_name("consequence")
        if not cond or not consequence:
            continue

        while cond and cond.type == "parenthesized_expression":
            cond = cond.named_children[0] if cond.named_children else None

        if not cond:
            continue

        path_literal: str | None = None
        extracted_methods: set[str] = set()

        sub_conds = []
        if cond.type == "binary_expression":
            op = cond.child_by_field_name("operator") or cond.child(1)
            if op and op.text in (b"&&", b"||"):
                sub_conds = [cond.child_by_field_name("left"), cond.child_by_field_name("right")]
            else:
                sub_conds = [cond]
        else:
            sub_conds = [cond]

        for sc in sub_conds:
            if not sc:
                continue
            while sc.type == "parenthesized_expression":
                sc = sc.named_children[0] if sc.named_children else None
                if not sc:
                    break
            if not sc:
                continue
            if sc.type == "binary_expression":
                left = sc.child_by_field_name("left")
                op = sc.child_by_field_name("operator") or sc.child(1)
                right = sc.child_by_field_name("right")
                if op and op.text in (b"===", b"=="):
                    if left and left.text in (b"path", b"url.pathname", b"pathname"):
                        if right and right.type == "string":
                            path_literal = right.text.decode("utf-8").strip('"\'')
                    elif (
                        right
                        and right.text in (b"path", b"url.pathname", b"pathname")
                        and left
                        and left.type == "string"
                    ):
                        path_literal = left.text.decode("utf-8").strip('"\'')
                    elif (
                        left
                        and left.text in (b"method", b"request.method")
                        and right
                        and right.type == "string"
                    ):
                        extracted_methods.add(right.text.decode("utf-8").strip('"\'').upper())
                    elif (
                        right
                        and right.text in (b"method", b"request.method")
                        and left
                        and left.type == "string"
                    ):
                        extracted_methods.add(left.text.decode("utf-8").strip('"\'').upper())

        if not path_literal and cond.type == "identifier":
            var_name = cond.text.decode("utf-8")
            if var_name in regex_vars:
                raw_regex = regex_vars[var_name]
                # Validate anchored regex
                m = re.match(r"^/\^(.+)\$/[a-z]*$", raw_regex)
                if m:
                    pattern = m.group(1).replace(r"\/", "/")
                    # Convert single-segment capture groups to {param}
                    normalized = re.sub(r"\([^)]+\)", "{param}", pattern)
                    path_literal = normalized
                else:
                    warnings.append(f"UNSUPPORTED_DYNAMIC_ROUTE_REGEX:{raw_regex}")

        if path_literal:
            start_l = node.start_point.row + 1
            end_l = node.end_point.row + 1

            # Detect method guards in consequence statements
            c_stack = [consequence]
            while c_stack:
                cn = c_stack.pop()
                if cn.type == "if_statement":
                    inner_cond = cn.child_by_field_name("condition")
                    while inner_cond and inner_cond.type == "parenthesized_expression":
                        inner_cond = (
                        inner_cond.named_children[0]
                        if inner_cond.named_children
                        else None
                    )
                    if inner_cond and inner_cond.type == "binary_expression":
                        m_left = inner_cond.child_by_field_name("left")
                        m_op = inner_cond.child_by_field_name("operator") or inner_cond.child(1)
                        m_right = inner_cond.child_by_field_name("right")
                        is_method_op = m_op and (
                            m_op.text in (b"!==", b"!=") or m_op.text in (b"===", b"==")
                        )
                        is_method_left = m_left and m_left.text in (b"method", b"request.method")
                        if is_method_op and is_method_left and m_right and m_right.type == "string":
                            extracted_methods.add(
                                m_right.text.decode("utf-8").strip('"\'').upper()
                            )
                for c in reversed(cn.children):
                    c_stack.append(c)

            routes.append(
                ExtractedRawRoute(
                    path_template=path_literal,
                    methods=tuple(sorted(extracted_methods)),
                    file_path=rel_path_str,
                    start_line=start_l,
                    end_line=end_l,
                    extraction_method=METHOD_CLOUDFLARE_WORKER,
                    extraction_method_digest=METHOD_DIGEST_CLOUDFLARE_WORKER,
                )
            )

    # 3. Extract Express / Hono router calls: app.get("/path", ...)
    http_methods = {b"get", b"post", b"put", b"delete", b"patch", b"options", b"head"}
    for node in all_nodes:
        if node.type == "call_expression":
            fn = node.child_by_field_name("function")
            args = node.child_by_field_name("arguments")
            if fn and args and fn.type == "member_expression":
                prop = fn.child_by_field_name("property")
                if prop and prop.text and prop.text.lower() in http_methods:
                    method_str = prop.text.decode("utf-8").upper()
                    obj = fn.child_by_field_name("object")
                    obj_text = obj.text.decode("utf-8").lower() if obj and obj.text else ""
                    # Ignore common map/params/URL accessors
                    ignore_objs = {
                        "url", "searchparams", "formdata", "headers",
                        "request", "req", "map", "params", "data",
                    }
                    if obj_text in ignore_objs:
                        continue
                    if args.named_children and args.named_children[0].type == "string":
                        p_lit = args.named_children[0].text.decode("utf-8").strip('"\'')
                        if not p_lit.startswith("/"):
                            continue
                        start_l = node.start_point.row + 1
                        end_l = node.end_point.row + 1
                        routes.append(
                            ExtractedRawRoute(
                                path_template=p_lit,
                                methods=(method_str,),
                                file_path=rel_path_str,
                                start_line=start_l,
                                end_line=end_l,
                                extraction_method=METHOD_JS_ROUTER,
                                extraction_method_digest=METHOD_DIGEST_JS_ROUTER,
                            )
                        )

    return routes, [], warnings


# ---------------------------------------------------------------------------
# 5. Python AST Route Extraction (Standard Library ast)
# ---------------------------------------------------------------------------


def _extract_python_routes(
    file_path: Path, rel_path_str: str, content_str: str
) -> tuple[list[ExtractedRawRoute], list[str], list[str]]:
    """Parse Python code using standard library ast and extract decorated routes."""
    try:
        mod = ast.parse(content_str, filename=str(file_path))
    except SyntaxError as exc:
        return [], [], [f"AST_SYNTAX_WARNING:{rel_path_str}:{exc.lineno}"]

    routes: list[ExtractedRawRoute] = []

    for item in ast.walk(mod):
        if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
            continue

        for dec in item.decorator_list:
            if not isinstance(dec, ast.Call):
                continue

            dec_fn = dec.func
            methods: set[str] = set()
            path_str: str | None = None

            # Pattern: @app.route("/path", methods=["GET", "POST"])
            if isinstance(dec_fn, ast.Attribute) and dec_fn.attr == "route":
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    path_str = dec.args[0].value
                for kw in dec.keywords:
                    if kw.arg == "methods" and isinstance(kw.value, (ast.List, ast.Tuple, ast.Set)):
                        for elt in kw.value.elts:
                            if isinstance(elt, ast.Constant) and isinstance(elt.value, str):
                                methods.add(elt.value.upper())

            # Pattern: @app.get("/path"), @router.post("/path"), etc.
            elif isinstance(dec_fn, ast.Attribute) and dec_fn.attr.lower() in {
                "get", "post", "put", "delete", "patch", "options", "head"
            }:
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    path_str = dec.args[0].value
                    methods.add(dec_fn.attr.upper())

            if path_str:
                start_l = item.lineno
                end_l = getattr(item, "end_lineno", item.lineno)
                routes.append(
                    ExtractedRawRoute(
                        path_template=path_str,
                        methods=tuple(sorted(methods)),
                        file_path=rel_path_str,
                        start_line=start_l,
                        end_line=end_l,
                        extraction_method=METHOD_PY_DECORATOR,
                        extraction_method_digest=METHOD_DIGEST_PY_DECORATOR,
                    )
                )

    return routes, [], []


# ---------------------------------------------------------------------------
# 6. Main Orchestrator: extract_route_bindings
# ---------------------------------------------------------------------------


def extract_route_bindings(
    request: Module2AnalysisRequest,
    *,
    evidence_allocator: RecordIdAllocator | None = None,
    execution_ref: str | None = None,
    captured_at: datetime | None = None,
    existing_evidence_ids: Set[str] | None = None,
) -> RouteBindingExtractionResult:
    """Deterministically extract RouteBindingArtifactRef items from repository source code."""
    # Step 1: Validate scope and authorization
    _auth_path, refusal = validate_source_analysis_scope(request, require_existing_filesystem=False)
    if refusal is not None:
        return RouteBindingExtractionResult(limitations=(refusal,))

    rules = request.target_model.scope_rules
    if (
        rules is None
        or rules.testing_mode == TestingMode.BLACKBOX
        or not request.source_repo_path
    ):
        return RouteBindingExtractionResult(limitations=("BLACKBOX_OR_MISSING_SOURCE_REPO",))

    repo_root = Path(request.source_repo_path).resolve()
    if not repo_root.exists() or not repo_root.is_dir():
        return RouteBindingExtractionResult(
            limitations=(f"Source repository path does not exist on disk: {repo_root}",)
        )

    # Step 2: Resolve snapshot identity
    snapshot = resolve_source_snapshot(repo_root)
    if snapshot.error:
        return RouteBindingExtractionResult(limitations=(f"Snapshot error: {snapshot.error}",))
    if not snapshot.source_revision:
        return RouteBindingExtractionResult(limitations=("MISSING_SOURCE_REVISION",))

    limitations: list[str] = []
    warnings: list[str] = []

    # Step 3: Scan and parse source files
    extracted_routes: list[ExtractedRawRoute] = []
    all_files: list[Path] = []
    for cand in sorted(repo_root.rglob("*")):
        if cand.is_file():
            try:
                rel = cand.relative_to(repo_root)
            except ValueError:
                continue
            if not any(part in _IGNORED_DIRS for part in rel.parts):
                all_files.append(cand)

    for file_path in all_files:
        rel_posix = normalize_sink_file_path(file_path.relative_to(repo_root).as_posix())
        if not is_safe_sink_path(rel_posix):
            continue

        suffix = file_path.suffix.lower()
        if suffix in {".js", ".mjs", ".cjs", ".jsx"}:
            try:
                c_bytes = file_path.read_bytes()
            except OSError as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_js_ts_routes(
                file_path, rel_posix, c_bytes, is_ts=False
            )
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

        elif suffix in {".ts", ".tsx"}:
            try:
                c_bytes = file_path.read_bytes()
            except OSError as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_js_ts_routes(
                file_path, rel_posix, c_bytes, is_ts=True
            )
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

        elif suffix == ".py":
            try:
                c_str = file_path.read_text(encoding="utf-8")
            except (OSError, UnicodeDecodeError) as exc:
                warnings.append(f"FAILED_READ_SOURCE_FILE:{rel_posix}:{exc}")
                continue
            r_list, r_lims, r_warns = _extract_python_routes(file_path, rel_posix, c_str)
            extracted_routes.extend(r_list)
            limitations.extend(r_lims)
            warnings.extend(r_warns)

    # Step 4: Deterministically match against TargetModel.endpoints
    known_endpoints = request.target_model.endpoints
    matched_bindings: list[tuple[EndpointDefinition, ExtractedRawRoute]] = []

    for ep in known_endpoints:
        ep_segments = _normalize_path_segments(ep.path)
        ep_method = ep.method.upper().strip()

        candidate_routes = []
        for r in extracted_routes:
            r_segments = _normalize_path_segments(r.path_template)
            if r_segments == ep_segments and (not r.methods or ep_method in r.methods):
                candidate_routes.append(r)

        if len(candidate_routes) == 1:
            matched_bindings.append((ep, candidate_routes[0]))
        elif len(candidate_routes) > 1:
            warnings.append(
                f"AMBIGUOUS_ROUTE_BINDING:{ep.endpoint_id} matches {len(candidate_routes)} handlers"
            )

    # Sort deterministically by endpoint_id
    matched_bindings.sort(
        key=lambda pair: (pair[0].endpoint_id, pair[1].file_path, pair[1].start_line)
    )

    # Seed allocator
    all_known_evidence: set[str] = set()
    for evd in request.evidence_records:
        all_known_evidence.add(str(evd.evidence_id))
    for ep in request.target_model.endpoints:
        all_known_evidence.update(str(r) for r in ep.evidence_refs)
    if existing_evidence_ids:
        all_known_evidence.update(str(x) for x in existing_evidence_ids)

    allocator = evidence_allocator or RecordIdAllocator(all_known_evidence)
    capture_time = captured_at or request.target_model.last_updated or datetime.now(UTC)
    exec_ref = execution_ref or f"EXEC-{uuid.uuid4().int}"

    route_artifacts: list[RouteBindingArtifactRef] = []
    evidence_records: list[EvidenceArtifactRecord] = []
    manifests: list[ArtifactManifest] = []

    for ep, r in matched_bindings:
        evd_id = Id(allocator.new("EVD"))
        art_ref = f"route-binding-{ep.endpoint_id.lower()}"

        payload = {
            "schema": "websecuritycheck.route_binding_artifact.v1",
            "assessment_id": request.target_model.assessment_id,
            "endpoint_id": ep.endpoint_id,
            "method": ep.method.upper().strip(),
            "path": ep.path.strip(),
            "file_path": r.file_path,
            "start_line": r.start_line,
            "end_line": r.end_line,
        }
        content_str = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=False)
        content_bytes = content_str.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        manifest = ArtifactManifest(
            artifact_ref=art_ref,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            content=content_str,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            metadata={
                "endpoint_id": ep.endpoint_id,
                "file_path": r.file_path,
                "start_line": r.start_line,
                "end_line": r.end_line,
            },
        )
        manifests.append(manifest)

        evd_record = EvidenceArtifactRecord(
            evidence_id=evd_id,
            assessment_id=request.target_model.assessment_id,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            artifact_ref=art_ref,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            captured_at=capture_time,
            execution_ref=Id(exec_ref),
            source_tool_id=STATIC_ROUTE_PRODUCER_ID,
            provenance={
                "extraction_method": r.extraction_method,
                "extraction_method_digest": r.extraction_method_digest,
                "source_repository_ref": rules.source_repository_ref,
                "source_repo_path": str(repo_root),
                "source_revision": snapshot.source_revision,
                "source_tree_sha256": snapshot.tree_sha256,
                "worktree_dirty": snapshot.is_dirty,
                "execution_ref": exec_ref,
                "derivation_modality": "static_source_snapshot",
            },
            metadata={
                "endpoint_id": ep.endpoint_id,
                "file_path": r.file_path,
                "start_line": r.start_line,
                "end_line": r.end_line,
            },
        )
        evidence_records.append(evd_record)

        rb_ref = RouteBindingArtifactRef(
            evidence_ref=EvidenceId(str(evd_id)),
            manifest=manifest,
        )
        route_artifacts.append(rb_ref)

    return RouteBindingExtractionResult(
        route_binding_artifacts=tuple(route_artifacts),
        analysis_evidence_records=tuple(evidence_records),
        artifact_manifests=tuple(manifests),
        source_revision=snapshot.source_revision,
        source_tree_sha256=snapshot.tree_sha256,
        execution_ref=exec_ref,
        limitations=tuple(sorted(set(limitations))),
        warnings=tuple(sorted(set(warnings))),
    )


__all__ = [
    "METHOD_CLOUDFLARE_WORKER",
    "METHOD_DIGEST_CLOUDFLARE_WORKER",
    "METHOD_DIGEST_JS_ROUTER",
    "METHOD_DIGEST_PY_DECORATOR",
    "METHOD_JS_ROUTER",
    "METHOD_PY_DECORATOR",
    "REVIEWED_STATIC_ROUTE_PRODUCER",
    "STATIC_ROUTE_PRODUCER_ID",
    "RouteBindingExtractionResult",
    "extract_route_bindings",
]
