"""Python AST intra-procedural backward taint slicer and dispatcher entrypoint."""

from __future__ import annotations

import ast
from pathlib import Path

from websecuritycheck.domain.analysis_models import SinkKind
from websecuritycheck.domain.enums import InputLocation

from .js_ts_tracer import _analyze_js_ts_sink
from .models import (
    _CMDI_SINK_METHODS,
    _EVAL_SINK_FUNCS,
    _JS_SUFFIXES,
    _NUMERIC_COERCION_FUNCS,
    _SQL_SINK_METHODS,
    _STRING_PROPAGATOR_METHODS,
    _TS_SUFFIXES,
    AstTaintTraceResult,
    ResolvedTaintInput,
    _regex_guard_is_strict,
    _resolve_repo_file,
    deduplicate_resolved_inputs,
)


def _py_is_static_expr(node: ast.AST | None) -> bool:
    if node is None:
        return True
    if isinstance(node, ast.Constant):
        return True
    if isinstance(node, ast.JoinedStr):
        return not any(isinstance(v, ast.FormattedValue) for v in node.values)
    if isinstance(node, ast.BinOp):
        return _py_is_static_expr(node.left) and _py_is_static_expr(node.right)
    return False


def _py_chain(node: ast.AST) -> tuple[ast.AST, list[str]]:
    parts: list[str] = []
    curr = node
    while True:
        if isinstance(curr, ast.Attribute):
            parts.append(curr.attr)
            curr = curr.value
        elif isinstance(curr, ast.Subscript):
            slc = curr.slice
            if isinstance(slc, ast.Constant) and isinstance(slc.value, str):
                parts.append(slc.value)
                curr = curr.value
            else:
                return node, []
        else:
            break
    parts.reverse()
    return curr, parts


def _py_check_guard_vars(if_node: ast.If) -> set[str]:
    """Detect pre-sink early-return/raise numeric regex guard on variables."""
    if not any(isinstance(s, (ast.Return, ast.Raise)) for s in if_node.body):
        return set()
    test = if_node.test
    if isinstance(test, ast.UnaryOp) and isinstance(test.op, ast.Not):
        inner = test.operand
        if (
            isinstance(inner, ast.Call)
            and isinstance(inner.func, ast.Attribute)
            and inner.func.attr in {"match", "fullmatch"}
            and len(inner.args) >= 2
        ):
            pat = inner.args[0]
            if (
                isinstance(pat, ast.Constant)
                and isinstance(pat.value, str)
                and _regex_guard_is_strict(pat.value)
                and isinstance(inner.args[1], ast.Name)
            ):
                return {inner.args[1].id}
    return set()


def _py_classify_request_container(
    obj: ast.AST,
    defs: dict[str, list[tuple[int, ast.AST]]],
    line: int,
    param_path: str,
    visited: frozenset[str],
) -> tuple[InputLocation, str, int] | None:
    if isinstance(obj, ast.Await):
        obj = obj.value

    if (
        isinstance(obj, ast.Call)
        and isinstance(obj.func, ast.Attribute)
        and obj.func.attr in {"get_json", "json"}
        and isinstance(obj.func.value, ast.Name)
        and obj.func.value.id in {"request", "req"}
    ):
        return InputLocation.JSON_BODY, f"body.{param_path}", getattr(obj, "lineno", line)

    if (
        isinstance(obj, ast.Attribute)
        and isinstance(obj.value, ast.Name)
        and obj.value.id == "request"
    ):
        attr = obj.attr
        mapping = {
            "args": (InputLocation.QUERY, f"request.args.get('{param_path}')"),
            "form": (InputLocation.FORM, f"request.form.get('{param_path}')"),
            "headers": (InputLocation.HEADER, f"request.headers.get('{param_path}')"),
            "cookies": (InputLocation.COOKIE, f"request.cookies.get('{param_path}')"),
            "view_args": (InputLocation.PATH, f"request.view_args['{param_path}']"),
            "json": (InputLocation.JSON_BODY, f"body.{param_path}"),
            "GET": (InputLocation.QUERY, f"request.GET.get('{param_path}')"),
            "POST": (InputLocation.FORM, f"request.POST.get('{param_path}')"),
            "COOKIES": (InputLocation.COOKIE, f"request.COOKIES.get('{param_path}')"),
        }
        if attr in mapping:
            loc, snip = mapping[attr]
            return loc, snip, getattr(obj, "lineno", line)

    if isinstance(obj, ast.Name) and obj.id not in visited:
        assigns = [pair for pair in defs.get(obj.id, ()) if pair[0] <= line]
        if assigns:
            def_line, def_expr = max(assigns, key=lambda p: p[0])
            res = _py_classify_request_container(
                def_expr, defs, def_line, param_path, visited | {obj.id}
            )
            if res is not None:
                return res[0], res[1], res[2]
    return None


def _py_match_direct_source(
    node: ast.AST,
    defs: dict[str, list[tuple[int, ast.AST]]],
    use_line: int,
    visited: frozenset[str],
) -> ResolvedTaintInput | None:
    line = getattr(node, "lineno", use_line)

    if (
        isinstance(node, ast.Call)
        and isinstance(node.func, ast.Attribute)
        and node.func.attr == "get"
        and node.args
        and isinstance(node.args[0], ast.Constant)
        and isinstance(node.args[0].value, str)
    ):
        param = node.args[0].value
        obj = node.func.value
        loc_and_snip = _py_classify_request_container(obj, defs, line, param, visited)
        if loc_and_snip is not None:
            loc, snip, src_l = loc_and_snip
            return ResolvedTaintInput(
                location=loc,
                parameter_name=param,
                accessor_snippet=snip,
                source_file="",
                source_line=src_l,
            )

    if isinstance(node, ast.Subscript):
        root, chain = _py_chain(node)
        if chain:
            joined = ".".join(chain)
            loc_and_snip = _py_classify_request_container(root, defs, line, joined, visited)
            if loc_and_snip is not None:
                loc, snip, src_l = loc_and_snip
                return ResolvedTaintInput(
                    location=loc,
                    parameter_name=joined,
                    accessor_snippet=snip,
                    source_file="",
                    source_line=src_l,
                )

    return None


def _py_resolve_expr(
    node: ast.AST | None,
    *,
    file_path: str,
    defs: dict[str, list[tuple[int, ast.AST]]],
    guards: dict[str, int],
    use_line: int,
    visited: frozenset[str],
    trail: tuple[str, ...],
) -> tuple[list[ResolvedTaintInput], bool]:
    if node is None or _py_is_static_expr(node):
        return [], False

    if isinstance(node, ast.Name) and node.id in guards and guards[node.id] < use_line:
        return [], True

    direct = _py_match_direct_source(node, defs, use_line, visited)
    if direct is not None:
        src_step = f"{file_path}:{direct.source_line} (source: {direct.accessor_snippet})"
        return [
            direct.model_copy(
                update={"source_file": file_path, "propagation_steps": (src_step, *trail)}
            )
        ], False

    if isinstance(node, ast.JoinedStr):
        all_found: list[ResolvedTaintInput] = []
        any_san = False
        for v in node.values:
            if isinstance(v, ast.FormattedValue):
                res, san = _py_resolve_expr(
                    v.value,
                    file_path=file_path,
                    defs=defs,
                    guards=guards,
                    use_line=use_line,
                    visited=visited,
                    trail=trail,
                )
                all_found.extend(res)
                any_san = any_san or san
        return all_found, any_san and not all_found

    if isinstance(node, ast.BinOp):
        res_l, san_l = _py_resolve_expr(
            node.left,
            file_path=file_path,
            defs=defs,
            guards=guards,
            use_line=use_line,
            visited=visited,
            trail=trail,
        )
        res_r, san_r = _py_resolve_expr(
            node.right,
            file_path=file_path,
            defs=defs,
            guards=guards,
            use_line=use_line,
            visited=visited,
            trail=trail,
        )
        combined = [*res_l, *res_r]
        return combined, (san_l or san_r) and not combined

    if isinstance(node, ast.Call):
        if isinstance(node.func, ast.Name) and node.func.id in _NUMERIC_COERCION_FUNCS:
            return [], True
        if isinstance(node.func, ast.Attribute) and node.func.attr in _STRING_PROPAGATOR_METHODS:
            if node.func.attr == "format":
                out: list[ResolvedTaintInput] = []
                for arg in [*node.args, *(k.value for k in node.keywords)]:
                    res, _ = _py_resolve_expr(
                        arg,
                        file_path=file_path,
                        defs=defs,
                        guards=guards,
                        use_line=use_line,
                        visited=visited,
                        trail=trail,
                    )
                    out.extend(res)
                return out, False
            return _py_resolve_expr(
                node.func.value,
                file_path=file_path,
                defs=defs,
                guards=guards,
                use_line=use_line,
                visited=visited,
                trail=trail,
            )

    if isinstance(node, ast.Name):
        if node.id in visited:
            return [], False
        assigns = [pair for pair in defs.get(node.id, ()) if pair[0] <= use_line]
        if not assigns:
            return [], False
        def_line, def_expr = max(assigns, key=lambda p: p[0])
        if node.id in guards and guards[node.id] < use_line:
            return [], True
        prop_step = f"{file_path}:{def_line} (propagator: {node.id})"
        return _py_resolve_expr(
            def_expr,
            file_path=file_path,
            defs=defs,
            guards=guards,
            use_line=def_line,
            visited=visited | {node.id},
            trail=(prop_step, *trail),
        )

    return [], False


def _analyze_python_sink(
    content_str: str,
    *,
    file_path: str,
    sink_line: int,
    sink_kind: SinkKind,
    handler_span: tuple[int, int] | None,
) -> AstTaintTraceResult:
    lines = content_str.splitlines()
    raw_line = lines[sink_line - 1].strip() if 1 <= sink_line <= len(lines) else None
    try:
        mod = ast.parse(content_str, filename=file_path)
    except SyntaxError:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            sink_code_line=raw_line,
        )

    enclosing_fn: ast.AST = mod
    best_span_len = 10**9
    for node in ast.walk(mod):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef)):
            s_l = node.lineno
            e_l = getattr(node, "end_lineno", s_l)
            if s_l <= sink_line <= e_l and (e_l - s_l) < best_span_len:
                enclosing_fn = node
                best_span_len = e_l - s_l

    eff_start = handler_span[0] if handler_span else getattr(enclosing_fn, "lineno", 1)
    eff_end = (
        handler_span[1] if handler_span else getattr(enclosing_fn, "end_lineno", len(lines) or 1)
    )

    defs: dict[str, list[tuple[int, ast.AST]]] = {}
    guards: dict[str, int] = {}

    def walk_active(stmt_list: list[ast.stmt]) -> None:
        for stmt in stmt_list:
            sl = getattr(stmt, "lineno", 0)
            el = getattr(stmt, "end_lineno", sl)
            if sl > sink_line:
                continue
            if isinstance(stmt, ast.If):
                in_body = stmt.body and stmt.body[0].lineno <= sink_line <= getattr(
                    stmt.body[-1], "end_lineno", sink_line
                )
                in_else = stmt.orelse and stmt.orelse[0].lineno <= sink_line <= getattr(
                    stmt.orelse[-1], "end_lineno", sink_line
                )
                if in_body:
                    walk_active(stmt.body)
                elif in_else:
                    walk_active(stmt.orelse)
                elif el < sink_line:
                    for gv in _py_check_guard_vars(stmt):
                        guards[gv] = max(guards.get(gv, 0), sl)
            elif isinstance(stmt, ast.Assign):
                for tgt in stmt.targets:
                    if isinstance(tgt, ast.Name):
                        defs.setdefault(tgt.id, []).append((sl, stmt.value))
            elif (
                isinstance(stmt, ast.AnnAssign) and isinstance(stmt.target, ast.Name) and stmt.value
            ):
                defs.setdefault(stmt.target.id, []).append((sl, stmt.value))
            elif isinstance(stmt, ast.Try):
                walk_active(stmt.body)
                for h in stmt.handlers:
                    if h.lineno <= sink_line <= getattr(h, "end_lineno", sink_line):
                        walk_active(h.body)

    body_stmts = getattr(enclosing_fn, "body", [])
    walk_active(body_stmts)

    candidate_names: set[str] = set()
    for node in ast.walk(enclosing_fn):
        nl = getattr(node, "lineno", 0)
        if eff_start <= nl <= sink_line and isinstance(node, (ast.Call, ast.Subscript)):
            matched = _py_match_direct_source(node, defs, nl, frozenset())
            if matched is not None:
                candidate_names.add(matched.parameter_name)

    call_cands = [
        node
        for node in ast.walk(enclosing_fn)
        if isinstance(node, ast.Call) and getattr(node, "lineno", 0) == sink_line
    ]
    if not call_cands:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=eff_start,
            handler_end_line=eff_end,
            sink_code_line=raw_line,
            candidate_input_names_in_handler=tuple(sorted(candidate_names)),
        )

    def _py_call_prio(c: ast.Call) -> int:
        if isinstance(c.func, ast.Attribute):
            if (
                sink_kind in {SinkKind.SQL_QUERY, SinkKind.ORM_QUERY}
                and c.func.attr in _SQL_SINK_METHODS
            ):
                return 10
            if sink_kind == SinkKind.OS_COMMAND and c.func.attr in _CMDI_SINK_METHODS:
                return 10
        elif isinstance(c.func, ast.Name) and c.func.id in _EVAL_SINK_FUNCS:
            return 10
        return 1

    sink_call = max(call_cands, key=_py_call_prio)
    args = list(sink_call.args)
    if not args:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=eff_start,
            handler_end_line=eff_end,
            sink_code_line=raw_line,
            candidate_input_names_in_handler=tuple(sorted(candidate_names)),
        )

    if sink_kind in {SinkKind.SQL_QUERY, SinkKind.ORM_QUERY} and _py_is_static_expr(args[0]):
        reason = (
            "Parameterized SQL query with constant template"
            if len(args) > 1 or sink_call.keywords
            else "Static SQL query constant passed to sink"
        )
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=eff_start,
            handler_end_line=eff_end,
            sink_code_line=raw_line,
            has_taint_flow=False,
            is_sanitized_or_parameterized=True,
            sanitization_reason=reason,
            candidate_input_names_in_handler=tuple(sorted(candidate_names)),
        )

    if all(_py_is_static_expr(a) for a in args):
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=eff_start,
            handler_end_line=eff_end,
            sink_code_line=raw_line,
            has_taint_flow=False,
            is_sanitized_or_parameterized=True,
            sanitization_reason="Constant argument passed to sink",
            candidate_input_names_in_handler=tuple(sorted(candidate_names)),
        )

    sink_step = f"{file_path}:{sink_line} (sink: {raw_line or 'sink_call'})"
    all_resolved: list[ResolvedTaintInput] = []
    any_sanitized = False
    for arg in args:
        found, san = _py_resolve_expr(
            arg,
            file_path=file_path,
            defs=defs,
            guards=guards,
            use_line=sink_line,
            visited=frozenset(),
            trail=(sink_step,),
        )
        all_resolved.extend(found)
        any_sanitized = any_sanitized or san

    unique_resolved = deduplicate_resolved_inputs(all_resolved)

    if not unique_resolved and any_sanitized:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=eff_start,
            handler_end_line=eff_end,
            sink_code_line=raw_line,
            has_taint_flow=False,
            is_sanitized_or_parameterized=True,
            sanitization_reason="Pre-sink numeric coercion or strict regex guard",
            candidate_input_names_in_handler=tuple(sorted(candidate_names)),
        )

    steps = list(unique_resolved[0].propagation_steps) if unique_resolved else []
    return AstTaintTraceResult(
        file_path=file_path,
        sink_line=sink_line,
        sink_kind=sink_kind,
        handler_start_line=eff_start,
        handler_end_line=eff_end,
        sink_code_line=raw_line,
        has_taint_flow=bool(unique_resolved),
        resolved_sources=unique_resolved,
        dataflow_steps=tuple(steps),
        candidate_input_names_in_handler=tuple(sorted(candidate_names)),
    )


def trace_intraprocedural_sink_taint(
    repo_root: str | Path,
    *,
    file_path: str,
    sink_line: int,
    sink_kind: SinkKind,
    handler_span: tuple[int, int] | None = None,
    route_path: str | None = None,
) -> AstTaintTraceResult:
    """Run intra-procedural AST backward slicing for a sink in a JS/TS or Python file."""
    resolved = _resolve_repo_file(repo_root, file_path)
    if resolved is None:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
        )

    suffix = resolved.suffix.lower()
    if suffix in _JS_SUFFIXES or suffix in _TS_SUFFIXES:
        try:
            content_bytes = resolved.read_bytes()
        except OSError:
            return AstTaintTraceResult(
                file_path=file_path,
                sink_line=sink_line,
                sink_kind=sink_kind,
            )
        return _analyze_js_ts_sink(
            content_bytes,
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            is_ts=suffix in _TS_SUFFIXES,
            handler_span=handler_span,
            route_path=route_path,
        )

    if suffix == ".py":
        try:
            content_str = resolved.read_text(encoding="utf-8", errors="replace")
        except OSError:
            return AstTaintTraceResult(
                file_path=file_path,
                sink_line=sink_line,
                sink_kind=sink_kind,
            )
        return _analyze_python_sink(
            content_str,
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_span=handler_span,
        )

    return AstTaintTraceResult(
        file_path=file_path,
        sink_line=sink_line,
        sink_kind=sink_kind,
    )


__all__ = ["trace_intraprocedural_sink_taint"]

