"""JavaScript / TypeScript intra-procedural backward taint slicer."""

from __future__ import annotations

import re
from typing import Any

from websecuritycheck.domain.analysis_models import SinkKind
from websecuritycheck.domain.enums import InputLocation

from .js_ts_ast_utils import (
    _js_collect_active_defs_and_guards,
    _js_find_scopes,
    _js_find_sink_call,
    _js_is_static_expr,
    _js_lines,
    _js_member_chain,
    _js_parse,
    _js_string_literal,
    _js_text,
    _js_unwrap_parens,
    _JsDefEntry,
)
from .models import (
    _NUMERIC_COERCION_FUNCS,
    _STRING_PROPAGATOR_METHODS,
    AstTaintTraceResult,
    ResolvedTaintInput,
    _route_path_params,
    deduplicate_resolved_inputs,
)


def _js_latest_def(var_name: str, defs: list[_JsDefEntry], max_line: int) -> _JsDefEntry | None:
    matching = [d for d in defs if d.var_name == var_name and d.line <= max_line]
    return max(matching, key=lambda d: d.line) if matching else None


def _js_is_json_body_expr(node: Any, content_bytes: bytes) -> int | None:
    unwrapped = _js_unwrap_parens(node)
    if unwrapped is None:
        return None
    if unwrapped.type == "call_expression":
        txt = _js_text(unwrapped, content_bytes)
        if re.search(r"\b(?:request|req)\.json\(\)\s*$", txt):
            return _js_lines(unwrapped, content_bytes)[0]
    return None


def _js_is_formdata_var(
    var_name: str, defs: list[_JsDefEntry], max_line: int, content_bytes: bytes
) -> bool:
    d = _js_latest_def(var_name, defs, max_line)
    if d is None:
        return False
    txt = _js_text(d.expr_node, content_bytes)
    return "formData()" in txt


def _js_is_path_match_var(
    var_name: str, defs: list[_JsDefEntry], max_line: int, content_bytes: bytes
) -> bool:
    d = _js_latest_def(var_name, defs, max_line)
    if d is None:
        return False
    txt = _js_text(d.expr_node, content_bytes)
    return ".match(" in txt and ("path" in txt.lower() or "pathname" in txt.lower())


def _js_match_direct_source(
    node: Any,
    content_bytes: bytes,
    defs: list[_JsDefEntry],
    use_line: int,
    route_params: list[str],
    visited: frozenset[str],
) -> ResolvedTaintInput | None:
    """Recognize direct HTTP input accessor AST patterns or member accesses on them."""
    unwrapped = _js_unwrap_parens(node)
    if unwrapped is None:
        return None
    line, _ = _js_lines(unwrapped, content_bytes)

    if unwrapped.type == "call_expression":
        fn = unwrapped.child_by_field_name("function")
        args = unwrapped.child_by_field_name("arguments")
        if fn and fn.type == "member_expression" and args and args.named_children:
            prop_n = fn.child_by_field_name("property")
            obj_n = fn.child_by_field_name("object")
            prop_name = _js_text(prop_n, content_bytes) if prop_n else ""
            obj_text = _js_text(obj_n, content_bytes) if obj_n else ""
            first_arg = _js_string_literal(args.named_children[0], content_bytes)

            if prop_name == "get" and first_arg:
                if "searchParams" in obj_text:
                    return ResolvedTaintInput(
                        location=InputLocation.QUERY,
                        parameter_name=first_arg,
                        accessor_snippet=f'{obj_text}.get("{first_arg}")',
                        source_file="",
                        source_line=line,
                    )
                if "headers" in obj_text:
                    return ResolvedTaintInput(
                        location=InputLocation.HEADER,
                        parameter_name=first_arg,
                        accessor_snippet=f'{obj_text}.get("{first_arg}")',
                        source_file="",
                        source_line=line,
                    )
                if re.search(
                    r"\b(?:form|formData)\b", obj_text, re.IGNORECASE
                ) or _js_is_formdata_var(obj_text, defs, line, content_bytes):
                    return ResolvedTaintInput(
                        location=InputLocation.FORM,
                        parameter_name=first_arg,
                        accessor_snippet=f'formData.get("{first_arg}")',
                        source_file="",
                        source_line=line,
                    )
                if obj_text in {"req", "request"}:
                    return ResolvedTaintInput(
                        location=InputLocation.HEADER,
                        parameter_name=first_arg,
                        accessor_snippet=f'{obj_text}.get("{first_arg}")',
                        source_file="",
                        source_line=line,
                    )

    if unwrapped.type in {"member_expression", "subscript_expression"}:
        root_n, chain = _js_member_chain(unwrapped, content_bytes)
        if root_n is not None and chain:
            root_txt = _js_text(root_n, content_bytes)
            str_chain = [str(p) for p in chain]

            if root_txt in {"req", "request"} and len(str_chain) >= 2:
                bucket = str_chain[0]
                param = ".".join(str_chain[1:])
                loc_map = {
                    "query": InputLocation.QUERY,
                    "params": InputLocation.PATH,
                    "headers": InputLocation.HEADER,
                    "cookies": InputLocation.COOKIE,
                    "body": InputLocation.JSON_BODY,
                }
                if bucket in loc_map:
                    return ResolvedTaintInput(
                        location=loc_map[bucket],
                        parameter_name=param,
                        accessor_snippet=f"req.{bucket}.{param}",
                        source_file="",
                        source_line=line,
                    )

            if root_n.type == "call_expression" and re.search(r"\.(?:json)\(\)\s*$", root_txt):
                param = ".".join(str_chain)
                return ResolvedTaintInput(
                    location=InputLocation.JSON_BODY,
                    parameter_name=param,
                    accessor_snippet=f"body.{param}",
                    source_file="",
                    source_line=line,
                )

            if len(chain) == 1 and isinstance(chain[0], int) and root_n.type == "identifier":
                idx = chain[0]
                if idx >= 1 and _js_is_path_match_var(root_txt, defs, line, content_bytes):
                    param_name = (
                        route_params[idx - 1] if idx - 1 < len(route_params) else f"match_{idx}"
                    )
                    return ResolvedTaintInput(
                        location=InputLocation.PATH,
                        parameter_name=param_name,
                        accessor_snippet=f"route.params.{param_name}",
                        source_file="",
                        source_line=line,
                    )

            if root_n.type == "identifier" and root_txt not in visited:
                resolved_def = _js_latest_def(root_txt, defs, use_line)
                if resolved_def is not None:
                    full_chain = [*resolved_def.prop_path, *str_chain]
                    json_line = _js_is_json_body_expr(resolved_def.expr_node, content_bytes)
                    if json_line is not None and full_chain:
                        param = ".".join(full_chain)
                        return ResolvedTaintInput(
                            location=InputLocation.JSON_BODY,
                            parameter_name=param,
                            accessor_snippet=f"body.{param}",
                            source_file="",
                            source_line=resolved_def.line,
                        )
                    if resolved_def.expr_node.type in {"member_expression", "subscript_expression"}:
                        base_root, base_chain = _js_member_chain(
                            resolved_def.expr_node, content_bytes
                        )
                        if base_root and base_root.type == "identifier":
                            b_def = _js_latest_def(
                                _js_text(base_root, content_bytes), defs, resolved_def.line
                            )
                            if (
                                b_def
                                and _js_is_json_body_expr(b_def.expr_node, content_bytes)
                                is not None
                            ):
                                full_p = ".".join(
                                    [*b_def.prop_path, *(str(x) for x in base_chain), *str_chain]
                                )
                                if full_p:
                                    return ResolvedTaintInput(
                                        location=InputLocation.JSON_BODY,
                                        parameter_name=full_p,
                                        accessor_snippet=f"body.{full_p}",
                                        source_file="",
                                        source_line=b_def.line,
                                    )

    return None


def _js_resolve_expr(
    node: Any,
    *,
    file_path: str,
    content_bytes: bytes,
    defs: list[_JsDefEntry],
    guards: dict[str, int],
    use_line: int,
    route_params: list[str],
    visited: frozenset[str],
    trail: tuple[str, ...],
) -> tuple[list[ResolvedTaintInput], bool]:
    """Recursively trace an expression backward along def-use edges."""
    if node is None:
        return [], False
    unwrapped = _js_unwrap_parens(node)
    if unwrapped is None or _js_is_static_expr(unwrapped):
        return [], False

    expr_txt = _js_text(unwrapped, content_bytes).strip()
    if expr_txt in guards and guards[expr_txt] < use_line:
        return [], True

    direct = _js_match_direct_source(
        unwrapped, content_bytes, defs, use_line, route_params, visited
    )
    if direct is not None:
        src_step = f"{file_path}:{direct.source_line} (source: {direct.accessor_snippet})"
        return [
            direct.model_copy(
                update={
                    "source_file": file_path,
                    "propagation_steps": (src_step, *trail),
                }
            )
        ], False

    if unwrapped.type == "template_string":
        all_found: list[ResolvedTaintInput] = []
        any_sanitized = False
        for ch in unwrapped.named_children:
            if ch.type == "template_substitution" and ch.named_children:
                res, san = _js_resolve_expr(
                    ch.named_children[0],
                    file_path=file_path,
                    content_bytes=content_bytes,
                    defs=defs,
                    guards=guards,
                    use_line=use_line,
                    route_params=route_params,
                    visited=visited,
                    trail=trail,
                )
                all_found.extend(res)
                any_sanitized = any_sanitized or san
        return all_found, any_sanitized and not all_found

    if unwrapped.type == "binary_expression":
        res_l, san_l = _js_resolve_expr(
            unwrapped.child_by_field_name("left"),
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=use_line,
            route_params=route_params,
            visited=visited,
            trail=trail,
        )
        res_r, san_r = _js_resolve_expr(
            unwrapped.child_by_field_name("right"),
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=use_line,
            route_params=route_params,
            visited=visited,
            trail=trail,
        )
        combined = [*res_l, *res_r]
        return combined, (san_l or san_r) and not combined

    if unwrapped.type == "ternary_expression":
        res_c, _ = _js_resolve_expr(
            unwrapped.child_by_field_name("consequence"),
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=use_line,
            route_params=route_params,
            visited=visited,
            trail=trail,
        )
        res_a, _ = _js_resolve_expr(
            unwrapped.child_by_field_name("alternative"),
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=use_line,
            route_params=route_params,
            visited=visited,
            trail=trail,
        )
        return [*res_c, *res_a], False

    if unwrapped.type == "call_expression":
        fn = unwrapped.child_by_field_name("function")
        args = unwrapped.child_by_field_name("arguments")
        fn_txt = _js_text(fn, content_bytes) if fn else ""
        if fn_txt in _NUMERIC_COERCION_FUNCS:
            return [], True
        if fn and fn.type == "member_expression":
            prop = fn.child_by_field_name("property")
            obj = fn.child_by_field_name("object")
            if prop and _js_text(prop, content_bytes) in _STRING_PROPAGATOR_METHODS:
                return _js_resolve_expr(
                    obj,
                    file_path=file_path,
                    content_bytes=content_bytes,
                    defs=defs,
                    guards=guards,
                    use_line=use_line,
                    route_params=route_params,
                    visited=visited,
                    trail=trail,
                )
        if fn_txt == "String" and args and args.named_children:
            return _js_resolve_expr(
                args.named_children[0],
                file_path=file_path,
                content_bytes=content_bytes,
                defs=defs,
                guards=guards,
                use_line=use_line,
                route_params=route_params,
                visited=visited,
                trail=trail,
            )

    if unwrapped.type == "identifier":
        if expr_txt in visited:
            return [], False
        d = _js_latest_def(expr_txt, defs, use_line)
        if d is None:
            return [], False

        if expr_txt in guards and guards[expr_txt] < use_line:
            return [], True

        if d.prop_path:
            prop_joined = ".".join(d.prop_path)
            json_line = _js_is_json_body_expr(d.expr_node, content_bytes)
            if json_line is not None:
                snippet = f"body.{prop_joined}"
                src_step = f"{file_path}:{d.line} (source: {snippet})"
                return [
                    ResolvedTaintInput(
                        location=InputLocation.JSON_BODY,
                        parameter_name=prop_joined,
                        accessor_snippet=snippet,
                        source_file=file_path,
                        source_line=d.line,
                        propagation_steps=(src_step, *trail),
                    )
                ], False
            base_expr = _js_unwrap_parens(d.expr_node)
            if base_expr and base_expr.type == "identifier":
                base_def = _js_latest_def(_js_text(base_expr, content_bytes), defs, d.line)
                if (
                    base_def
                    and _js_is_json_body_expr(base_def.expr_node, content_bytes) is not None
                ):
                    full_p = ".".join([*base_def.prop_path, *d.prop_path])
                    snippet = f"body.{full_p}"
                    src_step = f"{file_path}:{d.line} (source: {snippet})"
                    return [
                        ResolvedTaintInput(
                            location=InputLocation.JSON_BODY,
                            parameter_name=full_p,
                            accessor_snippet=snippet,
                            source_file=file_path,
                            source_line=d.line,
                            propagation_steps=(src_step, *trail),
                        )
                    ], False

        if d.array_index is not None and d.array_index >= 1:
            base_expr = _js_unwrap_parens(d.expr_node)
            if (
                base_expr
                and base_expr.type == "identifier"
                and _js_is_path_match_var(
                    _js_text(base_expr, content_bytes), defs, d.line, content_bytes
                )
            ):
                p_name = (
                    route_params[d.array_index - 1]
                    if d.array_index - 1 < len(route_params)
                    else f"match_{d.array_index}"
                )
                snippet = f"route.params.{p_name}"
                return [
                    ResolvedTaintInput(
                        location=InputLocation.PATH,
                        parameter_name=p_name,
                        accessor_snippet=snippet,
                        source_file=file_path,
                        source_line=d.line,
                        propagation_steps=(f"{file_path}:{d.line} (source: {snippet})", *trail),
                    )
                ], False

        prop_step = f"{file_path}:{d.line} (propagator: {expr_txt})"
        return _js_resolve_expr(
            d.expr_node,
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=d.line,
            route_params=route_params,
            visited=visited | {expr_txt},
            trail=(prop_step, *trail),
        )

    return [], False


def _js_collect_handler_candidate_inputs(
    scope_node: Any,
    content_bytes: bytes,
    defs: list[_JsDefEntry],
    handler_span: tuple[int, int],
    sink_line: int,
    route_params: list[str],
) -> tuple[str, ...]:
    """Collect input names actually referenced inside [handler_start..sink_line]."""
    names: set[str] = set()
    h_start = handler_span[0]
    upper_line = min(sink_line, handler_span[1])

    for d in defs:
        if h_start <= d.line <= upper_line and d.prop_path:
            base = _js_unwrap_parens(d.expr_node)
            if base and base.type == "identifier":
                b_def = _js_latest_def(_js_text(base, content_bytes), defs, d.line)
                if b_def and _js_is_json_body_expr(b_def.expr_node, content_bytes) is not None:
                    names.add(".".join([*b_def.prop_path, *d.prop_path]))
            elif d.expr_node and _js_is_json_body_expr(d.expr_node, content_bytes) is not None:
                names.add(".".join(d.prop_path))

    stack = [scope_node]
    while stack:
        node = stack.pop()
        s_line, e_line = _js_lines(node, content_bytes)
        if e_line < h_start or s_line > upper_line:
            continue
        if h_start <= s_line <= upper_line and node.type in {
            "call_expression",
            "member_expression",
            "subscript_expression",
        }:
            matched = _js_match_direct_source(
                node, content_bytes, defs, s_line, route_params, frozenset()
            )
            if matched is not None:
                if not (
                    matched.location == InputLocation.HEADER
                    and matched.parameter_name.casefold() == "content-type"
                ):
                    names.add(matched.parameter_name)
                continue
        for ch in node.named_children:
            stack.append(ch)
    return tuple(sorted(names))


def _analyze_js_ts_sink(
    content_bytes: bytes,
    *,
    file_path: str,
    sink_line: int,
    sink_kind: SinkKind,
    is_ts: bool,
    handler_span: tuple[int, int] | None,
    route_path: str | None,
) -> AstTaintTraceResult:
    text_lines = content_bytes.decode("utf-8", errors="replace").splitlines()
    raw_line = text_lines[sink_line - 1].strip() if 1 <= sink_line <= len(text_lines) else None

    tree = _js_parse(content_bytes, is_ts=is_ts)
    if tree is None:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            sink_code_line=raw_line,
        )

    scope_node, effective_span = _js_find_scopes(
        tree.root_node, content_bytes, sink_line, handler_span
    )
    route_params = _route_path_params(route_path)
    defs, guards = _js_collect_active_defs_and_guards(scope_node, content_bytes, sink_line)
    candidate_names = _js_collect_handler_candidate_inputs(
        scope_node, content_bytes, defs, effective_span, sink_line, route_params
    )

    call_node, args, is_safe, safe_reason = _js_find_sink_call(
        tree.root_node, content_bytes, sink_line, sink_kind
    )
    if call_node is None or not args:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=effective_span[0],
            handler_end_line=effective_span[1],
            sink_code_line=raw_line,
            candidate_input_names_in_handler=candidate_names,
        )

    if is_safe:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=effective_span[0],
            handler_end_line=effective_span[1],
            sink_code_line=raw_line,
            has_taint_flow=False,
            is_sanitized_or_parameterized=True,
            sanitization_reason=safe_reason,
            candidate_input_names_in_handler=candidate_names,
        )

    sink_call_txt = _js_text(call_node, content_bytes)[:120]
    sink_step = f"{file_path}:{sink_line} (sink: {sink_call_txt})"
    all_resolved: list[ResolvedTaintInput] = []
    any_guard_sanitized = False

    for arg in args:
        found, san = _js_resolve_expr(
            arg,
            file_path=file_path,
            content_bytes=content_bytes,
            defs=defs,
            guards=guards,
            use_line=sink_line,
            route_params=route_params,
            visited=frozenset(),
            trail=(sink_step,),
        )
        all_resolved.extend(found)
        any_guard_sanitized = any_guard_sanitized or san

    unique_resolved = deduplicate_resolved_inputs(all_resolved)

    if not unique_resolved and any_guard_sanitized:
        return AstTaintTraceResult(
            file_path=file_path,
            sink_line=sink_line,
            sink_kind=sink_kind,
            handler_start_line=effective_span[0],
            handler_end_line=effective_span[1],
            sink_code_line=raw_line,
            has_taint_flow=False,
            is_sanitized_or_parameterized=True,
            sanitization_reason="Pre-sink numeric coercion or strict regex guard",
            candidate_input_names_in_handler=candidate_names,
        )

    steps = list(unique_resolved[0].propagation_steps) if unique_resolved else []
    return AstTaintTraceResult(
        file_path=file_path,
        sink_line=sink_line,
        sink_kind=sink_kind,
        handler_start_line=effective_span[0],
        handler_end_line=effective_span[1],
        sink_code_line=raw_line,
        has_taint_flow=bool(unique_resolved),
        resolved_sources=unique_resolved,
        dataflow_steps=tuple(steps),
        candidate_input_names_in_handler=candidate_names,
    )


__all__ = ["_analyze_js_ts_sink"]
