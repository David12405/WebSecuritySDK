"""Tree-sitter JS/TS AST helpers, scope resolution, def-use collection, and sink matching."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any

from websecuritycheck.domain.analysis_models import SinkKind

from .models import (
    _CMDI_SINK_METHODS,
    _EVAL_SINK_FUNCS,
    _SQL_SINK_METHODS,
    _regex_guard_is_strict,
)


@dataclass(frozen=True)
class _JsDefEntry:
    line: int
    var_name: str
    expr_node: Any
    prop_path: tuple[str, ...] = ()
    array_index: int | None = None
    is_param: bool = False


def _js_parse(content_bytes: bytes, is_ts: bool) -> Any | None:
    try:
        import tree_sitter_javascript as tsjs
        import tree_sitter_typescript as tsts
        from tree_sitter import Language, Parser
    except ImportError:
        return None
    lang_fn = tsts.language_typescript() if is_ts else tsjs.language()
    parser = Parser(Language(lang_fn))
    return parser.parse(content_bytes)


def _js_text(node: Any, content_bytes: bytes) -> str:
    return content_bytes[node.start_byte : node.end_byte].decode("utf-8", errors="replace")


def _js_lines(node: Any, content_bytes: bytes) -> tuple[int, int]:
    return (
        content_bytes.count(b"\n", 0, node.start_byte) + 1,
        content_bytes.count(b"\n", 0, node.end_byte) + 1,
    )


def _js_unwrap_parens(node: Any) -> Any:
    curr = node
    while curr is not None and curr.type in {
        "parenthesized_expression",
        "await_expression",
        "as_expression",
        "non_null_expression",
    }:
        children = curr.named_children
        curr = children[0] if children else None
    return curr


def _js_unwrap_parens_only(node: Any) -> Any:
    curr = node
    while curr is not None and curr.type == "parenthesized_expression":
        children = curr.named_children
        curr = children[0] if children else None
    return curr


def _js_string_literal(node: Any, content_bytes: bytes) -> str | None:
    if node is None:
        return None
    if node.type == "string":
        raw = _js_text(node, content_bytes)
        if len(raw) >= 2 and raw[0] in ("'", '"') and raw[-1] == raw[0]:
            return raw[1:-1]
        return raw.strip("\"'")
    if node.type == "template_string":
        has_sub = any(c.type == "template_substitution" for c in node.named_children)
        if has_sub:
            return None
        return _js_text(node, content_bytes)[1:-1]
    return None


def _js_is_static_expr(node: Any) -> bool:
    if node is None:
        return True
    if node.type in {"string", "number", "true", "false", "null", "undefined", "regex"}:
        return True
    if node.type == "template_string":
        return not any(c.type == "template_substitution" for c in node.named_children)
    if node.type == "binary_expression":
        return _js_is_static_expr(node.child_by_field_name("left")) and _js_is_static_expr(
            node.child_by_field_name("right")
        )
    return False


def _js_member_chain(node: Any, content_bytes: bytes) -> tuple[Any | None, list[str | int]]:
    """Split a member/subscript chain into (root_node, [prop_or_index, ...])."""
    parts: list[str | int] = []
    curr = _js_unwrap_parens_only(node)
    while curr is not None:
        if curr.type == "member_expression":
            prop = curr.child_by_field_name("property")
            if prop is None:
                break
            parts.append(_js_text(prop, content_bytes))
            curr = _js_unwrap_parens_only(curr.child_by_field_name("object"))
        elif curr.type == "subscript_expression":
            idx = curr.child_by_field_name("index")
            if idx is None:
                break
            lit = _js_string_literal(idx, content_bytes)
            if lit is not None:
                parts.append(lit)
            elif idx.type == "number":
                try:
                    parts.append(int(_js_text(idx, content_bytes)))
                except ValueError:
                    parts.append(_js_text(idx, content_bytes))
            else:
                return curr, []
            curr = _js_unwrap_parens_only(curr.child_by_field_name("object"))
        else:
            break
    parts.reverse()
    return curr, parts


def _js_is_route_if(node: Any, content_bytes: bytes) -> bool:
    if node.type != "if_statement":
        return False
    cond = _js_unwrap_parens_only(node.child_by_field_name("condition"))
    if cond is None:
        return False
    cond_txt = _js_text(cond, content_bytes)
    if re.search(r"\b(?:path|url\.pathname|pathname)\b\s*={2,3}\s*['\"]/", cond_txt):
        return True
    if cond.type == "identifier" and "match" in cond_txt.lower():
        return True
    return ".test(" in cond_txt and "path" in cond_txt.lower()


def _js_find_scopes(
    root_node: Any,
    content_bytes: bytes,
    sink_line: int,
    handler_span: tuple[int, int] | None,
) -> tuple[Any, tuple[int, int]]:
    """Locate the enclosing function node and effective handler span."""
    fn_types = {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
    }
    enclosing_fns: list[tuple[int, int, Any]] = []
    enclosing_ifs: list[tuple[int, int, Any]] = []

    stack = [root_node]
    while stack:
        node = stack.pop()
        s_line, e_line = _js_lines(node, content_bytes)
        if not (s_line <= sink_line <= e_line):
            continue
        if node.type in fn_types:
            enclosing_fns.append((e_line - s_line, s_line, node))
        elif _js_is_route_if(node, content_bytes):
            enclosing_ifs.append((e_line - s_line, s_line, node))
        for child in reversed(node.named_children):
            stack.append(child)

    scope_node = min(enclosing_fns, key=lambda x: (x[0], -x[1]))[2] if enclosing_fns else root_node
    if handler_span is not None:
        return scope_node, handler_span
    if enclosing_ifs:
        chosen_if = min(enclosing_ifs, key=lambda x: (x[0], -x[1]))[2]
        return scope_node, _js_lines(chosen_if, content_bytes)
    return scope_node, _js_lines(scope_node, content_bytes)


def _js_consequence_exits(node: Any) -> bool:
    if node is None:
        return False
    stmts = node.named_children if node.type == "statement_block" else [node]
    return any(s.type in {"return_statement", "throw_statement"} for s in stmts)


def _js_block_has_sanitizer_guard(if_node: Any, content_bytes: bytes) -> set[str]:
    """Identify variables validated by an early-return/throw guard like `if (!/^\\d+$/.test(x))`."""
    consequence = if_node.child_by_field_name("consequence")
    if not _js_consequence_exits(consequence):
        return set()

    cond = _js_unwrap_parens_only(if_node.child_by_field_name("condition"))
    if cond is None:
        return set()

    guarded: set[str] = set()
    stack = [cond]
    while stack:
        curr = stack.pop()
        if curr.type == "unary_expression":
            inner = _js_unwrap_parens_only(curr.child_by_field_name("argument"))
            if inner and inner.type == "call_expression":
                fn = inner.child_by_field_name("function")
                args = inner.child_by_field_name("arguments")
                if fn and fn.type == "member_expression":
                    obj = _js_unwrap_parens_only(fn.child_by_field_name("object"))
                    prop = fn.child_by_field_name("property")
                    if (
                        obj
                        and prop
                        and _js_text(prop, content_bytes) == "test"
                        and obj.type == "regex"
                        and _regex_guard_is_strict(_js_text(obj, content_bytes))
                        and args
                    ):
                        for a in args.named_children:
                            guarded.add(_js_text(_js_unwrap_parens_only(a), content_bytes))
                elif (
                    fn
                    and args
                    and _js_text(fn, content_bytes) in {"Number.isInteger", "Number.isFinite"}
                ):
                    for a in args.named_children:
                        guarded.add(_js_text(_js_unwrap_parens_only(a), content_bytes))
        for ch in curr.named_children:
            stack.append(ch)
    return guarded


def _js_extract_destructure(
    pattern_node: Any,
    val_node: Any,
    line: int,
    prefix: tuple[str, ...],
    out: list[_JsDefEntry],
    content_bytes: bytes,
) -> None:
    if pattern_node.type == "object_pattern":
        for child in pattern_node.named_children:
            if child.type == "shorthand_property_identifier_pattern":
                name = _js_text(child, content_bytes)
                out.append(
                    _JsDefEntry(
                        line=line, var_name=name, expr_node=val_node, prop_path=(*prefix, name)
                    )
                )
            elif child.type == "pair_pattern":
                k_node = child.child_by_field_name("key")
                v_node = child.child_by_field_name("value")
                if k_node and v_node:
                    key_txt = _js_string_literal(k_node, content_bytes) or _js_text(
                        k_node, content_bytes
                    )
                    _js_extract_destructure(
                        v_node, val_node, line, (*prefix, key_txt), out, content_bytes
                    )
    elif pattern_node.type == "array_pattern":
        for idx, child in enumerate(pattern_node.named_children):
            if child.type == "identifier":
                out.append(
                    _JsDefEntry(
                        line=line,
                        var_name=_js_text(child, content_bytes),
                        expr_node=val_node,
                        array_index=idx,
                    )
                )
    elif pattern_node.type == "identifier":
        out.append(
            _JsDefEntry(
                line=line,
                var_name=_js_text(pattern_node, content_bytes),
                expr_node=val_node,
                prop_path=prefix,
            )
        )


def _js_collect_active_defs_and_guards(
    scope_node: Any,
    content_bytes: bytes,
    sink_line: int,
) -> tuple[list[_JsDefEntry], dict[str, int]]:
    """Walk active statements in `scope_node` up to `sink_line`, skipping non-enclosing branches."""
    defs: list[_JsDefEntry] = []
    guards: dict[str, int] = {}

    fn_nested_types = {
        "function_declaration",
        "function_expression",
        "arrow_function",
        "method_definition",
        "generator_function_declaration",
    }

    def visit(node: Any) -> None:
        if node is None:
            return
        s_line, e_line = _js_lines(node, content_bytes)
        if s_line > sink_line:
            return
        if (
            node is not scope_node
            and node.type in fn_nested_types
            and not (s_line <= sink_line <= e_line)
        ):
            return

        if node.type == "if_statement":
            conseq = node.child_by_field_name("consequence")
            alt = node.child_by_field_name("alternative")
            c_span = _js_lines(conseq, content_bytes) if conseq else (0, 0)
            a_span = _js_lines(alt, content_bytes) if alt else (0, 0)
            in_conseq = conseq is not None and c_span[0] <= sink_line <= c_span[1]
            in_alt = alt is not None and a_span[0] <= sink_line <= a_span[1]
            if in_conseq:
                visit(conseq)
            elif in_alt:
                visit(alt)
            elif e_line < sink_line:
                for g_var in _js_block_has_sanitizer_guard(node, content_bytes):
                    guards[g_var] = max(guards.get(g_var, 0), s_line)
            return

        if node.type == "try_statement":
            for child in node.named_children:
                if child.type == "catch_clause":
                    cs, ce = _js_lines(child, content_bytes)
                    if cs <= sink_line <= ce:
                        visit(child)
                else:
                    visit(child)
            return

        if node.type == "variable_declarator":
            name_n = node.child_by_field_name("name")
            val_n = node.child_by_field_name("value")
            if name_n and val_n and s_line <= sink_line:
                _js_extract_destructure(name_n, val_n, s_line, (), defs, content_bytes)
            return

        if node.type == "assignment_expression":
            left_n = node.child_by_field_name("left")
            right_n = node.child_by_field_name("right")
            if left_n and right_n and s_line <= sink_line and left_n.type == "identifier":
                defs.append(
                    _JsDefEntry(
                        line=s_line, var_name=_js_text(left_n, content_bytes), expr_node=right_n
                    )
                )
            return

        for child in node.named_children:
            visit(child)

    visit(scope_node)
    return defs, guards


def _js_sink_method_priority(call_name: str, sink_kind: SinkKind) -> int:
    low = call_name.split(".")[-1]
    if sink_kind in {SinkKind.SQL_QUERY, SinkKind.ORM_QUERY} and low in _SQL_SINK_METHODS:
        return 10
    if sink_kind == SinkKind.OS_COMMAND and low in _CMDI_SINK_METHODS:
        return 10
    if sink_kind == SinkKind.CODE_EVAL and low in _EVAL_SINK_FUNCS:
        return 10
    return 1


def _js_find_sink_call(
    root_node: Any,
    content_bytes: bytes,
    sink_line: int,
    sink_kind: SinkKind,
) -> tuple[Any | None, list[Any], bool, str | None]:
    """Return (call_node, arg_nodes, is_parameterized, sanitization_reason) at `sink_line`."""
    candidates: list[tuple[int, int, Any, str]] = []
    stack = [root_node]
    while stack:
        node = stack.pop()
        s_line, e_line = _js_lines(node, content_bytes)
        if not (s_line <= sink_line <= e_line):
            continue
        if node.type in {"call_expression", "new_expression"}:
            fn_field = "constructor" if node.type == "new_expression" else "function"
            fn_node = node.child_by_field_name(fn_field)
            fn_name = _js_text(fn_node, content_bytes) if fn_node else ""
            prio = _js_sink_method_priority(fn_name, sink_kind)
            if s_line == sink_line or prio > 1:
                candidates.append((prio, node.end_byte - node.start_byte, node, fn_name))
        for ch in node.named_children:
            stack.append(ch)

    if not candidates:
        return None, [], False, None

    candidates.sort(key=lambda x: (-x[0], x[1]))
    chosen_prio, _span, call_node, fn_name = candidates[0]
    if chosen_prio == 1 and len(candidates) > 1:
        line_exact = [c for c in candidates if _js_lines(c[2], content_bytes)[0] == sink_line]
        if line_exact:
            call_node = min(line_exact, key=lambda x: x[1])[2]
            fn_name = min(line_exact, key=lambda x: x[1])[3]

    args_node = call_node.child_by_field_name("arguments")
    args = list(args_node.named_children) if args_node else []

    if sink_kind in {SinkKind.SQL_QUERY, SinkKind.ORM_QUERY} and args:
        sql_arg = args[0]
        if _js_is_static_expr(sql_arg):
            parent = call_node.parent
            has_bind = False
            while parent is not None and _js_lines(parent, content_bytes)[0] <= sink_line + 1:
                if ".bind(" in _js_text(parent, content_bytes):
                    has_bind = True
                    break
                parent = parent.parent
            reason = (
                "Parameterized SQL query via static .prepare(...).bind(...)"
                if has_bind
                else "Static SQL query string literal passed to sink"
            )
            return call_node, args, True, reason

    if args and all(_js_is_static_expr(a) for a in args):
        return call_node, args, True, f"Constant literal argument passed to {fn_name}"

    return call_node, args, False, None


__all__ = [
    "_JsDefEntry",
    "_js_collect_active_defs_and_guards",
    "_js_find_scopes",
    "_js_find_sink_call",
    "_js_is_static_expr",
    "_js_lines",
    "_js_member_chain",
    "_js_parse",
    "_js_string_literal",
    "_js_text",
    "_js_unwrap_parens",
]

