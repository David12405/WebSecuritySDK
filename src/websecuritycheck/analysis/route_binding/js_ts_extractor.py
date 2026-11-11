"""JavaScript / TypeScript Tree-sitter route handler extractor."""

from __future__ import annotations

import re
from pathlib import Path

from .models import (
    METHOD_CLOUDFLARE_WORKER,
    METHOD_DIGEST_CLOUDFLARE_WORKER,
    METHOD_DIGEST_JS_ROUTER,
    METHOD_JS_ROUTER,
    ExtractedRawRoute,
)


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

    # Collect all named AST nodes iteratively to prevent deep recursion issues
    stack = [tree.root_node]
    all_nodes = []
    while stack:
        curr = stack.pop()
        all_nodes.append(curr)
        for child in reversed(curr.named_children):
            stack.append(child)

    def _node_bytes(n: object) -> bytes:
        return content_bytes[n.start_byte : n.end_byte]  # type: ignore[attr-defined]

    def _node_lines(n: object) -> tuple[int, int]:
        sb: int = n.start_byte  # type: ignore[attr-defined]
        eb: int = n.end_byte  # type: ignore[attr-defined]
        return (
            content_bytes.count(b"\n", 0, sb) + 1,
            content_bytes.count(b"\n", 0, eb) + 1,
        )

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
                    if prop and _node_bytes(prop) == b"match":
                        for a in args.named_children:
                            if a.type == "regex":
                                regex_vars[_node_bytes(name_node).decode("utf-8")] = _node_bytes(
                                    a
                                ).decode("utf-8")

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
            if op and _node_bytes(op) in (b"&&", b"||"):
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
                if op and _node_bytes(op) in (b"===", b"=="):
                    left_b = _node_bytes(left) if left else b""
                    right_b = _node_bytes(right) if right else b""
                    if left and left_b in (b"path", b"url.pathname", b"pathname"):
                        if right and right.type == "string":
                            path_literal = right_b.decode("utf-8").strip("\"'")
                    elif (
                        right
                        and right_b in (b"path", b"url.pathname", b"pathname")
                        and left
                        and left.type == "string"
                    ):
                        path_literal = left_b.decode("utf-8").strip("\"'")
                    elif (
                        left
                        and left_b in (b"method", b"request.method")
                        and right
                        and right.type == "string"
                    ):
                        extracted_methods.add(right_b.decode("utf-8").strip("\"'").upper())
                    elif (
                        right
                        and right_b in (b"method", b"request.method")
                        and left
                        and left.type == "string"
                    ):
                        extracted_methods.add(left_b.decode("utf-8").strip("\"'").upper())

        if not path_literal and cond.type == "identifier":
            var_name = _node_bytes(cond).decode("utf-8")
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
            start_l, end_l = _node_lines(node)

            # Detect method guards in consequence statements
            candidate_stmts = (
                consequence.named_children
                if consequence.type == "statement_block"
                else [consequence]
            )
            for cn in candidate_stmts:
                if cn.type == "if_statement":
                    inner_cond = cn.child_by_field_name("condition")
                    while inner_cond and inner_cond.type == "parenthesized_expression":
                        inner_cond = (
                            inner_cond.named_children[0] if inner_cond.named_children else None
                        )
                    if inner_cond and inner_cond.type == "binary_expression":
                        m_left = inner_cond.child_by_field_name("left")
                        m_op = inner_cond.child_by_field_name("operator") or inner_cond.child(1)
                        m_right = inner_cond.child_by_field_name("right")
                        m_op_b = _node_bytes(m_op) if m_op else b""
                        m_left_b = _node_bytes(m_left) if m_left else b""
                        is_method_op = m_op_b in (b"!==", b"!=", b"===", b"==")
                        is_method_left = m_left_b in (b"method", b"request.method")
                        if is_method_op and is_method_left and m_right and m_right.type == "string":
                            extracted_methods.add(
                                _node_bytes(m_right).decode("utf-8").strip("\"'").upper()
                            )

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
                prop_b = _node_bytes(prop).lower() if prop else b""
                if prop_b in http_methods:
                    method_str = prop_b.decode("utf-8").upper()
                    obj = fn.child_by_field_name("object")
                    obj_text = _node_bytes(obj).decode("utf-8").lower() if obj else ""
                    # Ignore common map/params/URL accessors
                    ignore_objs = {
                        "url",
                        "searchparams",
                        "formdata",
                        "headers",
                        "request",
                        "req",
                        "map",
                        "params",
                        "data",
                    }
                    if any(ig in obj_text for ig in ignore_objs):
                        continue
                    if args.named_children and args.named_children[0].type == "string":
                        p_lit = _node_bytes(args.named_children[0]).decode("utf-8").strip("\"'")
                        if not p_lit.startswith("/"):
                            continue
                        start_l, end_l = _node_lines(node)
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


__all__ = ["_extract_js_ts_routes"]

