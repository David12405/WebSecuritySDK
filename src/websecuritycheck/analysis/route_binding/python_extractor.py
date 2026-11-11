"""Python standard-library AST route decorator extractor."""

from __future__ import annotations

import ast
from pathlib import Path

from .models import (
    METHOD_DIGEST_PY_DECORATOR,
    METHOD_PY_DECORATOR,
    ExtractedRawRoute,
)


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
                "get",
                "post",
                "put",
                "delete",
                "patch",
                "options",
                "head",
            }:
                if (
                    dec.args
                    and isinstance(dec.args[0], ast.Constant)
                    and isinstance(dec.args[0].value, str)
                ):
                    path_str = dec.args[0].value
                    methods.add(dec_fn.attr.upper())

            if path_str:
                start_l = int(item.lineno)
                end_l = int(getattr(item, "end_lineno", item.lineno))
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


__all__ = ["_extract_python_routes"]

