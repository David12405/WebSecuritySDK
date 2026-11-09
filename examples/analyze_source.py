"""Run Module 2 source tools directly against an authorized local repository."""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
from pathlib import Path
from typing import Any

_PROJECT_ROOT = Path(__file__).resolve().parents[1]
if str(_PROJECT_ROOT) not in sys.path:
    sys.path.insert(0, str(_PROJECT_ROOT))

from mcp_servers.websec_tools.analysis import semgrep, source  # noqa: E402
from mcp_servers.websec_tools.errors import ToolError  # noqa: E402

TOOL_ALIASES = {
    "tree": "inspect_source_tree",
    "read": "read_source_file",
    "search": "search_source",
    "semgrep": "analyze_source",
}
TOOL_NAMES = (
    "inspect_source_tree",
    "read_source_file",
    "search_source",
    "analyze_source",
)


def _parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(description="Run local source-analysis tools")
    parser.add_argument("target", type=Path, help="absolute or expandable repository path")
    parser.add_argument(
        "--tool",
        choices=(*TOOL_NAMES, *TOOL_ALIASES),
        default="inspect_source_tree",
    )
    parser.add_argument("--path", default=".", help="repository-relative path")
    parser.add_argument("--max-depth", type=int, default=4)
    parser.add_argument("--start-line", type=int, default=1)
    parser.add_argument("--end-line", type=int)
    parser.add_argument("--query")
    parser.add_argument("--case-sensitive", action="store_true")
    return parser


async def _run(args: argparse.Namespace) -> dict[str, Any]:
    target = str(args.target.expanduser().resolve())
    tool = TOOL_ALIASES.get(args.tool, args.tool)
    if tool == "inspect_source_tree":
        return await source.inspect_source_tree(target, args.path, args.max_depth)
    if tool == "read_source_file":
        if args.path == ".":
            raise ToolError("E_INVALID_ARGUMENT", "--path is required for read_source_file")
        return await source.read_source_file(target, args.path, args.start_line, args.end_line)
    if tool == "search_source":
        if not args.query:
            raise ToolError("E_INVALID_ARGUMENT", "--query is required for search_source")
        return await source.search_source(target, args.query, args.path, args.case_sensitive)
    return await semgrep.analyze_source(target, args.path)


def main(argv: list[str] | None = None) -> int:
    args = _parser().parse_args(argv)
    try:
        result = asyncio.run(_run(args))
    except ToolError as exc:
        result = {
            "error": {"code": exc.code, "message": exc.message},
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1
    except Exception:
        result = {
            "error": {"code": "E_INTERNAL", "message": "tool failed"},
        }
        print(json.dumps(result, indent=2, ensure_ascii=False))
        return 1
    print(json.dumps(result, indent=2, ensure_ascii=False))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
