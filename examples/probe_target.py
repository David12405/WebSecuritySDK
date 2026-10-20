"""Investigate any site through the MCP tools - no model, no agent.

    python examples/probe_target.py https://example.com
    python examples/probe_target.py https://example.com --json report.json
    python examples/probe_target.py https://example.com --scope https://other.test
    python examples/probe_target.py https://docs.python.org --scope https://python.org --subdomains

Starts `mcp_servers.websec_tools.server` as a real stdio subprocess,
discovers its tools with `list_tools`, applies the scope guard to each
proposed call, then calls the ones that survive. That exercises layers 3, 5
and 6 and the whole tool contract, for the price of a few seconds and no
model credentials.

What it is for: proving the path works end to end *before* a model is in it.
When a live check later returns something surprising, this says whether the
surprise came from the tools or from the agent.
"""

from __future__ import annotations

import argparse
import asyncio
import json
import sys
import time
from pathlib import Path
from typing import Any

from mcp import ClientSession
from mcp.client.stdio import StdioServerParameters, stdio_client

from websecuritycheck.policy.errors import code_of, is_retryable, message_of
from websecuritycheck.policy.scope_guard import guard_tool_call, normalize_scope

REPO_ROOT = Path(__file__).resolve().parent.parent

SERVER = StdioServerParameters(
    command=sys.executable,
    args=["-m", "mcp_servers.websec_tools.server"],
    cwd=str(REPO_ROOT),
)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("target", help="the http(s) URL to probe")
    parser.add_argument(
        "--scope",
        action="append",
        help="scope entry; repeatable. Defaults to the target itself.",
    )
    parser.add_argument("--subdomains", action="store_true", help="allow subdomains of the scope")
    parser.add_argument("--json", dest="json_path", help="write the raw envelopes to this file")
    parser.add_argument("--timeout", type=float, default=30.0, help="per-tool timeout in seconds")
    return parser.parse_args()


def text_of(result: Any) -> str:
    parts = []
    for block in getattr(result, "content", []) or []:
        text = getattr(block, "text", None)
        if text:
            parts.append(text)
    return "\n".join(parts)


def payload_of(result: Any) -> Any:
    """The envelope, however this SDK version chose to carry it."""
    structured = getattr(result, "structured_content", None) or getattr(
        result, "structuredContent", None
    )
    if structured:
        return structured
    try:
        return json.loads(text_of(result))
    except (ValueError, TypeError):
        return {"summary": text_of(result)}


async def run(args: argparse.Namespace) -> int:
    scope = normalize_scope(args.scope or [args.target])
    print(f"target  {args.target}")
    print(f"scope   {args.scope or [args.target]}" + ("  (+subdomains)" if args.subdomains else ""))

    report: dict[str, Any] = {"target": args.target, "tools": {}}
    blocked = 0
    failed = 0

    async with (
        stdio_client(SERVER) as (read, write),
        ClientSession(read, write) as session,
    ):
        await session.initialize()
        tools = (await session.list_tools()).tools
        names = ", ".join(tool.name for tool in tools)
        print(f"\nMCP server exposes {len(tools)} tool(s): {names}\n")

        for tool in tools:
            tool_input: dict[str, Any] = {"target": args.target}

            # The same scope policy the agent runs under, with no agent.
            decision = guard_tool_call(
                tool.name,
                tool_input,
                allowlist=[t.name for t in tools],
                scope=scope,
                allow_subdomains=args.subdomains,
            )
            if not decision:
                blocked += 1
                print(f"{tool.name:22} BLOCKED  {decision.reason}")
                report["tools"][tool.name] = {"blocked": decision.reason}
                continue

            started = time.perf_counter()
            try:
                result = await asyncio.wait_for(
                    session.call_tool(tool.name, tool_input), timeout=args.timeout
                )
            except TimeoutError:
                failed += 1
                report["tools"][tool.name] = {"error": "no answer", "code": "E_TIMEOUT"}
                print(f"{tool.name:22} E_TIMEOUT    no answer in {args.timeout}s")
                continue
            elapsed = int((time.perf_counter() - started) * 1000)

            if getattr(result, "is_error", False) or getattr(result, "isError", False):
                failed += 1
                raw = text_of(result)
                code = code_of(raw)
                retry = "retryable" if is_retryable(code) else "terminal"
                print(f"{tool.name:22} {code:12} {message_of(raw)}   ({retry}, {elapsed} ms)")
                report["tools"][tool.name] = {"error": message_of(raw), "code": code}
                continue

            envelope = payload_of(result)
            summary = envelope.get("summary", "<no summary>")
            cut = "  [truncated]" if envelope.get("truncated") else ""
            print(f"{tool.name:22} {summary}{cut}   ({elapsed} ms)")
            report["tools"][tool.name] = envelope

    answered = len(report["tools"]) - blocked - failed
    print(f"\n{answered} tool(s) answered, {blocked} blocked, {failed} failed")

    if args.json_path:
        Path(args.json_path).write_text(json.dumps(report, indent=2), encoding="utf-8")
        print(f"raw envelopes written to {args.json_path}")
    return 1 if failed else 0


def main() -> int:
    return asyncio.run(run(parse_args()))


if __name__ == "__main__":
    sys.exit(main())
