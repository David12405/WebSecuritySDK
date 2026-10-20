"""Investigate any site through the MCP tools - no model, no agent.

    python examples/probe_target.py https://example.com
    python examples/probe_target.py https://example.com --brief
    python examples/probe_target.py https://example.com --json report.json
    python examples/probe_target.py https://example.com --scope https://other.test
    python examples/probe_target.py https://docs.python.org --scope https://python.org --subdomains

Starts `mcp_servers.websec_tools.server` as a real stdio subprocess,
discovers its tools with `list_tools`, applies the scope guard to each
proposed call, then calls the ones that survive. That exercises layers 3, 5
and 6 and the whole tool contract, for the price of a few seconds and no
model credentials.

Each tool is printed in three stages - what the guard was asked, what it
decided, and what came back - followed by the findings the one-line summary
had to leave out. The summary says "1 cookie with weak flags"; the stage
below it says which cookie and which flag.

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
    parser.add_argument("--brief", action="store_true", help="one line per tool, no findings")
    return parser.parse_args()


# --------------------------------------------------------------------------
# What each envelope actually says
# --------------------------------------------------------------------------
#
# The summary is one line by contract, so it has to leave things out - "1
# cookie with weak flags" without saying which cookie or which flag. These
# read the `data` half and show the part a person would ask about next.
#
# Keyed by tool name, with a generic fallback: this script discovers whatever
# tools a server exposes, so it must stay useful against a server it has
# never seen.


def detail_headers(data: dict[str, Any]) -> list[str]:
    lines = [f"final url    {data.get('final_url')}  (status {data.get('status')})"]
    if chain := data.get("redirect_chain"):
        lines.append(f"redirects    {' -> '.join(chain)}")
    present = data.get("security_headers_present") or {}
    for name, value in present.items():
        lines.append(f"present      {name}: {value[:70]}")
    for name in data.get("security_headers_missing") or []:
        lines.append(f"MISSING      {name}")
    for name, value in (data.get("information_disclosure") or {}).items():
        lines.append(f"discloses    {name}: {value[:70]}")
    return lines


def detail_cookies(data: dict[str, Any]) -> list[str]:
    weak = data.get("weak_cookies") or {}
    lines = []
    for cookie in data.get("cookies") or []:
        flags = [flag for flag in ("secure", "httponly") if cookie.get(flag)]
        if cookie.get("samesite"):
            flags.append(f"samesite={cookie['samesite']}")
        name = cookie["name"]
        mark = "WEAK " if name in weak else "ok   "
        lines.append(f"{mark}        {name}  ({cookie['value_length']} chars) {', '.join(flags)}")
        for reason in weak.get(name, []):
            lines.append(f"               - {reason}")
    return lines


def detail_tls(data: dict[str, Any]) -> list[str]:
    trusted = "trusted" if data.get("chain_trusted") else f"NOT trusted: {data.get('chain_error')}"
    lines = [
        f"protocol     {data.get('protocol')}  {data.get('cipher')}",
        f"chain        {trusted}",
        f"issuer       {data.get('issuer')}",
        f"subject      {data.get('subject')}",
        f"valid until  {data.get('not_after')}  ({data.get('expires_in_days')} days)",
    ]
    sans = data.get("sans") or []
    if sans:
        shown = ", ".join(sans[:5])
        more = f" (+{data['san_count'] - 5} more)" if data.get("san_count", 0) > 5 else ""
        lines.append(f"sans         {shown}{more}")
    return lines


def detail_cors(data: dict[str, Any]) -> list[str]:
    lines = [
        f"allow-origin {data.get('allow_origin')!r}",
        f"credentials  {data.get('allow_credentials')}",
        f"vary origin  {data.get('vary_includes_origin')}",
    ]
    if data.get("credentialed_wildcard"):
        lines.append("WEAK         wildcard origin with credentials; browsers refuse this")
    if data.get("reflects_arbitrary_origin"):
        lines.append(f"WEAK         reflects any origin ({data.get('probe_origin')} was echoed)")
    if methods := data.get("preflight_allow_methods"):
        lines.append(f"preflight    methods {methods}")
    return lines


DETAIL = {
    "get_response_headers": detail_headers,
    "get_cookies": detail_cookies,
    "get_tls_info": detail_tls,
    "get_cors_policy": detail_cors,
}


def detail_generic(data: dict[str, Any]) -> list[str]:
    """For a tool this script has never seen - a partner's, or a new one of ours."""
    lines = []
    for key, value in data.items():
        rendered = json.dumps(value) if not isinstance(value, str) else value
        lines.append(f"{key[:12]:12} {rendered[:80]}")
    return lines


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


def say(args: argparse.Namespace, stage: str, line: str) -> None:
    """One stage line, unless `--brief` asked for the summary only."""
    if not args.brief:
        print(f"  {stage:7} {line}")


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
            if not args.brief:
                print(f"\n{'-' * 78}\n{tool.name}\n{'-' * 78}")

            # ---- before the call: the same policy the agent runs under ----
            decision = guard_tool_call(
                tool.name,
                tool_input,
                allowlist=[t.name for t in tools],
                scope=scope,
                allow_subdomains=args.subdomains,
            )
            say(args, "BEFORE", f"scope guard: {json.dumps(tool_input)}")
            if not decision:
                blocked += 1
                verdict = f"BLOCKED  {decision.reason}"
                print(f"{tool.name:22} {verdict}" if args.brief else f"  {verdict}")
                report["tools"][tool.name] = {"blocked": decision.reason}
                continue
            say(args, "", "allowed, calling the tool")

            # ---- the call -------------------------------------------------
            started = time.perf_counter()
            try:
                result = await asyncio.wait_for(
                    session.call_tool(tool.name, tool_input), timeout=args.timeout
                )
            except TimeoutError:
                failed += 1
                report["tools"][tool.name] = {"error": "no answer", "code": "E_TIMEOUT"}
                line = f"E_TIMEOUT    no answer in {args.timeout}s"
                print(f"{tool.name:22} {line}" if args.brief else f"  AFTER   {line}")
                continue
            elapsed = int((time.perf_counter() - started) * 1000)

            # ---- after the call -------------------------------------------
            if getattr(result, "is_error", False) or getattr(result, "isError", False):
                failed += 1
                raw = text_of(result)
                code = code_of(raw)
                retry = "retryable" if is_retryable(code) else "terminal"
                line = f"{code:12} {message_of(raw)}   ({retry}, {elapsed} ms)"
                print(f"{tool.name:22} {line}" if args.brief else f"  AFTER   {line}")
                report["tools"][tool.name] = {"error": message_of(raw), "code": code}
                continue

            envelope = payload_of(result)
            summary = envelope.get("summary", "<no summary>")
            cut = "  [truncated]" if envelope.get("truncated") else ""
            report["tools"][tool.name] = envelope

            if args.brief:
                print(f"{tool.name:22} {summary}{cut}   ({elapsed} ms)")
                continue

            say(args, "AFTER", f"{summary}{cut}   ({elapsed} ms)")
            data = envelope.get("data") or {}
            render = DETAIL.get(tool.name, detail_generic)
            for line in render(data):
                print(f"            {line}")

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
