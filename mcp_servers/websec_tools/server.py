"""Thin MCP transport for the ten Layer 6 security tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from . import nmap, openapi, probes, whatweb, zap
from .errors import ToolError

ToolCallable = Callable[..., Awaitable[dict[str, Any]]]


def _mcp_error_result(message: str) -> Any:
    try:
        from mcp.types import CallToolResult, TextContent
    except ImportError:
        raise RuntimeError(message) from None
    content = [TextContent(type="text", text=message)]
    try:
        return CallToolResult(content=content, isError=True)
    except TypeError:
        return CallToolResult(content=content, is_error=True)


async def _invoke(tool: ToolCallable, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await tool(*args, **kwargs)
    except ToolError as exc:
        return _mcp_error_result(exc.public_message)
    except Exception:
        return _mcp_error_result("E_INTERNAL: tool failed")
    raise AssertionError("unreachable")


async def get_response_headers(target: str) -> dict[str, Any]:
    """Return final URL, status, redirect chain and response security headers."""

    return await _invoke(probes.get_response_headers, target)


async def get_cookies(target: str) -> dict[str, Any]:
    """Return cookie metadata without returning cookie values."""

    return await _invoke(probes.get_cookies, target)


async def get_tls_info(target: str) -> dict[str, Any]:
    """Return TLS protocol, certificate and expiry information."""

    return await _invoke(probes.get_tls_info, target)


async def get_cors_policy(target: str) -> dict[str, Any]:
    """Return simple-request and preflight CORS behavior."""

    return await _invoke(probes.get_cors_policy, target)


async def discover_hosts(target: str) -> dict[str, Any]:
    """Discover live hosts using the fixed Nmap host-discovery profile."""

    return await _invoke(nmap.discover_hosts, target)


async def discover_services(
    target: str,
    profile: Literal["service-top-100", "service-explicit-ports"] = "service-top-100",
    ports: list[int] | None = None,
) -> dict[str, Any]:
    """Discover services with a constrained Nmap profile."""

    return await _invoke(nmap.discover_services, target, profile, ports)


async def crawl_web(target: str) -> dict[str, Any]:
    """Crawl same-origin URLs using ZAP traditional Spider."""

    return await _invoke(zap.crawl_web, target)


async def passive_web_analysis(target: str) -> dict[str, Any]:
    """Run ZAP Spider and return passive scanner signals only."""

    return await _invoke(zap.passive_web_analysis, target)


async def fingerprint_web(target: str) -> dict[str, Any]:
    """Fingerprint web technologies with constrained WhatWeb settings."""

    return await _invoke(whatweb.fingerprint_web, target)


async def parse_api_spec(target: str) -> dict[str, Any]:
    """Parse a remote Swagger/OpenAPI document."""

    return await _invoke(openapi.parse_api_spec, target)


TOOLS = (
    get_response_headers,
    get_cookies,
    get_tls_info,
    get_cors_policy,
    discover_hosts,
    discover_services,
    crawl_web,
    passive_web_analysis,
    fingerprint_web,
    parse_api_spec,
)


def main() -> None:
    try:
        from mcp.server.fastmcp import FastMCP
    except ImportError as exc:
        raise RuntimeError("Install the mcp dependency to run websec-tools") from exc

    server = FastMCP("websec-tools")

    for tool in TOOLS:
        server.tool()(tool)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
