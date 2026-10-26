"""Thin MCP transport for the Layer 6 security tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from . import probes
from . import recon as recon_tools
from .errors import ToolError

ToolCallable = Callable[..., Awaitable[dict[str, Any]]]


def _raise_mcp_tool_error(message: str) -> None:
    """Raise the SDK exception so MCP serializes the call as ``isError``."""
    try:
        from mcp.server.mcpserver.exceptions import ToolError as MCPToolError
    except ImportError:
        try:
            from mcp.server.exceptions import ToolError as MCPToolError
        except ImportError:
            try:
                from mcp.server.fastmcp.exceptions import ToolError as MCPToolError
            except ImportError:
                raise RuntimeError(message) from None
    raise MCPToolError(message)


async def _invoke(tool: ToolCallable, *args: Any, **kwargs: Any) -> dict[str, Any]:
    try:
        return await tool(*args, **kwargs)
    except ToolError as exc:
        _raise_mcp_tool_error(exc.public_message)
    except Exception:
        _raise_mcp_tool_error("E_INTERNAL: tool failed")
    raise AssertionError("unreachable")


async def get_response_headers(target: str) -> dict[str, Any]:
    """Return final URL, status, redirect chain and response security headers."""

    return await _invoke(probes.get_response_headers, target)


async def probe_http(
    target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    body: str | None = None,
) -> dict[str, Any]:
    """Collect one bounded, redacted HTTP exchange."""

    return await _invoke(probes.probe_http, target, method, headers, body)


async def explore_browser(
    target: str,
    actions: list[dict[str, Any]] | None = None,
    auth_ref: str | None = None,
) -> dict[str, Any]:
    """Explore a target through bounded declarative browser actions."""

    return await _invoke(recon_tools.browser.explore_browser, target, actions, auth_ref)


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

    return await _invoke(recon_tools.nmap.discover_hosts, target)


async def discover_services(
    target: str,
    profile: Literal["service-top-100", "service-explicit-ports"] = "service-top-100",
    ports: list[int] | None = None,
) -> dict[str, Any]:
    """Discover services with a constrained Nmap profile."""

    return await _invoke(recon_tools.nmap.discover_services, target, profile, ports)


async def crawl_web(target: str) -> dict[str, Any]:
    """Crawl same-origin URLs using ZAP traditional Spider."""

    return await _invoke(recon_tools.zap.crawl_web, target)


async def begin_proxy_capture(target: str) -> dict[str, Any]:
    """Create an opaque boundary for traffic observed by the configured ZAP proxy."""

    return await _invoke(recon_tools.zap.begin_proxy_capture, target)


async def collect_proxy_traffic(target: str, capture_ref: str) -> dict[str, Any]:
    """Collect sanitized ZAP proxy traffic for one opaque capture boundary."""

    return await _invoke(recon_tools.zap.collect_proxy_traffic, target, capture_ref)


async def passive_web_analysis(target: str) -> dict[str, Any]:
    """Run ZAP Spider and return passive scanner signals only."""

    return await _invoke(recon_tools.zap.passive_web_analysis, target)


async def fingerprint_web(target: str) -> dict[str, Any]:
    """Fingerprint web technologies with constrained WhatWeb settings."""

    return await _invoke(recon_tools.whatweb.fingerprint_web, target)


async def parse_api_spec(target: str) -> dict[str, Any]:
    """Parse a remote Swagger/OpenAPI document."""

    return await _invoke(recon_tools.openapi.parse_api_spec, target)


TOOLS = (
    probe_http,
    get_response_headers,
    get_cookies,
    get_tls_info,
    get_cors_policy,
    discover_hosts,
    discover_services,
    begin_proxy_capture,
    collect_proxy_traffic,
    crawl_web,
    passive_web_analysis,
    fingerprint_web,
    parse_api_spec,
    explore_browser,
)


def main() -> None:
    try:
        from mcp.server.mcpserver import MCPServer
    except ImportError as exc:
        try:
            from mcp.server import MCPServer
        except ImportError:
            try:
                from mcp.server.fastmcp import FastMCP as MCPServer
            except ImportError:
                raise RuntimeError(
                    "The installed MCP SDK does not expose MCPServer; "
                    "install a compatible mcp package"
                ) from exc

    server = MCPServer("websec-tools")

    for tool in TOOLS:
        server.tool()(tool)
    server.run(transport="stdio")


if __name__ == "__main__":
    main()
