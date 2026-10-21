"""Thin MCP transport for the Layer 6 security tools."""

from __future__ import annotations

from collections.abc import Awaitable, Callable
from typing import Any, Literal

from . import analysis as analysis_tools
from . import probes

try:
    from . import recon as recon_tools
except ImportError:  # Compatibility while the recon package is not merged.
    from . import nmap, openapi, whatweb, zap

    class _FlatReconTools:
        nmap = nmap
        openapi = openapi
        whatweb = whatweb
        zap = zap

    recon_tools = _FlatReconTools()
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


async def passive_web_analysis(target: str) -> dict[str, Any]:
    """Run ZAP Spider and return passive scanner signals only."""

    return await _invoke(recon_tools.zap.passive_web_analysis, target)


async def fingerprint_web(target: str) -> dict[str, Any]:
    """Fingerprint web technologies with constrained WhatWeb settings."""

    return await _invoke(recon_tools.whatweb.fingerprint_web, target)


async def parse_api_spec(target: str) -> dict[str, Any]:
    """Parse a remote Swagger/OpenAPI document."""

    return await _invoke(recon_tools.openapi.parse_api_spec, target)


async def inspect_source_tree(
    target: str, path: str = ".", max_depth: int = 4
) -> dict[str, Any]:
    """Return deterministic repository structure facts."""

    return await _invoke(analysis_tools.source.inspect_source_tree, target, path, max_depth)


async def read_source_file(
    target: str,
    path: str,
    start_line: int = 1,
    end_line: int | None = None,
) -> dict[str, Any]:
    """Return a bounded range from an authorized source file."""

    return await _invoke(
        analysis_tools.source.read_source_file, target, path, start_line, end_line
    )


async def search_source(
    target: str,
    query: str,
    path: str = ".",
    case_sensitive: bool = False,
) -> dict[str, Any]:
    """Search repository source using bounded literal matching."""

    return await _invoke(
        analysis_tools.source.search_source, target, query, path, case_sensitive
    )


async def analyze_source(target: str, path: str = ".") -> dict[str, Any]:
    """Run the server-configured Semgrep ruleset over repository source."""

    return await _invoke(analysis_tools.semgrep.analyze_source, target, path)


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
    inspect_source_tree,
    read_source_file,
    search_source,
    analyze_source,
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
