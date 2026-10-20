"""MCP tool definitions.  Speaks MCP over stdio.

    python -m mcp_servers.websec_tools.server

Four passive tools, every one of them taking its target in an argument
named `target`. That naming is not a style choice: the scope guard reads
`tool_use.input["target"]` without knowing what the tool does, so a tool
that calls it `url` or `host` cannot be scope-checked and is not
allowlisted.

This module is deliberately thin. The probes do the work and the analysis;
this file turns them into MCP tools and turns a `ProbeError` into the error
shape the contract specifies.

**Why errors are raised as `ToolError`.** The SDK returns `str(exc)`
verbatim for `ToolError`, but wraps anything else as "Error executing tool
<name>: ...". The contract says the text *begins* with a stable code, which
is what lets the retry hook classify a failure without parsing prose - so
the code has to be first, and only `ToolError` keeps it there.
"""

from __future__ import annotations

import logging
from typing import Annotated, Any

from mcp.server import MCPServer
from mcp.server.mcpserver.exceptions import ToolError
from pydantic import Field

from . import probes
from .probes import PROBE_ORIGIN, ProbeError

server = MCPServer(
    name="websec-tools",
    version="0.1.0",
    instructions=(
        "Passive web-security probes. Every tool performs one ordinary HTTP "
        "request or one TLS handshake against a target you are authorised to "
        "test. No payloads, no fuzzing, no authentication, no writes. Each "
        "returns {summary, data, truncated}; a non-2xx status is data, not an "
        "error."
    ),
)

Target = Annotated[str, Field(description="The http(s) URL to probe.")]


def _run(probe, *args: Any) -> dict[str, Any]:
    """Call a probe, and give a failure the shape the contract requires."""
    try:
        return probe(*args).as_dict()
    except ProbeError as exc:
        raise ToolError(str(exc)) from exc
    except Exception as exc:  # a bug in the probe is still a declared code
        raise ToolError(f"E_INTERNAL: {exc.__class__.__name__}: {exc}") from exc


@server.tool()
def get_response_headers(target: Target) -> dict[str, Any]:
    """Fetch a URL and return its HTTP response headers.

    Reports the final URL after redirects, the status, every response header,
    which security headers are present or missing, and which headers disclose
    information about the stack.
    """
    return _run(probes.probe_response_headers, target)


@server.tool()
def get_cookies(target: Target) -> dict[str, Any]:
    """Return the cookies a URL sets, and which of them have weak flags.

    Cookie values are never returned - only their length. A cookie value is a
    live session credential and has no place in a report.
    """
    return _run(probes.probe_cookies, target)


@server.tool()
def get_tls_info(target: Target) -> dict[str, Any]:
    """Complete one TLS handshake and describe the certificate.

    Returns the protocol version, the cipher, whether the chain is trusted
    and why not, the issuer and subject, the validity window, days to expiry
    and the subject alternative names. Requires an https URL.
    """
    return _run(probes.probe_tls, target)


@server.tool()
def get_cors_policy(
    target: Target,
    origin: Annotated[
        str,
        Field(description="The origin the probe claims to be. Sent as a header; never contacted."),
    ] = PROBE_ORIGIN,
) -> dict[str, Any]:
    """Send a simple request and a preflight from an unknown origin.

    Reports allow-origin, allow-credentials, whether an arbitrary origin is
    reflected, whether Vary includes Origin, and the preflight answer.
    """
    return _run(probes.probe_cors, target, origin)


def main() -> None:
    # httpx logs every request at INFO, which on stdio lands in the client's
    # stderr and buries the server's own output. A probe that says what it
    # did belongs in the envelope, not in a log line.
    logging.getLogger("httpx").setLevel(logging.WARNING)
    server.run()


if __name__ == "__main__":
    main()
