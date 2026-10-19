"""Investigate any site through the MCP tools - no model, no agent.

    python examples/probe_target.py https://example.com
    python examples/probe_target.py https://example.com --json report.json
    python examples/probe_target.py https://example.com --scope https://other.test

Starts `mcp_servers.websec_tools.server` as a real stdio subprocess,
discovers its tools, applies the scope guard, then calls each tool. This is
the cheapest way to exercise Layers 3, 5 and 6 and the whole tool contract.

INIT: no implementation yet.
"""
