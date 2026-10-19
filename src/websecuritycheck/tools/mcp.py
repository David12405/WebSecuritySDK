"""MCP client, per-check allowlist, dead-server handling.

Reads `config/servers.yaml`, starts or connects to each enabled server,
discovers its tools, and hands the agent only the tools the current `Check`
declares. A server that does not come up is an `E_SERVER_UNAVAILABLE` entry
in `errors[]`, not a crash; a check that declares a tool no server provides
is `E_TOOL_MISSING`.

Every tool, ours or a partner's, must take its target as an argument named
`target` - that is the single rule the scope guard depends on, and a tool
that breaks it cannot be allowlisted.

INIT: no implementation yet.
"""
