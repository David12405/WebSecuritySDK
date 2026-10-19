"""The actual network probes, with no MCP in them.

Every probe is passive and read-only: one ordinary HTTP request, or one TLS
handshake. No payloads, no fuzzing, no authentication, no writes.

Size caps declared here, because the contract requires a server to declare
them: 60 headers, 40 cookies, 2048 chars per value, 20 SANs, 5 redirects.

INIT: no implementation yet.
"""
