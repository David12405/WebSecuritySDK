"""MCP tool definitions.  Speaks MCP over stdio.

    python -m mcp_servers.websec_tools.server

Tools in v0.1 - every one takes `target`:

    get_response_headers   final URL, status, redirect chain, all headers,
                           which security headers are present or missing
    get_cookies            per cookie: name, value LENGTH, secure, httponly,
                           samesite, domain, path, expiry
    get_tls_info           protocol, cipher, chain validity, issuer, subject,
                           notBefore/notAfter, days to expiry, SANs
    get_cors_policy        simple + preflight CORS headers, reflection,
                           wildcard, vary-includes-origin

Output envelope, always structured JSON and never raw prose:

    {"summary": "one line", "data": {...}, "truncated": false}

The summary is what survives context compaction as a stub, so it has to carry
the headline fact on its own.

Errors are an MCP `isError` result whose text begins with a stable code -
`E_TIMEOUT: connect timed out after 10.0s`. A non-2xx HTTP status is NOT an
error; it is data, returned in `data.status`.

INIT: no implementation yet.
"""
