"""Single inventory contract for the currently exposed L6 tools."""

from mcp_servers.websec_tools import server


TOOL_COVERAGE = {
    "probe_http": "http",
    "get_response_headers": "http",
    "get_cookies": "http",
    "get_tls_info": "http",
    "get_cors_policy": "http",
    "discover_hosts": "network",
    "discover_services": "network",
    "crawl_web": "zap",
    "passive_web_analysis": "zap",
    "fingerprint_web": "whatweb",
    "parse_api_spec": "openapi",
    "explore_browser": "browser",
}


def test_every_registered_tool_has_declared_test_coverage():
    names = [tool.__name__ for tool in server.TOOLS]
    assert len(names) == len(set(names))
    assert set(names) == set(TOOL_COVERAGE)


def test_tool_inventory_has_no_unclassified_entries():
    assert set(TOOL_COVERAGE.values()) == {"http", "network", "zap", "whatweb", "openapi", "browser"}
