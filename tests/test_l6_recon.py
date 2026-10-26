import asyncio
import json
from functools import wraps
from pathlib import Path

import pytest

from mcp_servers.websec_tools import server
from mcp_servers.websec_tools.recon import nmap, openapi, whatweb, zap
from mcp_servers.websec_tools.errors import ToolError


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


NMAP_XML = b"""
<nmaprun>
  <host>
    <status state="up" reason="syn-ack"/>
    <address addr="10.0.0.10" addrtype="ipv4"/>
    <hostnames><hostname name="app.internal"/></hostnames>
    <ports>
      <port protocol="tcp" portid="443">
        <state state="open"/>
        <service name="https" product="nginx" version="1.25"/>
      </port>
    </ports>
  </host>
</nmaprun>
"""


@async_test
async def test_nmap_profiles_use_constrained_argv_and_parse_xml():
    calls = []

    async def runner(argv, timeout):
        calls.append((argv, timeout))
        return 0, NMAP_XML, b"secret stderr must not be returned"

    result = await nmap.discover_services("10.0.0.10", runner=runner)

    assert calls[0][0] == [
        "nmap",
        "-sV",
        "-n",
        "--top-ports",
        "100",
        "-oX",
        "-",
        "10.0.0.10",
    ]
    assert result["data"]["hosts"][0]["services"][0]["port"] == 443
    assert "secret stderr" not in json.dumps(result)


@async_test
async def test_nmap_rejects_invalid_profile_and_ports_before_spawn():
    async def runner(argv, timeout):
        raise AssertionError("runner must not be called")

    with pytest.raises(ToolError) as profile_error:
        await nmap.discover_services("10.0.0.1", "arbitrary", runner=runner)
    assert profile_error.value.code == "E_INVALID_ARGUMENT"

    with pytest.raises(ToolError) as ports_error:
        await nmap.discover_services("10.0.0.1", "service-explicit-ports", [], runner=runner)
    assert ports_error.value.code == "E_INVALID_ARGUMENT"


@async_test
async def test_whatweb_uses_fixed_arguments_and_cleans_temporary_output():
    calls = []
    output_path: Path | None = None

    async def runner(argv, path, timeout):
        nonlocal output_path
        calls.append(argv)
        output_path = path
        path.write_text(
            json.dumps(
                [
                    {
                        "plugins": {
                            "nginx": {
                                "version": ["1.25"],
                                "certainty": 100,
                                "categories": ["Web servers"],
                            }
                        }
                    }
                ]
            ),
            encoding="utf-8",
        )
        return 0

    result = await whatweb.fingerprint_web("https://example.com", runner=runner)

    assert calls[0][1:3] == ["--aggression=1", "--follow-redirect=never"]
    assert result["data"]["technologies"][0]["confidence"] == "HIGH"
    assert output_path is not None and not output_path.exists()


def test_openapi_parser_supports_json_yaml_and_rejects_external_refs():
    document = {
        "openapi": "3.0.0",
        "info": {"title": "Demo"},
        "paths": {
            "/users": {
                "get": {
                    "operationId": "listUsers",
                    "parameters": [{"name": "limit", "in": "query", "schema": {"type": "integer"}}],
                    "responses": {"200": {"content": {"application/json": {}}}},
                }
            }
        },
    }
    result = openapi.parse_api_document(document, source_url="https://example.com/openapi.json")
    assert result.operations[0].operation_id == "listUsers"
    assert result.operations[0].parameters[0].schema_type == "integer"

    yaml_result = openapi.parse_api_document(
        "openapi: 3.1.0\ninfo:\n  title: YAML\npaths: {}\n",
        source_url="https://example.com/openapi.yaml",
    )
    assert yaml_result.title == "YAML"

    with pytest.raises(ToolError) as error:
        openapi.parse_api_document(
            {"openapi": "3.0.0", "paths": {"/x": {"get": {"$ref": "other.yaml#/get"}}}},
            source_url="https://example.com/openapi.json",
        )
    assert error.value.code == "E_UNSUPPORTED_INPUT"


@async_test
async def test_zap_crawl_and_passive_are_stateless_and_safe():
    calls = []

    async def requester(path, params):
        calls.append((path, params))
        if path.endswith("newContext/"):
            return {"id": "context"}
        if path.endswith("includeInContext/"):
            return {"Result": "OK"}
        if path.endswith("spider/action/scan/"):
            return {"scan": "1"}
        if path.endswith("spider/view/status/"):
            return {"status": "100"}
        if path.endswith("spider/view/results/"):
            return {"results": ["https://example.com/", "https://third-party.test/no"]}
        if path.endswith("recordsToScan/"):
            return {"recordsToScan": "0"}
        if path.endswith("alerts/"):
            return {
                "alerts": [
                    {
                        "pluginId": "10021",
                        "alert": "X-Content-Type-Options Missing",
                        "risk": "Low",
                        "confidence": "High",
                        "url": "https://example.com/",
                        "cweid": "693",
                    }
                ]
            }
        if path.endswith("removeContext/"):
            return {"Result": "OK"}
        raise AssertionError(path)

    crawl = await zap.crawl_web(
        "https://example.com", base_url="http://zap.invalid", requester=requester
    )
    passive = await zap.passive_web_analysis(
        "https://example.com", base_url="http://zap.invalid", requester=requester
    )

    assert len(crawl["data"]["endpoints"]) == 1
    assert passive["data"]["signals"][0]["plugin_id"] == "10021"
    assert all("apikey" not in params or params["apikey"] == "" for _path, params in calls)


def test_server_registers_all_l6_tools():
    assert [tool.__name__ for tool in server.TOOLS] == [
        "probe_http",
        "get_response_headers",
        "get_cookies",
        "get_tls_info",
        "get_cors_policy",
        "discover_hosts",
        "discover_services",
        "crawl_web",
        "passive_web_analysis",
        "fingerprint_web",
        "parse_api_spec",
        "explore_browser",
    ]
