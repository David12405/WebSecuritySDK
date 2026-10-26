import asyncio
import json
from functools import wraps
from pathlib import Path

import pytest

from mcp_servers.websec_tools import server
from mcp_servers.websec_tools.errors import ToolError
from mcp_servers.websec_tools.recon import nmap, openapi, whatweb, zap


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


@async_test
async def test_zap_proxy_capture_is_bounded_scoped_redacted_and_spider_free(monkeypatch):
    zap._CAPTURES.clear()
    monkeypatch.setattr(zap, "PROXY_MESSAGE_PAGE_SIZE", 2)
    calls = []
    message_count_calls = 0
    raw_messages = [
        {
            "requestHeader": (
                "POST https://user:request-secret@example.com/login?token=secret-query "
                "HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Authorization: Bearer secret-auth\r\n"
                "Cookie: sid=secret-cookie\r\n"
                "Content-Type: application/json\r\n"
            ),
            "requestBody": '{"user":{"id":"7"},"password":"secret-body"}',
            "responseHeader": (
                "HTTP/1.1 201 Created\r\n"
                "Content-Type: application/json; charset=utf-8\r\n"
                "Set-Cookie: sid=secret-response\r\n"
            ),
            "responseBody": '{"token":"secret-response-body"}',
        },
        {
            "requestHeader": (
                "GET https://outside.test/tracker?api_key=secret HTTP/1.1\r\n"
                "Host: outside.test\r\n"
            ),
            "responseHeader": "HTTP/1.1 200 OK\r\nContent-Type: text/plain\r\n",
        },
        {
            "requestHeader": (
                "POST /profile HTTP/1.1\r\n"
                "Host: example.com\r\n"
                "Content-Type: application/x-www-form-urlencoded\r\n"
            ),
            "requestBody": "email=user%40example.com&password=secret-form",
            "responseHeader": "HTTP/1.1 204 No Content\r\n",
        },
    ]

    async def requester(path, params):
        nonlocal message_count_calls
        calls.append((path, params))
        if path.endswith("numberOfMessages/"):
            message_count_calls += 1
            return {"numberOfMessages": "10" if message_count_calls == 1 else "13"}
        if path.endswith("messages/"):
            start = int(params["start"]) - 10
            count = int(params["count"])
            return {"messages": raw_messages[start : start + count]}
        raise AssertionError(path)

    boundary = await zap.begin_proxy_capture(
        "https://example.com?token=boundary-secret",
        base_url="http://zap.invalid",
        requester=requester,
    )
    capture_ref = boundary["data"]["capture_ref"]
    assert capture_ref.startswith("ZCAP-")
    assert boundary["data"]["target"] == "https://example.com"
    assert "boundary-secret" not in json.dumps(boundary)
    assert "start_message_index" not in json.dumps(boundary)

    result = await zap.collect_proxy_traffic(
        "https://example.com:443/path?token=collection-secret",
        capture_ref,
        base_url="http://zap.invalid",
        requester=requester,
    )

    serialized = json.dumps(result)
    for secret in (
        "secret-query",
        "request-secret",
        "secret-auth",
        "secret-cookie",
        "secret-body",
        "secret-response",
        "secret-response-body",
        "secret-form",
        "collection-secret",
    ):
        assert secret not in serialized
    assert result["data"]["target"] == "https://example.com:443"
    assert [item["url"] for item in result["data"]["messages"]] == [
        "https://example.com/login",
        "https://example.com/profile",
    ]
    assert result["data"]["messages"][0]["query_parameter_names"] == ["token"]
    assert result["data"]["messages"][0]["body_parameter_names"] == [
        "password",
        "user",
        "user.id",
    ]
    assert result["data"]["excluded_message_count"] == 1
    assert result["data"]["artifact_manifests"][0]["redaction_applied"] is True
    assert not any("spider" in path for path, _params in calls)

    with pytest.raises(ToolError) as reused:
        await zap.collect_proxy_traffic(
            "https://example.com",
            capture_ref,
            base_url="http://zap.invalid",
            requester=requester,
        )
    assert reused.value.code == "E_INVALID_ARGUMENT"


@async_test
async def test_zap_proxy_capture_is_target_bound_and_expires(monkeypatch):
    zap._CAPTURES.clear()

    async def requester(path, _params):
        if path.endswith("numberOfMessages/"):
            return {"numberOfMessages": "0"}
        raise AssertionError(path)

    boundary = await zap.begin_proxy_capture(
        "https://example.com", base_url="http://zap.invalid", requester=requester
    )
    capture_ref = boundary["data"]["capture_ref"]
    with pytest.raises(ToolError) as mismatch:
        await zap.collect_proxy_traffic(
            "https://other.example",
            capture_ref,
            base_url="http://zap.invalid",
            requester=requester,
        )
    assert mismatch.value.code == "E_SCOPE"

    zap._CAPTURES.clear()
    monkeypatch.setattr(zap, "CAPTURE_TTL_SECONDS", -1.0)
    expired = await zap.begin_proxy_capture(
        "https://example.com", base_url="http://zap.invalid", requester=requester
    )
    with pytest.raises(ToolError) as expiry:
        await zap.collect_proxy_traffic(
            "https://example.com",
            expired["data"]["capture_ref"],
            base_url="http://zap.invalid",
            requester=requester,
        )
    assert expiry.value.code == "E_INVALID_ARGUMENT"


@async_test
async def test_zap_proxy_capture_retries_api_errors_and_counts_overflow(monkeypatch):
    zap._CAPTURES.clear()
    monkeypatch.setattr(zap, "MAX_PROXY_MESSAGES", 1)
    count_calls = 0

    async def requester(path, _params):
        nonlocal count_calls
        if path.endswith("numberOfMessages/"):
            count_calls += 1
            if count_calls == 2:
                raise TimeoutError
            return {"numberOfMessages": "0" if count_calls == 1 else "3"}
        if path.endswith("messages/"):
            return {
                "messages": [
                    {
                        "requestHeader": "GET https://example.com/one HTTP/1.1\r\n",
                        "responseHeader": "HTTP/1.1 200 OK\r\n",
                    }
                ]
            }
        raise AssertionError(path)

    boundary = await zap.begin_proxy_capture(
        "https://example.com", base_url="http://zap.invalid", requester=requester
    )
    capture_ref = boundary["data"]["capture_ref"]
    with pytest.raises(ToolError) as transient:
        await zap.collect_proxy_traffic(
            "https://example.com",
            capture_ref,
            base_url="http://zap.invalid",
            requester=requester,
        )
    assert transient.value.code == "E_TIMEOUT"
    assert capture_ref in zap._CAPTURES

    result = await zap.collect_proxy_traffic(
        "https://example.com",
        capture_ref,
        base_url="http://zap.invalid",
        requester=requester,
    )
    assert result["data"]["captured_message_count"] == 1
    assert result["data"]["dropped_message_count"] == 2
    assert result["truncated"] is True
    assert capture_ref not in zap._CAPTURES


def test_server_registers_all_l6_tools():
    assert [tool.__name__ for tool in server.TOOLS] == [
        "probe_http",
        "get_response_headers",
        "get_cookies",
        "get_tls_info",
        "get_cors_policy",
        "discover_hosts",
        "discover_services",
        "begin_proxy_capture",
        "collect_proxy_traffic",
        "crawl_web",
        "passive_web_analysis",
        "fingerprint_web",
        "parse_api_spec",
        "explore_browser",
    ]
