"""Opt-in live L6 checks for an authorized Metasploitable3 lab target."""

from __future__ import annotations

import asyncio
import os
from functools import wraps

import pytest

from mcp_servers.websec_tools import probes
from mcp_servers.websec_tools.errors import ToolError
from mcp_servers.websec_tools.recon import browser, nmap, openapi, whatweb, zap


pytestmark = [
    pytest.mark.live_tools,
    pytest.mark.skipif(
        not os.getenv("RUN_LIVE_TOOLS") or not os.getenv("WEBSEC_LIVE_HOST"),
        reason="set RUN_LIVE_TOOLS=1 and WEBSEC_LIVE_HOST for lab tests",
    ),
]


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def _skip_unavailable(error: ToolError):
    if error.code in {"E_TOOL_UNAVAILABLE", "E_CONNECT"}:
        pytest.skip(f"live dependency unavailable: {error.code}")
    raise error


@async_test
async def test_live_nmap_discovery_contract():
    try:
        result = await nmap.discover_services(os.environ["WEBSEC_LIVE_HOST"])
    except ToolError as error:
        _skip_unavailable(error)
    assert set(result) == {"summary", "data", "truncated"}
    assert result["data"]["target"] == os.environ["WEBSEC_LIVE_HOST"]


@async_test
async def test_live_http_and_technology_contract():
    target = os.environ.get("WEBSEC_LIVE_URL") or f"http://{os.environ['WEBSEC_LIVE_HOST']}/"
    try:
        http_result = await probes.probe_http(target)
        fingerprint = await whatweb.fingerprint_web(target)
    except ToolError as error:
        _skip_unavailable(error)
    assert http_result["data"]["final_url"]
    assert http_result["data"]["artifact_manifests"]
    assert "password" not in str(http_result).lower() or "<redacted>" in str(http_result)
    assert set(fingerprint) == {"summary", "data", "truncated"}


@async_test
async def test_live_zap_contract():
    target = os.environ.get("WEBSEC_LIVE_URL") or f"http://{os.environ['WEBSEC_LIVE_HOST']}/"
    try:
        crawl = await zap.crawl_web(target)
    except ToolError as error:
        _skip_unavailable(error)
    assert crawl["data"]["target"] == target
    assert crawl["data"]["artifact_manifests"]


@async_test
async def test_live_browser_contract():
    target = os.environ.get("WEBSEC_LIVE_URL") or f"http://{os.environ['WEBSEC_LIVE_HOST']}/"
    try:
        browser_result = await browser.explore_browser(target, actions=[])
    except ToolError as error:
        _skip_unavailable(error)
    assert browser_result["data"]["target"] == target
    assert browser_result["data"]["artifact_manifests"]


@async_test
async def test_live_openapi_contract_or_expected_absence():
    target = os.environ.get("WEBSEC_LIVE_URL") or f"http://{os.environ['WEBSEC_LIVE_HOST']}/"
    try:
        result = await openapi.parse_api_spec(target)
    except ToolError as error:
        if error.code in {"E_HTTP", "E_PARSE", "E_UNSUPPORTED_INPUT"}:
            pytest.skip("target does not publish an API specification")
        _skip_unavailable(error)
    assert set(result) == {"summary", "data", "truncated"}
    assert result["data"]["artifact_manifests"]
