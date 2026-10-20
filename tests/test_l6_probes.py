import asyncio
import json
from functools import wraps

import httpx
import pytest

from mcp_servers.websec_tools import probes, server


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


def make_client(handler):
    return httpx.AsyncClient(transport=httpx.MockTransport(handler), follow_redirects=False)


@async_test
async def test_response_headers_returns_structured_data_and_caps_headers():
    async def handler(request):
        headers = {f"X-Test-{index}": "value" for index in range(61)}
        headers.update(
            {
                "Strict-Transport-Security": "max-age=1",
                "Content-Security-Policy": "default-src 'none'",
            }
        )
        return httpx.Response(200, headers=headers, request=request)

    async with make_client(handler) as client:
        result = await probes.get_response_headers("https://example.com", client)

    assert set(result) == {"summary", "data", "truncated"}
    assert result["data"]["status"] == 200
    assert "strict-transport-security" in result["data"]["security_headers_present"]
    assert result["truncated"] is True


@async_test
async def test_redirect_chain_and_non_2xx_are_data():
    async def handler(request):
        if request.url.path == "/":
            return httpx.Response(302, headers={"location": "/login"}, request=request)
        return httpx.Response(404, request=request)

    async with make_client(handler) as client:
        result = await probes.get_response_headers("https://example.com", client)

    assert result["data"]["status"] == 404
    assert len(result["data"]["redirects"]) == 1


@async_test
async def test_redirect_loop_is_stable_error():
    async def handler(request):
        return httpx.Response(302, headers={"location": "/"}, request=request)

    async with make_client(handler) as client:
        with pytest.raises(probes.ProbeError, match="more than 5") as error:
            await probes.get_response_headers("https://example.com", client)

    assert error.value.code == "E_REDIRECT_LOOP"


@async_test
async def test_cookie_probe_never_returns_cookie_value():
    async def handler(request):
        return httpx.Response(
            200,
            headers={
                "set-cookie": "session=super-secret; Secure; HttpOnly; SameSite=Lax; Path=/"
            },
            request=request,
        )

    async with make_client(handler) as client:
        result = await probes.get_cookies("https://example.com", client)

    serialized = json.dumps(result)
    assert "super-secret" not in serialized
    assert result["data"]["cookies"] == [{
        "name": "session", "value_length": 12, "secure": True, "httponly": True,
        "samesite": "Lax", "domain": None, "path": "/", "expires": None,
    }]


@async_test
async def test_header_probe_redacts_sensitive_header_values():
    async def handler(request):
        return httpx.Response(
            200,
            headers={"set-cookie": "session=super-secret", "x-api-key": "api-secret"},
            request=request,
        )

    async with make_client(handler) as client:
        result = await probes.get_response_headers("https://example.com", client)

    serialized = json.dumps(result)
    assert "super-secret" not in serialized
    assert "api-secret" not in serialized
    assert result["data"]["headers"]["set-cookie"] == "<redacted>"


@async_test
async def test_cors_probe_collects_simple_and_preflight():
    async def handler(request):
        if request.method == "OPTIONS":
            return httpx.Response(
                204,
                headers={
                    "access-control-allow-origin": "*",
                    "access-control-allow-methods": "GET",
                    "vary": "Origin",
                },
                request=request,
            )
        return httpx.Response(
            200,
            headers={
                "access-control-allow-origin": "*",
                "access-control-allow-credentials": "true",
            },
            request=request,
        )

    async with make_client(handler) as client:
        result = await probes.get_cors_policy("https://example.com", client)

    assert result["data"]["simple"]["status"] == 200
    assert result["data"]["preflight"]["status"] == 204
    assert result["data"]["wildcard_origin"] is True
    assert result["data"]["allow_credentials"] is True


@async_test
async def test_timeout_and_invalid_target_errors():
    async def timeout_handler(request):
        raise httpx.ReadTimeout("timed out", request=request)

    async with make_client(timeout_handler) as client:
        with pytest.raises(probes.ProbeError) as error:
            await probes.get_response_headers("https://example.com", client)
    assert error.value.code == "E_TIMEOUT"

    with pytest.raises(probes.ProbeError) as invalid:
        await probes.get_response_headers("not-a-url")
    assert invalid.value.code == "E_INVALID_TARGET"


@async_test
async def test_tls_probe_is_injectable(monkeypatch):
    info = {
        "protocol": "TLSv1.3",
        "cipher": "TLS_AES_256_GCM_SHA384",
        "chain_valid": True,
        "issuer": "CA",
        "subject": "example.com",
        "not_before": "2025-01-01T00:00:00+00:00",
        "not_after": "2027-01-01T00:00:00+00:00",
        "days_to_expiry": 400,
        "sans": ["example.com"],
    }
    monkeypatch.setattr(probes, "_tls_handshake", lambda target: (info, False))
    result = await probes.get_tls_info("https://example.com")
    assert result["data"]["protocol"] == "TLSv1.3"


@async_test
async def test_mcp_wrappers_keep_probe_errors_stable(monkeypatch):
    async def fail(target):
        raise probes.ProbeError("E_TIMEOUT", "timed out")

    monkeypatch.setattr(server.probes, "get_response_headers", fail)
    with pytest.raises(RuntimeError, match=r"^E_TIMEOUT:"):
        await server.get_response_headers("https://example.com")
