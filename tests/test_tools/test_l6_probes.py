import asyncio
import importlib
import ipaddress
import json
import socket
from datetime import UTC, datetime, timedelta
from functools import wraps

import httpx
import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID

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
            headers={"set-cookie": "session=super-secret; Secure; HttpOnly; SameSite=Lax; Path=/"},
            request=request,
        )

    async with make_client(handler) as client:
        result = await probes.get_cookies("https://example.com", client)

    serialized = json.dumps(result)
    assert "super-secret" not in serialized
    assert result["data"]["cookies"] == [
        {
            "name": "session",
            "value_length": 12,
            "secure": True,
            "httponly": True,
            "samesite": "Lax",
            "domain": None,
            "path": "/",
            "expires": None,
        }
    ]


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


def test_certificate_info_parses_self_signed_certificate():
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    name = x509.Name(
        [
            x509.NameAttribute(NameOID.COMMON_NAME, "example.com"),
            x509.NameAttribute(NameOID.ORGANIZATION_NAME, "Example Org"),
        ]
    )
    now = datetime.now(UTC)
    certificate = (
        x509.CertificateBuilder()
        .subject_name(name)
        .issuer_name(name)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(days=1))
        .not_valid_after(now + timedelta(days=30))
        .add_extension(
            x509.SubjectAlternativeName(
                [
                    x509.DNSName("example.com"),
                    x509.IPAddress(ipaddress.ip_address("127.0.0.1")),
                ]
            ),
            critical=False,
        )
        .sign(key, hashes.SHA256())
    )

    info, truncated = probes._certificate_info(
        certificate.public_bytes(serialization.Encoding.DER), chain_valid=True
    )

    assert truncated is False
    assert info["chain_valid"] is True
    assert info["issuer"] == "O=Example Org,CN=example.com"
    assert info["subject"] == "O=Example Org,CN=example.com"
    assert info["sans"] == ["example.com", "127.0.0.1"]
    assert info["not_before"] < now < info["not_after"]
    assert 29 <= info["days_to_expiry"] <= 30


def test_tls_handshake_preserves_connection_error(monkeypatch):
    def fail(*args, **kwargs):
        raise socket.gaierror("host unavailable")

    monkeypatch.setattr(probes.socket, "create_connection", fail)
    with pytest.raises(probes.ProbeError) as error:
        probes._tls_handshake("https://example.com")

    assert error.value.code == "E_CONNECT"


def _mcp_tool_error_type():
    for module_name in (
        "mcp.server.mcpserver.exceptions",
        "mcp.server.exceptions",
        "mcp.server.fastmcp.exceptions",
    ):
        try:
            module = importlib.import_module(module_name)
        except ImportError:
            continue
        error_type = getattr(module, "ToolError", None)
        if error_type is not None:
            return error_type
    pytest.skip("MCP SDK ToolError is unavailable")


@async_test
async def test_mcp_wrappers_keep_probe_errors_stable(monkeypatch):
    async def fail(target):
        raise probes.ProbeError("E_TIMEOUT", "timed out")

    monkeypatch.setattr(server.probes, "get_response_headers", fail)
    with pytest.raises(_mcp_tool_error_type(), match=r"^E_TIMEOUT:"):
        await server.get_response_headers("https://example.com")


@pytest.mark.parametrize(
    "wrapper_name,probe_name",
    [
        ("probe_http", "probe_http"),
        ("get_response_headers", "get_response_headers"),
        ("get_cookies", "get_cookies"),
        ("get_tls_info", "get_tls_info"),
        ("get_cors_policy", "get_cors_policy"),
    ],
)
@async_test
async def test_all_http_mcp_wrappers_preserve_error_codes(monkeypatch, wrapper_name, probe_name):
    async def fail(*_args, **_kwargs):
        raise probes.ProbeError("E_TIMEOUT", "timed out")

    monkeypatch.setattr(server.probes, probe_name, fail)
    with pytest.raises(_mcp_tool_error_type(), match=r"^E_TIMEOUT:"):
        await getattr(server, wrapper_name)("https://example.com")


@async_test
async def test_probe_http_preserves_exchange_facts_and_redacts_secrets():
    async def handler(request):
        assert request.method == "POST"
        assert request.content == b'{"user.id":"7","password":"secret"}'
        return httpx.Response(
            201,
            headers={"content-type": "application/json", "set-cookie": "sid=secret-cookie"},
            json={"user.id": "7", "password": "response-secret"},
            request=request,
        )

    async with make_client(handler) as client:
        result = await probes.probe_http(
            "https://example.com/api/users",
            method="POST",
            headers={"Content-Type": "application/json", "Authorization": "Bearer secret-token"},
            body='{"user.id":"7","password":"secret"}',
            client=client,
        )

    serialized = json.dumps(result)
    assert "secret-token" not in serialized
    assert "response-secret" not in serialized
    assert "secret-cookie" not in serialized
    assert result["data"]["status"] == 201
    assert result["data"]["request_parameter_names"] == ["password", "user.id"]
    assert result["data"]["artifact_manifests"][0]["artifact_type"] == "HTTP_RAW_EXCHANGE"


@async_test
async def test_probe_http_blocks_cross_origin_and_https_downgrade_redirects():
    calls = []

    async def cross_origin(request):
        calls.append(str(request.url))
        return httpx.Response(302, headers={"location": "https://evil.example/next"}, request=request)

    async with make_client(cross_origin) as client:
        with pytest.raises(probes.ProbeError, match="outside the initial origin") as error:
            await probes.probe_http("https://example.com", client=client)
    assert error.value.code == "E_SCOPE"
    assert calls == ["https://example.com/"]

    async def downgrade(request):
        return httpx.Response(302, headers={"location": "http://example.com/next"}, request=request)

    async with make_client(downgrade) as client:
        with pytest.raises(probes.ProbeError, match="downgrade") as error:
            await probes.probe_http("https://example.com", client=client)
    assert error.value.code == "E_SCOPE"


@async_test
async def test_probe_http_rejects_unsupported_method_before_request():
    async def handler(_request):
        raise AssertionError("the transport must not be called")

    async with make_client(handler) as client:
        with pytest.raises(probes.ProbeError) as error:
            await probes.probe_http("https://example.com", method="TRACE", client=client)
    assert error.value.code == "E_INVALID_ARGUMENT"


@async_test
async def test_tls_probe_rejects_http_and_preserves_stable_code():
    with pytest.raises(probes.ProbeError) as error:
        await probes.get_tls_info("http://example.com")
    assert error.value.code == "E_TLS"
