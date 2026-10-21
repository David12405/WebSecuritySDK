"""Passive, MCP-independent network probes for the Layer 6 server."""

from __future__ import annotations

import asyncio
import ipaddress
import math
import re
import socket
import ssl
from datetime import UTC, datetime
from http.cookies import SimpleCookie
from typing import Any
from urllib.parse import urljoin, urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.backends import default_backend
from pydantic import BaseModel, ConfigDict, Field

from .errors import ToolError, envelope, safe_message

TIMEOUT_SECONDS = 10.0
MAX_REDIRECTS = 5
MAX_HEADERS = 60
MAX_COOKIES = 40
MAX_VALUE_LENGTH = 2048
MAX_SANS = 20
TEST_ORIGIN = "https://websecuritycheck.invalid"
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
)
SENSITIVE_HEADERS = frozenset(
    {"set-cookie", "authorization", "proxy-authorization", "x-api-key"}
)
_HOSTNAME_RE = re.compile(
    r"^(?=.{1,253}$)(?:[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?\.)*"
    r"[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?$"
)


class RedirectHop(BaseModel):
    from_url: str = Field(alias="from")
    to_url: str = Field(alias="to")
    status: int

    model_config = ConfigDict(extra="forbid", populate_by_name=True)


class ResponseHeadersResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    final_url: str
    status: int
    http_version: str
    redirects: list[RedirectHop]
    headers: dict[str, str]
    redacted_headers: list[str]
    security_headers_present: list[str]
    security_headers_missing: list[str]


class CookieMetadata(BaseModel):
    model_config = ConfigDict(extra="forbid")

    name: str
    value_length: int = Field(ge=0)
    secure: bool
    httponly: bool
    samesite: str | None = None
    domain: str | None = None
    path: str | None = None
    expires: str | None = None


class CookieResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    final_url: str
    status: int
    redirects: list[RedirectHop]
    cookies: list[CookieMetadata]


class TLSInfoResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    hostname: str
    port: int = Field(ge=1, le=65535)
    protocol: str | None = None
    cipher: str | None = None
    chain_valid: bool
    issuer: str
    subject: str
    not_before: datetime
    not_after: datetime
    days_to_expiry: int
    sans: list[str]


class CORSExchange(BaseModel):
    model_config = ConfigDict(extra="forbid")

    status: int
    headers: dict[str, str]
    redirects: list[RedirectHop]


class CORSPolicyResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    origin_tested: str
    simple: CORSExchange
    preflight: CORSExchange
    allow_origin: str | None = None
    allow_credentials: bool
    origin_reflected: bool
    wildcard_origin: bool
    vary_includes_origin: bool


ProbeError = ToolError


def _validate_target(target: str) -> None:
    try:
        parsed = urlsplit(target)
        hostname = parsed.hostname
        port = parsed.port
    except (TypeError, ValueError):
        raise ProbeError("E_INVALID_TARGET", "target is not a valid URL") from None
    if (
        parsed.scheme not in {"http", "https"}
        or not hostname
        or parsed.username
        or parsed.password
        or (port is not None and not 1 <= port <= 65535)
        or any(char.isspace() or ord(char) < 32 for char in target)
    ):
        raise ProbeError("E_INVALID_TARGET", "target must be an absolute HTTP(S) URL")
    try:
        ascii_hostname = hostname.encode("idna").decode("ascii").rstrip(".")
    except UnicodeError:
        raise ProbeError("E_INVALID_TARGET", "target hostname is invalid") from None
    try:
        ipaddress.ip_address(ascii_hostname)
    except ValueError:
        if not _HOSTNAME_RE.fullmatch(ascii_hostname):
            raise ProbeError("E_INVALID_TARGET", "target hostname is invalid") from None


def _cap(value: str | None) -> tuple[str, bool]:
    value = value or ""
    if len(value) <= MAX_VALUE_LENGTH:
        return value, False
    return value[:MAX_VALUE_LENGTH], True


def _header_map(response: httpx.Response) -> tuple[dict[str, str], bool]:
    output: dict[str, str] = {}
    truncated = len(response.headers) > MAX_HEADERS
    items = list(response.headers.items())
    security_names = {name for name, _value in items if name.lower() in SECURITY_HEADERS}
    prioritized = [item for item in items if item[0].lower() in security_names]
    prioritized.extend(item for item in items if item[0].lower() not in security_names)
    for name, value in prioritized[:MAX_HEADERS]:
        normalized = name.lower()
        if normalized in SENSITIVE_HEADERS:
            output[normalized] = "<redacted>"
            continue
        capped, was_truncated = _cap(value)
        output[normalized] = capped
        truncated = truncated or was_truncated
    return output, truncated


async def _fetch(
    client: httpx.AsyncClient,
    target: str,
    method: str = "GET",
    headers: dict[str, str] | None = None,
) -> tuple[httpx.Response, list[dict[str, Any]]]:
    _validate_target(target)
    current = target
    chain: list[dict[str, Any]] = []
    for _ in range(MAX_REDIRECTS + 1):
        try:
            response = await client.request(
                method, current, headers=headers or {}, follow_redirects=False
            )
        except httpx.TimeoutException as exc:
            raise ProbeError(
                "E_TIMEOUT", f"request timed out after {TIMEOUT_SECONDS:.1f}s"
            ) from exc
        except httpx.InvalidURL as exc:
            raise ProbeError("E_INVALID_TARGET", "target URL is invalid") from exc
        except httpx.ConnectError as exc:
            raise ProbeError("E_CONNECT", "connection failed") from exc
        except httpx.HTTPError as exc:
            raise ProbeError("E_HTTP", "HTTP transport failed") from exc

        location = response.headers.get("location")
        if response.status_code not in {301, 302, 303, 307, 308} or not location:
            return response, chain
        if len(chain) >= MAX_REDIRECTS:
            raise ProbeError("E_REDIRECT_LOOP", f"more than {MAX_REDIRECTS} redirects")
        next_target = urljoin(current, location)
        _validate_target(next_target)
        chain.append({"from": current, "to": next_target, "status": response.status_code})
        current = next_target
    raise ProbeError("E_REDIRECT_LOOP", f"more than {MAX_REDIRECTS} redirects")


def _client_or_default(client: httpx.AsyncClient | None) -> tuple[httpx.AsyncClient, bool]:
    if client is not None:
        return client, False
    return httpx.AsyncClient(follow_redirects=False, timeout=TIMEOUT_SECONDS), True


async def get_response_headers(
    target: str, client: httpx.AsyncClient | None = None
) -> dict[str, Any]:
    http, owned = _client_or_default(client)
    try:
        response, redirects = await _fetch(http, target)
        headers, truncated = _header_map(response)
        present = [name for name in SECURITY_HEADERS if name in headers]
        missing = [name for name in SECURITY_HEADERS if name not in headers]
        final_url = str(response.url)
        summary = (
            f"{response.status_code} {response.http_version} on {final_url} — "
            f"{len(headers)} headers"
        )
        result = ResponseHeadersResult(
            final_url=final_url,
            status=response.status_code,
            http_version=response.http_version,
            redirects=redirects,
            headers=headers,
            redacted_headers=sorted(
                name for name in SENSITIVE_HEADERS if name in response.headers
            ),
            security_headers_present=present,
            security_headers_missing=missing,
        )
        return envelope(
            summary,
            result.model_dump(mode="json", by_alias=True),
            truncated,
        )
    finally:
        if owned:
            await http.aclose()


def _cookie_data(set_cookie_headers: list[str]) -> tuple[list[dict[str, Any]], bool]:
    cookies: list[dict[str, Any]] = []
    truncated = len(set_cookie_headers) > MAX_COOKIES
    for raw in set_cookie_headers[:MAX_COOKIES]:
        parsed = SimpleCookie()
        parsed.load(raw)
        for name, morsel in parsed.items():
            expires, expiry_truncated = _cap(morsel["expires"] or None)
            cookies.append(
                {
                    "name": name,
                    "value_length": len(morsel.value),
                    "secure": bool(morsel["secure"]),
                    "httponly": bool(morsel["httponly"]),
                    "samesite": morsel["samesite"] or None,
                    "domain": morsel["domain"] or None,
                    "path": morsel["path"] or None,
                    "expires": expires or None,
                }
            )
            truncated = truncated or expiry_truncated
    truncated = truncated or len(cookies) > MAX_COOKIES
    return cookies[:MAX_COOKIES], truncated


async def get_cookies(target: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    http, owned = _client_or_default(client)
    try:
        response, redirects = await _fetch(http, target)
        cookies, truncated = _cookie_data(response.headers.get_list("set-cookie"))
        result = CookieResult(
            final_url=str(response.url),
            status=response.status_code,
            redirects=redirects,
            cookies=cookies,
        )
        return envelope(
            f"{len(cookies)} cookies observed on {response.url}",
            result.model_dump(mode="json", by_alias=True),
            truncated,
        )
    finally:
        if owned:
            await http.aclose()


def _name(attributes: x509.Name) -> str:
    return attributes.rfc4514_string()


def _certificate_info(der: bytes, chain_valid: bool) -> tuple[dict[str, Any], bool]:
    certificate = x509.load_der_x509_certificate(der, default_backend())
    now = datetime.now(UTC)
    not_before = certificate.not_valid_before_utc
    not_after = certificate.not_valid_after_utc
    sans: list[str] = []
    try:
        extension = certificate.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        sans = [str(value) for value in extension.value.get_values_for_type(x509.DNSName)]
        sans.extend(str(value) for value in extension.value.get_values_for_type(x509.IPAddress))
    except x509.ExtensionNotFound:
        pass
    truncated = len(sans) > MAX_SANS
    days = math.floor((not_after - now).total_seconds() / 86400)
    return {
        "protocol": None,
        "cipher": None,
        "chain_valid": chain_valid,
        "issuer": _name(certificate.issuer),
        "subject": _name(certificate.subject),
        "not_before": not_before,
        "not_after": not_after,
        "days_to_expiry": days,
        "sans": sans[:MAX_SANS],
    }, truncated


def _tls_error(exc: BaseException) -> ToolError:
    if isinstance(exc, TimeoutError):
        return ToolError("E_TIMEOUT", "TLS connection timed out")
    if isinstance(exc, (socket.gaierror, ConnectionRefusedError, ConnectionResetError)):
        return ToolError("E_CONNECT", "TLS connection failed")
    return ToolError("E_TLS", safe_message(exc, "TLS handshake failed"))


def _tls_handshake(target: str) -> tuple[dict[str, Any], bool]:
    parsed = urlsplit(target)
    port = parsed.port or 443
    verified = True
    try:
        context = ssl.create_default_context()
        with (
            socket.create_connection((parsed.hostname, port), timeout=TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname=parsed.hostname) as secure,
        ):
            der = secure.getpeercert(binary_form=True)
            info, truncated = _certificate_info(der, True)
            info["protocol"] = secure.version()
            info["cipher"] = secure.cipher()[0] if secure.cipher() else None
            return info, truncated
    except ssl.SSLCertVerificationError:
        verified = False
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise _tls_error(exc) from exc

    try:
        context = ssl._create_unverified_context()
        with (
            socket.create_connection((parsed.hostname, port), timeout=TIMEOUT_SECONDS) as raw,
            context.wrap_socket(raw, server_hostname=parsed.hostname) as secure,
        ):
            der = secure.getpeercert(binary_form=True)
            info, truncated = _certificate_info(der, verified)
            info["protocol"] = secure.version()
            info["cipher"] = secure.cipher()[0] if secure.cipher() else None
            return info, truncated
    except (OSError, ssl.SSLError, ValueError) as exc:
        raise _tls_error(exc) from exc


async def get_tls_info(target: str) -> dict[str, Any]:
    _validate_target(target)
    if urlsplit(target).scheme != "https":
        raise ProbeError("E_TLS", "TLS probe requires an https target")
    info, truncated = await asyncio.to_thread(_tls_handshake, target)
    parsed = urlsplit(target)
    result = TLSInfoResult(hostname=parsed.hostname or "", port=parsed.port or 443, **info)
    return envelope(
        f"{result.protocol} {result.cipher} on {target}",
        result.model_dump(mode="json"),
        truncated,
    )


def _cors_headers(headers: httpx.Headers) -> tuple[dict[str, str], bool]:
    selected = {}
    truncated = False
    for name, value in headers.items():
        if name.lower().startswith("access-control-") or name.lower() == "vary":
            selected[name.lower()], was_truncated = _cap(value)
            truncated = truncated or was_truncated
    return selected, truncated


def _vary_includes_origin(*headers: dict[str, str]) -> bool:
    values = ",".join(header.get("vary", "") for header in headers)
    return any(token.strip().lower() == "origin" for token in values.split(","))


async def get_cors_policy(target: str, client: httpx.AsyncClient | None = None) -> dict[str, Any]:
    http, owned = _client_or_default(client)
    try:
        simple, simple_redirects = await _fetch(http, target, headers={"Origin": TEST_ORIGIN})
        preflight, preflight_redirects = await _fetch(
            http,
            target,
            method="OPTIONS",
            headers={
                "Origin": TEST_ORIGIN,
                "Access-Control-Request-Method": "GET",
                "Access-Control-Request-Headers": "content-type",
            },
        )
        simple_headers, simple_truncated = _cors_headers(simple.headers)
        preflight_headers, preflight_truncated = _cors_headers(preflight.headers)
        allow_origin = simple_headers.get("access-control-allow-origin") or preflight_headers.get(
            "access-control-allow-origin"
        )
        allow_credentials = (
            simple_headers.get("access-control-allow-credentials")
            or preflight_headers.get("access-control-allow-credentials", "")
        ).lower() == "true"
        reflected = allow_origin == TEST_ORIGIN
        wildcard = allow_origin == "*"
        result = CORSPolicyResult(
            origin_tested=TEST_ORIGIN,
            simple=CORSExchange(
                status=simple.status_code,
                headers=simple_headers,
                redirects=simple_redirects,
            ),
            preflight=CORSExchange(
                status=preflight.status_code,
                headers=preflight_headers,
                redirects=preflight_redirects,
            ),
            allow_origin=allow_origin,
            allow_credentials=allow_credentials,
            origin_reflected=reflected,
            wildcard_origin=wildcard,
            vary_includes_origin=_vary_includes_origin(simple_headers, preflight_headers),
        )
        return envelope(
            (
                f"CORS allow-origin={allow_origin or 'absent'} "
                f"credentials={str(allow_credentials).lower()}"
            ),
            result.model_dump(mode="json", by_alias=True),
            simple_truncated or preflight_truncated,
        )
    finally:
        if owned:
            await http.aclose()
