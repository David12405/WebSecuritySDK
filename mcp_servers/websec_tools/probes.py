"""The actual network probes, with no MCP in them.

Every probe is passive and read-only: one ordinary HTTP request, or one TLS
handshake. No payloads, no fuzzing, no authentication, no writes. A probe
that needed to be more active would be a separate contract discussion.

Two halves, deliberately separated:

    analyse_*   pure. Given headers or a certificate, what is wrong with it?
    probe_*     one network call, then `analyse_*`, then the envelope.

The analysis is where the security knowledge lives, and it is the half worth
testing - so it takes plain dicts and never touches a socket. The tests run
with no network at all.

Every probe returns the contract envelope:

    {"summary": "one line", "data": {...}, "truncated": false}

and raises `ProbeError` with a stable `E_*` code on failure. A non-2xx HTTP
status is **not** a failure - it is data, in `data["status"]`.
"""

from __future__ import annotations

import socket
import ssl
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any
from urllib.parse import urlsplit

import httpx
from cryptography import x509
from cryptography.hazmat.primitives import hashes

# --------------------------------------------------------------------------
# Declared size caps (the contract requires a server to declare them)
# --------------------------------------------------------------------------

MAX_HEADERS = 60
MAX_COOKIES = 40
MAX_VALUE_CHARS = 2048
MAX_SANS = 20
MAX_REDIRECTS = 5

DEFAULT_TIMEOUT_S = 10.0

#: The headers a check asks about. Order matters: it is the order they are
#: reported in, and a report that leads with a legacy header reads badly.
SECURITY_HEADERS = (
    "strict-transport-security",
    "content-security-policy",
    "x-frame-options",
    "x-content-type-options",
    "referrer-policy",
    "permissions-policy",
    "cross-origin-opener-policy",
    "cross-origin-resource-policy",
)

#: Present these say something about the stack behind the site. Not a
#: vulnerability on their own, which is why they are reported separately.
DISCLOSURE_HEADERS = (
    "server",
    "x-powered-by",
    "x-aspnet-version",
    "x-aspnetmvc-version",
    "x-generator",
    "via",
)

#: An origin no target should ever be configured to trust. If it comes back
#: in Access-Control-Allow-Origin, the target reflects whatever it is sent.
PROBE_ORIGIN = "https://websecuritycheck-probe.invalid"


class ProbeError(Exception):
    """A failure to complete the probe. Carries a stable code from the contract."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(f"{code}: {message}")
        self.code = code
        self.message = message


@dataclass(frozen=True)
class Envelope:
    summary: str
    data: dict[str, Any]
    truncated: bool = False

    def as_dict(self) -> dict[str, Any]:
        return {"summary": self.summary, "data": self.data, "truncated": self.truncated}


# --------------------------------------------------------------------------
# Pure analysis
# --------------------------------------------------------------------------


def analyse_headers(headers: dict[str, str]) -> dict[str, Any]:
    """Which security headers are present, which are missing, what leaks."""
    lower = {name.lower(): value for name, value in headers.items()}
    present = {name: lower[name] for name in SECURITY_HEADERS if name in lower}
    return {
        "security_headers_present": present,
        "security_headers_missing": [name for name in SECURITY_HEADERS if name not in lower],
        "information_disclosure": {
            name: lower[name] for name in DISCLOSURE_HEADERS if name in lower
        },
    }


def parse_set_cookie(raw: str) -> dict[str, Any]:
    """One `Set-Cookie` header line, as attributes.

    **The value is never returned, only its length.** A cookie value is a
    live session credential; it has no place in a finding, a log or a store,
    and a probe that returns one has handed the model something it can quote
    into a report by accident.
    """
    first, _, rest = raw.partition(";")
    name, _, value = first.partition("=")
    cookie: dict[str, Any] = {
        "name": name.strip(),
        "value_length": len(value.strip()),
        "secure": False,
        "httponly": False,
        "samesite": None,
        "domain": None,
        "path": None,
        "expires": None,
        "max_age": None,
    }
    for part in rest.split(";"):
        key, _, val = part.strip().partition("=")
        key = key.lower()
        val = val.strip()[:MAX_VALUE_CHARS]
        if key == "secure":
            cookie["secure"] = True
        elif key == "httponly":
            cookie["httponly"] = True
        elif key in {"samesite", "domain", "path", "expires"}:
            cookie[key] = val
        elif key == "max-age":
            cookie["max_age"] = val
    return cookie


def analyse_cookies(cookies: list[dict[str, Any]], *, https: bool) -> dict[str, Any]:
    """Which cookies have weak flags, and why each one is weak."""
    weak: dict[str, list[str]] = {}
    for cookie in cookies:
        reasons = []
        if https and not cookie["secure"]:
            reasons.append("no Secure flag on an https response")
        if not cookie["httponly"]:
            reasons.append("no HttpOnly flag, so script can read it")
        if not cookie["samesite"]:
            reasons.append("no SameSite attribute")
        elif cookie["samesite"].lower() == "none" and not cookie["secure"]:
            reasons.append("SameSite=None without Secure, which browsers reject")
        if reasons:
            weak[cookie["name"]] = reasons
    return {"cookies": cookies, "weak_cookies": weak}


def analyse_certificate(der: bytes, *, now: datetime | None = None) -> dict[str, Any]:
    """Issuer, subject, validity window and SANs, from the DER bytes."""
    now = now or datetime.now(UTC)
    cert = x509.load_der_x509_certificate(der)
    not_before, not_after = cert.not_valid_before_utc, cert.not_valid_after_utc
    try:
        san = cert.extensions.get_extension_for_class(x509.SubjectAlternativeName)
        names = [str(name.value) for name in san.value]
    except x509.ExtensionNotFound:
        names = []
    return {
        "subject": cert.subject.rfc4514_string()[:MAX_VALUE_CHARS],
        "issuer": cert.issuer.rfc4514_string()[:MAX_VALUE_CHARS],
        "not_before": not_before.isoformat(),
        "not_after": not_after.isoformat(),
        "expires_in_days": (not_after - now).days,
        "expired": not_after < now,
        "not_yet_valid": not_before > now,
        "sans": names[:MAX_SANS],
        "san_count": len(names),
        "fingerprint_sha256": cert.fingerprint(hashes.SHA256()).hex(),
    }


def analyse_cors(simple: dict[str, str], preflight: dict[str, str]) -> dict[str, Any]:
    """What the target is willing to share cross-origin, and with whom."""
    merged = {k.lower(): v for k, v in simple.items()}
    allow_origin = merged.get("access-control-allow-origin")
    allow_credentials = merged.get("access-control-allow-credentials", "").lower() == "true"
    vary = merged.get("vary", "").lower()
    pre = {k.lower(): v for k, v in preflight.items()}
    return {
        "allow_origin": allow_origin,
        "allow_credentials": allow_credentials,
        "wildcard": allow_origin == "*",
        "reflects_arbitrary_origin": allow_origin == PROBE_ORIGIN,
        "vary_includes_origin": "origin" in vary,
        "preflight_allow_methods": pre.get("access-control-allow-methods"),
        "preflight_allow_headers": pre.get("access-control-allow-headers"),
        "preflight_max_age": pre.get("access-control-max-age"),
        # The combination browsers refuse, and the one that turns a readable
        # response into a readable *authenticated* response.
        "credentialed_wildcard": allow_origin == "*" and allow_credentials,
    }


# --------------------------------------------------------------------------
# Network
# --------------------------------------------------------------------------


def _require_url(target: str, *, https_only: bool = False) -> tuple[str, int]:
    parts = urlsplit(target.strip())
    if parts.scheme not in {"http", "https"}:
        raise ProbeError("E_INVALID_TARGET", f"{target!r} is not an http or https URL")
    if https_only and parts.scheme != "https":
        raise ProbeError("E_INVALID_TARGET", "a TLS probe needs an https URL")
    try:
        hostname, port = parts.hostname, parts.port
    except ValueError as exc:
        raise ProbeError("E_INVALID_TARGET", f"{target!r} has an invalid port") from exc
    if not hostname:
        raise ProbeError("E_INVALID_TARGET", f"{target!r} has no host")
    return hostname, port or (443 if parts.scheme == "https" else 80)


def _fetch(
    target: str,
    *,
    method: str = "GET",
    headers: dict[str, str] | None = None,
    timeout: float = DEFAULT_TIMEOUT_S,
) -> httpx.Response:
    """One ordinary request. Every failure becomes a contract error code."""
    _require_url(target)
    try:
        with httpx.Client(
            follow_redirects=True,
            max_redirects=MAX_REDIRECTS,
            timeout=timeout,
            headers={"user-agent": "WebSecurityCheck/0.1 (passive probe)"},
        ) as client:
            return client.request(method, target, headers=headers or {})
    except httpx.TooManyRedirects as exc:
        raise ProbeError("E_REDIRECT_LOOP", f"more than {MAX_REDIRECTS} redirects") from exc
    except httpx.TimeoutException as exc:
        raise ProbeError("E_TIMEOUT", f"timed out after {timeout}s") from exc
    except httpx.ConnectError as exc:
        raise ProbeError("E_CONNECT", str(exc) or "could not connect") from exc
    except httpx.HTTPError as exc:
        raise ProbeError("E_HTTP", str(exc) or exc.__class__.__name__) from exc


def probe_response_headers(target: str, timeout: float = DEFAULT_TIMEOUT_S) -> Envelope:
    response = _fetch(target, timeout=timeout)
    headers = dict(response.headers)
    truncated = len(headers) > MAX_HEADERS
    if truncated:
        headers = dict(list(headers.items())[:MAX_HEADERS])
    headers = {k: v[:MAX_VALUE_CHARS] for k, v in headers.items()}

    analysis = analyse_headers(headers)
    chain = [str(r.url) for r in response.history][:MAX_REDIRECTS]
    missing = len(analysis["security_headers_missing"])
    return Envelope(
        summary=(
            f"{response.status_code} {response.http_version} on {response.url} - "
            f"{len(headers)} headers, {missing} security headers missing"
        ),
        data={
            "final_url": str(response.url),
            "status": response.status_code,
            "http_version": response.http_version,
            "redirect_chain": chain,
            "headers": headers,
            **analysis,
        },
        truncated=truncated,
    )


def probe_cookies(target: str, timeout: float = DEFAULT_TIMEOUT_S) -> Envelope:
    response = _fetch(target, timeout=timeout)
    raw = response.headers.get_list("set-cookie")
    truncated = len(raw) > MAX_COOKIES
    cookies = [parse_set_cookie(line) for line in raw[:MAX_COOKIES]]
    analysis = analyse_cookies(cookies, https=str(response.url).startswith("https://"))
    weak = len(analysis["weak_cookies"])
    return Envelope(
        summary=f"{len(cookies)} cookie(s) set; {weak} with weak flags",
        data={"final_url": str(response.url), **analysis},
        truncated=truncated,
    )


def probe_tls(target: str, timeout: float = DEFAULT_TIMEOUT_S) -> Envelope:
    """One TLS handshake.

    The verified handshake decides whether the chain is trusted. If it
    fails, a second unverified handshake still reports *which* certificate
    was presented - a report that says only "verification failed" sends the
    reader to look at a certificate it cannot see.
    """
    host, port = _require_url(target, https_only=True)
    verify_error: str | None = None
    try:
        der, protocol, cipher = _handshake(host, port, timeout, verify=True)
    except ssl.SSLCertVerificationError as exc:
        verify_error = exc.verify_message or str(exc)
        try:
            der, protocol, cipher = _handshake(host, port, timeout, verify=False)
        except OSError as inner:
            raise ProbeError("E_TLS", str(inner)) from inner
    except ssl.SSLError as exc:
        raise ProbeError("E_TLS", str(exc)) from exc
    except TimeoutError as exc:
        raise ProbeError("E_TIMEOUT", f"handshake timed out after {timeout}s") from exc
    except OSError as exc:
        raise ProbeError("E_CONNECT", str(exc)) from exc

    cert = analyse_certificate(der)
    valid = verify_error is None
    status = "certificate valid" if valid else f"chain NOT trusted ({verify_error})"
    return Envelope(
        summary=(f"{protocol} ({cipher}); {status}, {cert['expires_in_days']} days left"),
        data={
            "host": host,
            "port": port,
            "protocol": protocol,
            "cipher": cipher,
            "chain_trusted": valid,
            "chain_error": verify_error,
            **cert,
        },
        truncated=cert["san_count"] > MAX_SANS,
    )


def _handshake(host: str, port: int, timeout: float, *, verify: bool) -> tuple[bytes, str, str]:
    context = ssl.create_default_context()
    if not verify:
        context.check_hostname = False
        context.verify_mode = ssl.CERT_NONE
    with (
        socket.create_connection((host, port), timeout=timeout) as raw,
        context.wrap_socket(raw, server_hostname=host) as tls,
    ):
        der = tls.getpeercert(binary_form=True) or b""
        cipher = (tls.cipher() or ("?",))[0]
        return der, tls.version() or "?", cipher


def probe_cors(
    target: str, origin: str = PROBE_ORIGIN, timeout: float = DEFAULT_TIMEOUT_S
) -> Envelope:
    """A simple request and a preflight, both from an origin the target does not know.

    `origin` is the origin the probe *claims to be*, sent as a header. No
    request is made to it, which is why it is not scope-checked.
    """
    simple = _fetch(target, headers={"origin": origin}, timeout=timeout)
    preflight = _fetch(
        target,
        method="OPTIONS",
        headers={
            "origin": origin,
            "access-control-request-method": "GET",
            "access-control-request-headers": "authorization",
        },
        timeout=timeout,
    )
    analysis = analyse_cors(dict(simple.headers), dict(preflight.headers))
    if analysis["allow_origin"] is None:
        summary = "no CORS headers returned (cross-origin reads blocked by default)"
    elif analysis["credentialed_wildcard"]:
        summary = "allow-origin '*' with credentials - browsers refuse this combination"
    elif analysis["reflects_arbitrary_origin"]:
        summary = f"reflects any origin ({origin} was echoed back)"
    else:
        summary = f"allow-origin {analysis['allow_origin']!r}"
    credentials = "with" if analysis["allow_credentials"] else "without"
    return Envelope(
        summary=f"{summary}, {credentials} credentials",
        data={"probe_origin": origin, "simple_status": simple.status_code, **analysis},
    )
