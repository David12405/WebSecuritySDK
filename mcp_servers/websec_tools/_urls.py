"""Shared Layer 6 origin, same-origin comparison, and URL path normalization helpers."""

from __future__ import annotations

from urllib.parse import urlsplit


def origin_identity(url: str) -> tuple[str, str, int] | None:
    """Return canonical `(scheme, hostname, port)` for an HTTP(S) URL, or `None`."""
    try:
        parsed = urlsplit(url)
        port = parsed.port
    except ValueError:
        return None
    scheme = parsed.scheme.lower()
    hostname = parsed.hostname
    if scheme not in {"http", "https"} or hostname is None:
        return None
    effective_port = port if port is not None else (443 if scheme == "https" else 80)
    return scheme, hostname.rstrip(".").lower(), effective_port


def same_origin(left: str, right: str) -> bool:
    """Return True when two valid HTTP(S) URLs share scheme, host, and effective port."""
    left_origin = origin_identity(left)
    return left_origin is not None and left_origin == origin_identity(right)


def normalize_path(path: str) -> str:
    """Normalize a URL path by collapsing duplicate slashes and `.` segments."""
    if not path:
        return "/"
    parts = [part for part in path.split("/") if part not in {"", "."}]
    normalized = "/" + "/".join(parts)
    if path.endswith("/") and normalized != "/":
        normalized += "/"
    return normalized or "/"

