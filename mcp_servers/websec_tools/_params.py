"""Shared Layer 6 HTTP query and request-body parameter name extraction helpers."""

from __future__ import annotations

import json
import re
from typing import Any
from urllib.parse import parse_qsl, urlsplit

MAX_JSON_DEPTH = 8
MAX_VALUE_LENGTH = 2048
MAX_JSON_ARRAY_ITEMS = 10

_MULTIPART_NAME_RE = re.compile(
    r'content-disposition\s*:[^\r\n]*\bname\s*=\s*"([^"\r\n]+)"',
    re.IGNORECASE,
)


def json_field_names(
    value: Any,
    prefix: str = "",
    depth: int = 0,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_length: int = MAX_VALUE_LENGTH,
) -> list[str]:
    """Recursively collect JSON object field names up to a bounded depth."""
    if depth >= max_depth:
        return []
    names: list[str] = []
    if isinstance(value, dict):
        for key, child in value.items():
            name = f"{prefix}.{key}" if prefix else str(key)
            names.append(name[:max_length])
            names.extend(
                json_field_names(
                    child,
                    name,
                    depth + 1,
                    max_depth=max_depth,
                    max_length=max_length,
                )
            )
    elif isinstance(value, list):
        for child in value[:MAX_JSON_ARRAY_ITEMS]:
            names.extend(
                json_field_names(
                    child,
                    prefix,
                    depth + 1,
                    max_depth=max_depth,
                    max_length=max_length,
                )
            )
    return names


def body_parameter_names(
    body: str | bytes | None,
    content_type: str | None,
    *,
    max_depth: int = MAX_JSON_DEPTH,
    max_length: int = MAX_VALUE_LENGTH,
) -> list[str]:
    """Extract parameter/field names from JSON, URL-encoded, or multipart bodies."""
    if not body or not content_type:
        return []
    text = body.decode("utf-8", errors="replace") if isinstance(body, bytes) else str(body)
    if not text:
        return []
    normalized = content_type.split(";", 1)[0].strip().casefold()
    if (
        normalized in {"application/json", "text/json"}
        or normalized.endswith("+json")
        or "json" in normalized
    ):
        try:
            parsed = json.loads(text)
        except (TypeError, ValueError):
            return []
        return sorted(
            {
                name
                for name in json_field_names(parsed, max_depth=max_depth, max_length=max_length)
                if name
            }
        )
    if "x-www-form-urlencoded" in normalized:
        return sorted(
            {
                key[:max_length]
                for key, _value in parse_qsl(text, keep_blank_values=True)
                if key
            }
        )
    if "multipart/form-data" in normalized:
        return sorted(
            {
                name.strip()[:max_length]
                for name in _MULTIPART_NAME_RE.findall(text)
                if name.strip()
            }
        )
    return []


def query_parameter_names(url: str, *, max_length: int = MAX_VALUE_LENGTH) -> list[str]:
    """Extract sorted, percent-decoded query parameter names from a URL."""
    query = urlsplit(url).query
    if not query:
        return []
    return sorted(
        {
            name[:max_length]
            for name, _value in parse_qsl(query, keep_blank_values=True)
            if name
        }
    )
