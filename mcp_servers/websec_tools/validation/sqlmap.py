"""Constrained, non-destructive SQLMap detection tool for Layer 6.

Strictly enforces LOW risk profile (--risk=1, --batch) and blocks all data
exfiltration, enumeration, OS shell, file R/W, and WAF tamper flags.
"""

from __future__ import annotations

import asyncio
import contextlib
import hashlib
import json
import os
import re
import tempfile
from collections.abc import Awaitable, Callable, Sequence
from pathlib import Path
from typing import Any
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit

from pydantic import BaseModel, ConfigDict, Field

from ..errors import ToolError, envelope
from ..probes import _validate_target

DEFAULT_SQLMAP_PATH = "sqlmap"
DEFAULT_TIMEOUT_SECONDS = 120.0
MIN_TIMEOUT_SECONDS = 5.0
MAX_TIMEOUT_SECONDS = 300.0
DEFAULT_PER_REQUEST_TIMEOUT = 10
MIN_PER_REQUEST_TIMEOUT = 2
MAX_PER_REQUEST_TIMEOUT = 30
MAX_OUTPUT_BYTES = 2 * 1024 * 1024
MAX_FINDINGS = 20
MAX_PARAM_LENGTH = 256

ALLOWED_METHODS = frozenset({"GET", "POST", "PUT", "PATCH", "DELETE"})
ALLOWED_LOCATIONS = frozenset({"QUERY", "FORM", "JSON_BODY", "COOKIE", "HEADER"})
TECHNIQUE_NAME_TO_CODE = {
    "ERROR": "E",
    "BOOLEAN": "B",
    "UNION": "U",
    "TIME": "T",
}
CODE_TO_TECHNIQUE_NAME = {value: key for key, value in TECHNIQUE_NAME_TO_CODE.items()}
ALLOWED_TECHNIQUE_CODES = frozenset(TECHNIQUE_NAME_TO_CODE.values())
BUILTIN_LEVEL3_HEADERS = frozenset({"user-agent", "referer"})

FORBIDDEN_FLAGS = frozenset(
    {
        "--dump",
        "--dump-all",
        "--dbs",
        "--tables",
        "--columns",
        "--schema",
        "--count",
        "--search",
        "--passwords",
        "--users",
        "--roles",
        "--privileges",
        "--os-shell",
        "--os-pwn",
        "--os-cmd",
        "--os-bof",
        "--os-smbrelay",
        "--priv-esc",
        "--file-read",
        "--file-write",
        "--file-dest",
        "--sql-shell",
        "--sql-query",
        "--sql-file",
        "--tamper",
        "--crawl",
        "--forms",
        "--wizard",
        "--update",
        "--eval",
        "--udf-inject",
        "--shared-lib",
        "--reg-read",
        "--reg-add",
        "--reg-del",
    }
)
_FORBIDDEN_FLAG_PREFIXES = (
    "--dump",
    "--os-",
    "--file-",
    "--sql-",
    "--tamper",
    "--eval",
    "--reg-",
)
_PARAM_SAFE_RE = re.compile(r"^[A-Za-z0-9_.\[\]-]{1,256}$")
_DBMS_HINT_RE = re.compile(r"^[A-Za-z0-9 _.-]{1,40}$")
_SENSITIVE_HEADER_RE = re.compile(
    r"(?im)^((?:proxy-)?authorization|cookie|set-cookie|x-api-key|x-auth-token|x-csrf-token)"
    r"(\s*:\s*)(.+)$"
)
_BEARER_RE = re.compile(r"(?i)\b(Bearer|Basic)\s+[A-Za-z0-9._~+/=-]{6,}")
_SENSITIVE_KV_RE = re.compile(
    r"(?i)(\b(?:password|passwd|secret|token|api_key|apikey|access_token|refresh_token|"
    r"sessionid|session_id)\b\s*[:=]\s*)([\"']?)([^&\s,;\"'\r\n]+)\2"
)
_PARAMETER_HEADER_RE = re.compile(r"^Parameter:\s*(.+?)\s*(?:\(([^)]+)\))?\s*$")
_DBMS_LINE_RE = re.compile(r"(?im)^back-end DBMS:\s*(.+)$")

Runner = Callable[[list[str], float], Awaitable[tuple[int, bytes, bytes]]]


class SQLMapFinding(BaseModel):
    """Structured SQLMap detection record for one confirmed SQLi vector."""

    model_config = ConfigDict(extra="forbid")

    parameter_name: str
    location_label: str | None = None
    technique: str
    sqlmap_type: str
    title: str
    redacted_payload_summary: str | None = None
    dbms_identified: str | None = None


class SQLMapExecutionData(BaseModel):
    """Machine-readable result returned by Layer 6 ``detect_sqli``."""

    model_config = ConfigDict(extra="forbid")

    tool: str = "sqlmap"
    target: str
    method: str
    parameter_name: str
    parameter_location: str
    requested_techniques: list[str]
    findings: list[SQLMapFinding] = Field(default_factory=list)
    dbms_identified: str | None = None
    heuristic_signal_detected: bool = False
    target_stable: bool = True
    auth_failure_detected: bool = False
    rate_limited: bool = False
    waf_or_filter_detected: bool = False
    warnings: list[str] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)


def redact_sensitive_text(text: str) -> str:
    """Redact credentials, cookies, tokens, and secrets from text before persistence."""

    redacted = _SENSITIVE_HEADER_RE.sub(r"\1\2[REDACTED]", text)
    redacted = _BEARER_RE.sub(r"\1 [REDACTED]", redacted)
    redacted = _SENSITIVE_KV_RE.sub(r"\1\2[REDACTED]\2", redacted)
    return redacted


def _resolve_executable(executable: str | None) -> str:
    candidate = executable if executable is not None else os.getenv("WEBSEC_SQLMAP_PATH")
    if candidate is None or candidate == "":
        return DEFAULT_SQLMAP_PATH
    if (
        not isinstance(candidate, str)
        or not candidate.strip()
        or "\x00" in candidate
        or any(ord(ch) < 32 for ch in candidate)
        or candidate.startswith("-")
    ):
        raise ToolError("E_TOOL_UNAVAILABLE", "SQLMap executable configuration is invalid")
    return os.path.expanduser(candidate) if candidate.startswith("~") else candidate


def _validate_parameter_name(parameter_name: str) -> str:
    if (
        not isinstance(parameter_name, str)
        or not parameter_name
        or len(parameter_name) > MAX_PARAM_LENGTH
        or parameter_name.startswith("-")
        or not _PARAM_SAFE_RE.fullmatch(parameter_name)
    ):
        raise ToolError("E_INVALID_ARGUMENT", "parameter_name contains unsupported characters")
    return parameter_name


def _normalize_techniques(techniques: Sequence[str] | None) -> tuple[list[str], str]:
    items = list(techniques) if techniques is not None else ["ERROR", "BOOLEAN", "UNION"]
    if not items:
        raise ToolError("E_INVALID_ARGUMENT", "techniques must contain at least one technique")
    normalized_names: list[str] = []
    codes: list[str] = []
    for item in items:
        if not isinstance(item, str):
            raise ToolError("E_INVALID_ARGUMENT", "technique entries must be strings")
        token = item.strip().upper()
        if token in {"S", "STACKED", "Q", "INLINE"}:
            raise ToolError("E_INVALID_ARGUMENT", f"technique {token!r} is forbidden in v0.1")
        code = TECHNIQUE_NAME_TO_CODE.get(token)
        if code is None and token in ALLOWED_TECHNIQUE_CODES:
            code = token
            token = CODE_TO_TECHNIQUE_NAME[code]
        if code is None:
            raise ToolError("E_INVALID_ARGUMENT", f"unsupported SQLi technique {item!r}")
        if code not in codes:
            codes.append(code)
            normalized_names.append(token)
    return normalized_names, "".join(codes)


def _validate_dbms_hint(dbms_hint: str | None) -> str | None:
    if dbms_hint is None or dbms_hint == "":
        return None
    cleaned = dbms_hint.strip()
    if (
        not cleaned
        or cleaned.startswith("-")
        or not _DBMS_HINT_RE.fullmatch(cleaned)
    ):
        raise ToolError("E_INVALID_ARGUMENT", "dbms_hint is invalid")
    return cleaned


def _validate_header_map(headers: dict[str, str] | None) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    if not headers:
        return cleaned
    for name, value in headers.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ToolError("E_INVALID_ARGUMENT", "headers must map strings to strings")
        if any(ch in name for ch in "\r\n\x00:") or not name.strip():
            raise ToolError("E_INVALID_ARGUMENT", "header name is invalid")
        if any(ch in value for ch in "\r\n\x00"):
            raise ToolError("E_INVALID_ARGUMENT", "header value contains forbidden characters")
        cleaned[name.strip()] = value
    return cleaned


def _validate_cookie_map(cookies: dict[str, str] | None) -> dict[str, str]:
    cleaned: dict[str, str] = {}
    if not cookies:
        return cleaned
    for name, value in cookies.items():
        if not isinstance(name, str) or not isinstance(value, str):
            raise ToolError("E_INVALID_ARGUMENT", "cookies must map strings to strings")
        if any(ch in name for ch in "\r\n\x00=;") or not name.strip():
            raise ToolError("E_INVALID_ARGUMENT", "cookie name is invalid")
        if any(ch in value for ch in "\r\n\x00;"):
            raise ToolError("E_INVALID_ARGUMENT", "cookie value contains forbidden characters")
        cleaned[name.strip()] = value
    return cleaned


def _header_get_ci(headers: dict[str, str], target_name: str) -> str | None:
    wanted = target_name.casefold()
    for name, value in headers.items():
        if name.casefold() == wanted:
            return value
    return None


def _header_set_ci(headers: dict[str, str], name: str, value: str) -> None:
    wanted = name.casefold()
    for existing in list(headers):
        if existing.casefold() == wanted:
            del headers[existing]
    headers[name] = value


def _inject_json_marker(
    payload: Any, path_parts: list[str], fallback_value: str
) -> tuple[Any, bool]:
    if not path_parts:
        return payload, False
    key = path_parts[0]
    if isinstance(payload, dict):
        updated = dict(payload)
        if len(path_parts) == 1:
            current = updated.get(key, fallback_value)
            marker_base = "" if current is None else str(current)
            if "*" not in marker_base:
                updated[key] = f"{marker_base}*" if marker_base else "*"
            return updated, True
        if key in updated and isinstance(updated[key], dict):
            child, ok = _inject_json_marker(updated[key], path_parts[1:], fallback_value)
            if ok:
                updated[key] = child
                return updated, True
        return updated, False
    return payload, False


def _ensure_json_body(
    body: str | None,
    parameter_name: str,
    sample_value: str,
) -> tuple[str, bool]:
    """Ensure JSON body includes the target parameter and mark nested paths with `*`."""

    parsed: Any
    if body and body.strip():
        try:
            parsed = json.loads(body)
        except json.JSONDecodeError as exc:
            raise ToolError(
                "E_INVALID_ARGUMENT", "JSON_BODY requires valid JSON body content"
            ) from exc
        if not isinstance(parsed, dict):
            raise ToolError("E_INVALID_ARGUMENT", "JSON_BODY root value must be a JSON object")
    else:
        parsed = {}

    uses_marker = "." in parameter_name
    if uses_marker:
        parts = [part for part in parameter_name.split(".") if part]
        if not parts:
            raise ToolError("E_INVALID_ARGUMENT", "nested JSON parameter_name is invalid")
        cursor: dict[str, Any] = parsed
        for part in parts[:-1]:
            if part not in cursor or not isinstance(cursor[part], dict):
                cursor[part] = {}
            cursor = cursor[part]
        parsed, marked = _inject_json_marker(parsed, parts, sample_value)
        return json.dumps(parsed, separators=(",", ":")), marked

    if parameter_name not in parsed:
        parsed[parameter_name] = sample_value
    return json.dumps(parsed, separators=(",", ":")), False


def _ensure_query_param(url: str, parameter_name: str, sample_value: str) -> str:
    split = urlsplit(url)
    pairs = parse_qsl(split.query, keep_blank_values=True)
    if not any(key == parameter_name for key, _ in pairs):
        pairs.append((parameter_name, sample_value))
    new_query = urlencode(pairs)
    return urlunsplit((split.scheme, split.netloc, split.path or "/", new_query, ""))


def _ensure_form_body(body: str | None, parameter_name: str, sample_value: str) -> str:
    pairs = parse_qsl(body or "", keep_blank_values=True)
    if not any(key == parameter_name for key, _ in pairs):
        pairs.append((parameter_name, sample_value))
    return urlencode(pairs)


def _format_cookie_header(existing_cookie: str | None, cookies: dict[str, str]) -> str:
    merged: dict[str, str] = {}
    if existing_cookie:
        for chunk in existing_cookie.split(";"):
            if "=" in chunk:
                key, value = chunk.split("=", 1)
                merged[key.strip()] = value.strip()
    merged.update(cookies)
    return "; ".join(f"{key}={value}" for key, value in merged.items())


def _split_raw_request(raw_request: str) -> tuple[str, str, dict[str, str], str]:
    normalized = raw_request.replace("\r\n", "\n")
    head, _, body = normalized.partition("\n\n")
    lines = head.split("\n")
    if not lines or " " not in lines[0]:
        raise ToolError("E_INVALID_ARGUMENT", "raw_request is not a valid HTTP/1.1 request")
    parts = lines[0].split(" ")
    if len(parts) < 2:
        raise ToolError("E_INVALID_ARGUMENT", "raw_request request-line is invalid")
    req_method = parts[0].strip().upper()
    req_target = parts[1].strip()
    headers: dict[str, str] = {}
    for line in lines[1:]:
        if ":" not in line:
            continue
        key, value = line.split(":", 1)
        if any(ch in key for ch in "\r\n\x00") or any(ch in value for ch in "\r\n\x00"):
            raise ToolError("E_INVALID_ARGUMENT", "raw_request contains invalid header characters")
        headers[key.strip()] = value.strip()
    return req_method, req_target, headers, body


def _build_request_and_profile(
    *,
    target: str,
    method: str,
    parameter_name: str,
    parameter_location: str,
    headers: dict[str, str],
    cookies: dict[str, str],
    body: str | None,
    sample_value: str,
    raw_request: str | None,
) -> tuple[str, int, str | None]:
    """Build RFC 7230 HTTP request text, safe SQLMap --level, and optional `-p` parameter."""

    split = urlsplit(target)
    merged_headers = dict(headers)
    merged_cookies = dict(cookies)
    req_path = f"{split.path or '/'}{f'?{split.query}' if split.query else ''}"
    req_body = body or ""

    if raw_request:
        _raw_method, raw_target, raw_headers, raw_body = _split_raw_request(raw_request)
        if not req_body and raw_body:
            req_body = raw_body
        if raw_target and split.query == "" and "?" in raw_target:
            req_path = raw_target
        for h_name, h_val in raw_headers.items():
            if _header_get_ci(merged_headers, h_name) is None:
                merged_headers[h_name] = h_val

    if _header_get_ci(merged_headers, "Host") is None:
        _header_set_ci(merged_headers, "Host", split.netloc)

    level = 1
    p_flag: str | None = parameter_name

    if parameter_location == "QUERY":
        updated_url = _ensure_query_param(target, parameter_name, sample_value)
        u_split = urlsplit(updated_url)
        req_path = f"{u_split.path or '/'}{f'?{u_split.query}' if u_split.query else ''}"
    elif parameter_location == "FORM":
        req_body = _ensure_form_body(req_body, parameter_name, sample_value)
        if _header_get_ci(merged_headers, "Content-Type") is None:
            _header_set_ci(merged_headers, "Content-Type", "application/x-www-form-urlencoded")
    elif parameter_location == "JSON_BODY":
        req_body, used_marker = _ensure_json_body(req_body, parameter_name, sample_value)
        if _header_get_ci(merged_headers, "Content-Type") is None:
            _header_set_ci(merged_headers, "Content-Type", "application/json")
        if used_marker:
            p_flag = None
    elif parameter_location == "COOKIE":
        merged_cookies.setdefault(parameter_name, sample_value)
        level = 2
    elif parameter_location == "HEADER":
        existing_value = _header_get_ci(merged_headers, parameter_name) or sample_value
        if parameter_name.casefold() in BUILTIN_LEVEL3_HEADERS:
            _header_set_ci(merged_headers, parameter_name, existing_value)
            level = 3
        else:
            marked = existing_value if "*" in existing_value else f"{existing_value}*"
            _header_set_ci(merged_headers, parameter_name, marked)
            level = 1
            p_flag = None

    if merged_cookies:
        existing_cookie_hdr = _header_get_ci(merged_headers, "Cookie")
        _header_set_ci(
            merged_headers,
            "Cookie",
            _format_cookie_header(existing_cookie_hdr, merged_cookies),
        )

    if req_body:
        _header_set_ci(merged_headers, "Content-Length", str(len(req_body.encode("utf-8"))))

    lines = [f"{method} {req_path} HTTP/1.1"]
    for h_name, h_val in merged_headers.items():
        lines.append(f"{h_name}: {h_val}")
    raw_http = "\r\n".join(lines) + "\r\n\r\n" + req_body
    return raw_http, level, p_flag


def _assert_safe_argv(argv: list[str]) -> None:
    """Enforce hard safety guardrails on the constructed SQLMap CLI arguments."""

    if "--batch" not in argv or "--risk=1" not in argv or "--flush-session" not in argv:
        raise ToolError(
            "E_INVALID_ARGUMENT",
            "SQLMap argv must enforce --batch, --risk=1, and --flush-session",
        )

    tech_args = [arg for arg in argv if arg.startswith("--technique=")]
    if len(tech_args) != 1:
        raise ToolError(
            "E_INVALID_ARGUMENT",
            "SQLMap argv must contain exactly one --technique flag",
        )
    tech_codes = tech_args[0].split("=", 1)[1]
    if not tech_codes or any(code not in ALLOWED_TECHNIQUE_CODES for code in tech_codes):
        raise ToolError("E_INVALID_ARGUMENT", "SQLMap argv contains forbidden SQLi techniques")

    for arg in argv:
        lowered = arg.casefold()
        has_forbidden_prefix = any(
            lowered.startswith(prefix) for prefix in _FORBIDDEN_FLAG_PREFIXES
        )
        if lowered in FORBIDDEN_FLAGS or has_forbidden_prefix:
            raise ToolError("E_INVALID_ARGUMENT", f"forbidden SQLMap flag {arg!r}")
        if lowered.startswith("--risk=") and lowered != "--risk=1":
            raise ToolError("E_INVALID_ARGUMENT", "only --risk=1 is permitted")
        if lowered.startswith("--level=") and lowered not in {
            "--level=1",
            "--level=2",
            "--level=3",
        }:
            raise ToolError("E_INVALID_ARGUMENT", "SQLMap level above 3 is forbidden")


def _classify_sqlmap_type(sqlmap_type: str) -> str | None:
    lowered = sqlmap_type.casefold()
    if "error" in lowered:
        return "ERROR"
    if "boolean" in lowered:
        return "BOOLEAN"
    if "union" in lowered:
        return "UNION"
    if "time-based" in lowered or "time" in lowered:
        return "TIME"
    return None


def _parse_finding_blocks(combined_text: str, default_param: str) -> list[SQLMapFinding]:
    findings: list[SQLMapFinding] = []
    seen_keys: set[tuple[str, str, str]] = set()
    dbms_match = _DBMS_LINE_RE.search(combined_text)
    detected_dbms = dbms_match.group(1).strip() if dbms_match else None

    current_param = default_param
    current_loc: str | None = None
    block: dict[str, str] = {}

    def _flush_block() -> None:
        if not block or "Type" not in block or "Title" not in block:
            return
        technique = _classify_sqlmap_type(block["Type"])
        if technique is None:
            return
        key = (current_param, technique, block["Title"])
        if key in seen_keys:
            return
        seen_keys.add(key)
        raw_payload = block.get("Payload")
        findings.append(
            SQLMapFinding(
                parameter_name=current_param,
                location_label=current_loc,
                technique=technique,
                sqlmap_type=block["Type"],
                title=block["Title"],
                redacted_payload_summary=(
                    redact_sensitive_text(raw_payload)[:512] if raw_payload else None
                ),
                dbms_identified=detected_dbms,
            )
        )

    for raw_line in combined_text.splitlines():
        stripped = raw_line.strip()
        if not stripped:
            _flush_block()
            block = {}
            continue
        param_match = _PARAMETER_HEADER_RE.match(stripped)
        if param_match:
            _flush_block()
            block = {}
            current_param = param_match.group(1).strip().strip("'\"")
            current_loc = param_match.group(2).strip() if param_match.group(2) else None
            continue
        if stripped.startswith(("Type:", "Title:", "Payload:")):
            field_name, _, field_value = stripped.partition(":")
            if field_name == "Type" and "Type" in block:
                _flush_block()
                block = {}
            block[field_name] = field_value.strip()

    _flush_block()
    return findings[:MAX_FINDINGS]


def parse_sqlmap_output(
    *,
    stdout_text: str,
    stderr_text: str,
    session_log_text: str,
    target: str,
    method: str,
    parameter_name: str,
    parameter_location: str,
    requested_techniques: list[str],
) -> SQLMapExecutionData:
    """Parse SQLMap stdout, stderr, and session logs into structured, redacted output."""

    combined = "\n".join(part for part in (stdout_text, session_log_text) if part)
    lowered_all = "\n".join(part for part in (combined, stderr_text) if part).casefold()

    findings = _parse_finding_blocks(combined, parameter_name)
    dbms_match = _DBMS_LINE_RE.search(combined)
    dbms_identified = dbms_match.group(1).strip() if dbms_match else None

    heuristic = bool(
        re.search(r"heuristic \(basic\) test shows that .* might be injectable", lowered_all)
        or "sql error" in lowered_all
    )
    target_stable = not (
        "target url content is not stable" in lowered_all
        or "target url is not stable" in lowered_all
        or "responses are not consistent" in lowered_all
    )
    waf_detected = bool(
        "waf/ips identified" in lowered_all
        or "protected by some kind of waf/ips" in lowered_all
        or "heuristics detected web application firewall" in lowered_all
        or "waf/ips protection" in lowered_all
    )
    rate_limited = bool(
        "http error codes detected during run:\n429" in lowered_all
        or re.search(
            r"\b429\s*\(too many requests\)|\bhttp\s+error\s+429\b|\brate[\s_-]*limit",
            lowered_all,
        )
    )
    auth_failure = bool(
        re.search(
            r"\b401\s*\(unauthorized\)|\bhttp\s+error\s+401\b|"
            r"session expired|authentication required",
            lowered_all,
        )
    )

    warnings: list[str] = []
    if not target_stable:
        warnings.append("SQLMap reported unstable target responses")
    if waf_detected:
        warnings.append("SQLMap detected WAF/IPS filtering signals")
    if rate_limited:
        warnings.append("SQLMap observed HTTP 429 / rate-limiting signals")
    if auth_failure:
        warnings.append("SQLMap observed HTTP 401 / authentication failure signals")

    redacted_raw = redact_sensitive_text(
        "\n".join(
            section
            for section in (
                f"[STDOUT]\n{stdout_text}" if stdout_text else "",
                f"[SESSION_LOG]\n{session_log_text}" if session_log_text else "",
                f"[STDERR]\n{stderr_text}" if stderr_text else "",
            )
            if section
        )
    )
    raw_bytes = redacted_raw.encode("utf-8", errors="replace")
    digest = hashlib.sha256(raw_bytes).hexdigest()
    manifest = {
        "artifact_ref": f"sqlmap-output-{digest[:16]}",
        "artifact_type": "TOOL_RAW_OUTPUT",
        "content": redacted_raw,
        "sha256_hash": digest,
        "size_bytes": len(raw_bytes),
        "media_type": "text/plain",
        "redaction_applied": True,
        "metadata": {
            "tool": "sqlmap",
            "target": target,
            "method": method,
            "parameter_name": parameter_name,
            "parameter_location": parameter_location,
        },
    }

    return SQLMapExecutionData(
        target=target,
        method=method,
        parameter_name=parameter_name,
        parameter_location=parameter_location,
        requested_techniques=requested_techniques,
        findings=findings,
        dbms_identified=dbms_identified,
        heuristic_signal_detected=heuristic,
        target_stable=target_stable,
        auth_failure_detected=auth_failure,
        rate_limited=rate_limited,
        waf_or_filter_detected=waf_detected,
        warnings=warnings,
        artifact_manifests=[manifest],
    )


async def _default_runner(argv: list[str], timeout: float) -> tuple[int, bytes, bytes]:
    try:
        process = await asyncio.create_subprocess_exec(
            *argv,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
        )
    except FileNotFoundError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "SQLMap executable is not available") from exc
    except OSError as exc:
        raise ToolError("E_TOOL_UNAVAILABLE", "SQLMap executable could not be started") from exc
    try:
        stdout, stderr = await asyncio.wait_for(process.communicate(), timeout=timeout)
    except TimeoutError as exc:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise ToolError("E_TIMEOUT", "SQLMap execution timed out") from exc
    except asyncio.CancelledError:
        with contextlib.suppress(ProcessLookupError):
            process.kill()
        await process.communicate()
        raise
    return process.returncode or 0, stdout, stderr


def _read_session_logs(output_dir: Path) -> str:
    chunks: list[str] = []
    total = 0
    for log_path in sorted(output_dir.rglob("log")):
        if not log_path.is_file():
            continue
        text = log_path.read_text(encoding="utf-8", errors="replace")
        remaining = MAX_OUTPUT_BYTES - total
        if remaining <= 0:
            break
        chunks.append(text[:remaining])
        total += len(chunks[-1])
    return "\n".join(chunks)


async def detect_sqli(
    target: str,
    parameter_name: str,
    parameter_location: str = "QUERY",
    method: str = "GET",
    techniques: list[str] | None = None,
    dbms_hint: str | None = None,
    timeout_seconds: float = DEFAULT_TIMEOUT_SECONDS,
    risk_profile: str = "LOW",
    headers: dict[str, str] | None = None,
    cookies: dict[str, str] | None = None,
    body: str | None = None,
    sample_value: str = "1",
    raw_request: str | None = None,
    *,
    runner: Runner | None = None,
    executable: str | None = None,
) -> dict[str, Any]:
    """Run constrained, non-destructive SQLMap detection on one candidate parameter."""

    _validate_target(target)
    normalized_method = method.strip().upper()
    if normalized_method not in ALLOWED_METHODS:
        raise ToolError("E_INVALID_ARGUMENT", f"HTTP method {method!r} is not allowed")

    normalized_location = parameter_location.strip().upper()
    if normalized_location not in ALLOWED_LOCATIONS:
        raise ToolError(
            "E_UNSUPPORTED_INPUT",
            f"parameter_location {parameter_location!r} is unsupported for SQLMap",
        )

    if risk_profile != "LOW":
        raise ToolError("E_INVALID_ARGUMENT", "Only risk_profile=LOW is permitted in v0.1")

    safe_param = _validate_parameter_name(parameter_name)
    requested_techniques, technique_codes = _normalize_techniques(techniques)
    safe_dbms = _validate_dbms_hint(dbms_hint)
    if (
        isinstance(timeout_seconds, bool)
        or not isinstance(timeout_seconds, (int, float))
        or not MIN_TIMEOUT_SECONDS <= float(timeout_seconds) <= MAX_TIMEOUT_SECONDS
    ):
        raise ToolError(
            "E_INVALID_ARGUMENT",
            f"timeout_seconds must be between {MIN_TIMEOUT_SECONDS} and {MAX_TIMEOUT_SECONDS}",
        )

    safe_headers = _validate_header_map(headers)
    safe_cookies = _validate_cookie_map(cookies)
    if any(ch in sample_value for ch in "\r\n\x00"):
        raise ToolError("E_INVALID_ARGUMENT", "sample_value contains forbidden characters")

    exe = _resolve_executable(executable)
    raw_http, level, p_flag = _build_request_and_profile(
        target=target,
        method=normalized_method,
        parameter_name=safe_param,
        parameter_location=normalized_location,
        headers=safe_headers,
        cookies=safe_cookies,
        body=body,
        sample_value=sample_value,
        raw_request=raw_request,
    )

    per_req_timeout = max(
        MIN_PER_REQUEST_TIMEOUT,
        min(
            MAX_PER_REQUEST_TIMEOUT,
            int(float(timeout_seconds) // 4) or DEFAULT_PER_REQUEST_TIMEOUT,
        ),
    )

    with tempfile.TemporaryDirectory(prefix="websec-sqlmap-") as tmp_dir:
        tmp_path = Path(tmp_dir)
        req_file = tmp_path / "request.http"
        out_dir = tmp_path / "out"
        out_dir.mkdir(parents=True, exist_ok=True)
        req_file.write_text(raw_http, encoding="utf-8")
        with contextlib.suppress(OSError):
            os.chmod(req_file, 0o600)

        argv = [
            exe,
            "-r",
            str(req_file),
            "--batch",
            "--risk=1",
            f"--level={level}",
            f"--technique={technique_codes}",
            f"--timeout={per_req_timeout}",
            "--retries=1",
            "--threads=1",
            "--flush-session",
            f"--output-dir={out_dir}",
        ]
        if urlsplit(target).scheme == "https":
            argv.append("--force-ssl")
        if p_flag is not None:
            argv.extend(["-p", p_flag])
        if safe_dbms is not None:
            argv.append(f"--dbms={safe_dbms}")

        _assert_safe_argv(argv)

        try:
            returncode, stdout_bytes, stderr_bytes = await (runner or _default_runner)(
                argv, float(timeout_seconds)
            )
        except ToolError:
            raise
        except TimeoutError as exc:
            raise ToolError("E_TIMEOUT", "SQLMap execution timed out") from exc
        except OSError as exc:
            raise ToolError("E_TOOL_UNAVAILABLE", "SQLMap executable could not be started") from exc
        except Exception as exc:
            raise ToolError("E_TOOL_FAILED", "SQLMap execution failed") from exc

        if len(stdout_bytes) > MAX_OUTPUT_BYTES or len(stderr_bytes) > MAX_OUTPUT_BYTES:
            raise ToolError("E_TOOL_FAILED", "SQLMap output exceeded the size limit")

        stdout_text = stdout_bytes.decode("utf-8", errors="replace")
        stderr_text = stderr_bytes.decode("utf-8", errors="replace")
        session_log_text = _read_session_logs(out_dir)

        if returncode != 0 and not stdout_text.strip() and not session_log_text.strip():
            raise ToolError("E_TOOL_FAILED", f"SQLMap exited with code {returncode}")

        parsed = parse_sqlmap_output(
            stdout_text=stdout_text,
            stderr_text=stderr_text,
            session_log_text=session_log_text,
            target=target,
            method=normalized_method,
            parameter_name=safe_param,
            parameter_location=normalized_location,
            requested_techniques=requested_techniques,
        )
        if returncode != 0 and not parsed.findings:
            parsed.warnings.append(f"SQLMap exited cleanly/partially with code {returncode}")

    summary = (
        f"SQLMap confirmed {len(parsed.findings)} SQLi finding(s) on parameter "
        f"'{safe_param}' ({normalized_location})"
        if parsed.findings
        else f"SQLMap completed without confirmed SQLi on parameter "
        f"'{safe_param}' ({normalized_location})"
    )
    return envelope(summary, parsed.model_dump(mode="json"), len(parsed.findings) >= MAX_FINDINGS)
