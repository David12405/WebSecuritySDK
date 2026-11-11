"""Secret redaction, placeholder stripping, and Opengrep dataflow trace normalization."""

from __future__ import annotations

import re
from pathlib import Path
from typing import Any

from mcp_servers.websec_tools.analysis.source import is_exposure_safe

from .models import normalize_sink_file_path

_PEM_KEY_RE = re.compile(
    r"-----BEGIN [A-Z0-9 _-]+ KEY-----[\s\S]*?-----END [A-Z0-9 _-]+ KEY-----|"
    r"ssh-(?:rsa|ed25519)\s+[A-Za-z0-9+/=]+",
    re.IGNORECASE,
)
_CREDENTIAL_URL_RE = re.compile(r"[a-zA-Z][a-zA-Z0-9+.-]*://[^/\s:@]+:[^/\s@]+@[^\s\"']+")
_AUTH_HEADER_RE = re.compile(
    r"\b(?:Bearer\s+[A-Za-z0-9._~+/=-]+|Basic\s+[A-Za-z0-9+/=]+)", re.IGNORECASE
)
_JWT_TOKEN_RE = re.compile(r"\beyJ[A-Za-z0-9-_]+\.eyJ[A-Za-z0-9-_]+\.[A-Za-z0-9-_]+\b")
_AWS_KEY_RE = re.compile(r"\bAKIA[0-9A-Z]{16}\b")
_GITHUB_TOKEN_RE = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")
_SLACK_TOKEN_RE = re.compile(r"\bxox[baprs]-[A-Za-z0-9-]+\b")

_ASSIGNMENT_SECRET_RE = re.compile(
    r"""(?i)\b(password|passwd|pwd|secret|api_key|apikey|access_key|private_key|client_secret|auth_token|token|refresh_token|jwt|session_key|database_url|conn_str)\b\s*[:=]\s*(['"])(?:(?!\2).)*\2"""
)
_DICT_SECRET_RE = re.compile(
    r"""(?i)(['"])(password|passwd|pwd|secret|api_key|apikey|access_key|private_key|client_secret|auth_token|token|refresh_token|jwt|session_key|database_url|conn_str)\1\s*:\s*(['"])(?:(?!\3).)*\3"""
)
_UNRESOLVED_SECRET_KEYWORD_RE = re.compile(
    r"\b(?:password|passwd|secret|private_key|api_key|apikey|client_secret|auth_token)\b",
    re.IGNORECASE,
)
_WHOLE_BODY_READER_RE = re.compile(
    r"\b(?:await\s+)?(?:request|req)\.(?:json|text|formData)\(\)|\brequest\.get_json\(\)"
)
_BODY_MEMBER_EXPR_RE = re.compile(
    r"""\b([A-Za-z_$][\w$]*)(?:\.[A-Za-z_$][\w$]*|\[\s*['"][A-Za-z0-9_.-]+['"]\s*\])+"""
)


def _strip_login_placeholder(raw_text: Any) -> str | None:
    if not isinstance(raw_text, str):
        return None
    if raw_text.strip().casefold() == "requires login":
        return None
    return raw_text


def sanitize_sink_text(
    text: str | None, file_path: str, *, max_chars: int = 500
) -> tuple[str | None, bool]:
    """Apply unified fail-closed redaction to snippet or message text."""
    text = _strip_login_placeholder(text)
    if text is None:
        return None, False

    if not is_exposure_safe(Path(file_path)):
        return None, True

    if _PEM_KEY_RE.search(text):
        return None, True

    redaction_applied = False
    cleaned = text

    for pattern, repl in (
        (_CREDENTIAL_URL_RE, "<redacted-url>"),
        (_AUTH_HEADER_RE, "Bearer <redacted>"),
        (_JWT_TOKEN_RE, "<redacted-jwt>"),
        (_AWS_KEY_RE, "<redacted-key>"),
        (_GITHUB_TOKEN_RE, "<redacted-token>"),
        (_SLACK_TOKEN_RE, "<redacted-token>"),
        (_ASSIGNMENT_SECRET_RE, r'\1 = "<redacted>"'),
        (_DICT_SECRET_RE, r'"\2": "<redacted>"'),
    ):
        if pattern.search(cleaned):
            cleaned = pattern.sub(repl, cleaned)
            redaction_applied = True

    if _UNRESOLVED_SECRET_KEYWORD_RE.search(cleaned) and re.search(
        r"""(?i)\b(password|secret|key)\b\s*[:=]\s*['"][^<]""", cleaned
    ):
        return None, True

    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
        redaction_applied = True

    return cleaned, redaction_applied


def _parse_trace_node(
    node: Any, default_file: str
) -> tuple[str, int, int | None, int | None, str] | None:
    """Extract (file_path, start_line, start_col, end_col, content) from trace node."""
    if node is None:
        return None

    if isinstance(node, (list, tuple)):
        if len(node) == 2 and isinstance(node[0], str):
            tag, payload = node[0], node[1]
            if tag == "CliLoc":
                return _parse_trace_node(payload, default_file)
            if tag == "CliCall":
                if isinstance(payload, (list, tuple)) and len(payload) >= 1:
                    return _parse_trace_node(payload[0], default_file)
                return _parse_trace_node(payload, default_file)
        if len(node) >= 2 and (isinstance(node[0], dict) or isinstance(node[1], dict)):
            loc_part = node[0] if isinstance(node[0], dict) else node[1]
            content_part = (
                node[1]
                if isinstance(node[1], str)
                else (node[0] if isinstance(node[0], str) else "")
            )
            return _parse_trace_node({"location": loc_part, "content": content_part}, default_file)
        if len(node) == 1:
            return _parse_trace_node(node[0], default_file)

    if isinstance(node, dict):
        loc = node.get("location") or node
        path = loc.get("path") if isinstance(loc.get("path"), str) else default_file
        start = loc.get("start") if isinstance(loc.get("start"), dict) else {}
        end = loc.get("end") if isinstance(loc.get("end"), dict) else {}
        s_line = start.get("line") if isinstance(start.get("line"), int) else loc.get("line")
        s_col = start.get("col") if isinstance(start.get("col"), int) else loc.get("col")
        e_col = end.get("col") if isinstance(end.get("col"), int) else loc.get("end_col")
        content = (
            str(node.get("content"))
            if node.get("content") is not None
            else (
                str(node.get("abstract_content"))
                if node.get("abstract_content") is not None
                else ""
            )
        )
        if isinstance(s_line, int) and s_line > 0:
            return normalize_sink_file_path(path), s_line, s_col, e_col, content
    return None


def _flatten_trace_nodes(raw: Any) -> list[Any]:
    if not raw:
        return []
    if (
        isinstance(raw, (list, tuple))
        and len(raw) == 2
        and isinstance(raw[0], str)
        and raw[0] in {"CliLoc", "CliCall"}
    ):
        return [raw]
    if isinstance(raw, list):
        return raw
    return [raw]


def _refine_whole_body_source(
    clean_src: str | None,
    inter_contents: list[str],
    clean_snk: str | None,
) -> str | None:
    """Refine coarse whole-body reads (e.g. `await request.json()`) via trace member expressions."""
    if not clean_src or not _WHOLE_BODY_READER_RE.search(clean_src):
        return clean_src

    body_vars: set[str] = {"body", "data", "payload"}
    for txt in inter_contents:
        stripped = txt.strip()
        if re.fullmatch(r"[A-Za-z_$][\w$]*", stripped):
            body_vars.add(stripped)
            break

    candidates = [*reversed(inter_contents)]
    if clean_snk:
        candidates.append(clean_snk)

    for text in candidates:
        if not text:
            continue
        match = _BODY_MEMBER_EXPR_RE.search(text.strip())
        if match and match.group(1) in body_vars:
            return match.group(0)
    return clean_src


def _extract_dataflow_info(
    dataflow_trace: Any, file_path: str
) -> tuple[
    bool,
    list[str],
    str | None,
    str | None,
    int | None,
    tuple[int, int, int, int] | None,
    bool,
]:
    """Extract taint flow steps, taint source metadata, and precise taint sink span."""
    if not isinstance(dataflow_trace, dict):
        return False, [], None, None, None, None, False

    source_nodes = _flatten_trace_nodes(dataflow_trace.get("taint_source"))
    inter_nodes = _flatten_trace_nodes(dataflow_trace.get("intermediate_vars"))
    sink_nodes = _flatten_trace_nodes(dataflow_trace.get("taint_sink"))

    if not source_nodes or not sink_nodes:
        return False, [], None, None, None, None, False

    source_parsed = _parse_trace_node(source_nodes[0], file_path)
    sink_parsed = _parse_trace_node(sink_nodes[-1], file_path)
    if not source_parsed or not sink_parsed:
        return False, [], None, None, None, None, False

    src_file, src_line, _sc, _ec, src_content = source_parsed
    snk_file, snk_line, snk_sc, snk_ec, snk_content = sink_parsed

    clean_src, r1 = sanitize_sink_text(src_content, src_file, max_chars=120)
    clean_snk, r2 = sanitize_sink_text(snk_content, snk_file, max_chars=120)
    redaction_applied = r1 or r2

    steps: list[str] = [f"{src_file}:{src_line} (source: {clean_src or '<redacted>'})"]
    inter_contents: list[str] = []

    for item in inter_nodes:
        parsed = _parse_trace_node(item, file_path)
        if parsed:
            p_file, p_line, _c1, _c2, p_content = parsed
            clean_p, rp = sanitize_sink_text(p_content, p_file, max_chars=120)
            redaction_applied = redaction_applied or rp
            if clean_p:
                inter_contents.append(clean_p)
            steps.append(f"{p_file}:{p_line} (propagator: {clean_p or '<redacted>'})")

    steps.append(f"{snk_file}:{snk_line} (sink: {clean_snk or '<redacted>'})")

    refined_src = _refine_whole_body_source(clean_src, inter_contents, clean_snk)

    taint_sink_span: tuple[int, int, int, int] | None = None
    if snk_file == file_path and snk_sc is not None and snk_ec is not None:
        taint_sink_span = (snk_line, snk_line, snk_sc, snk_ec)

    return (
        True,
        steps,
        refined_src,
        src_file,
        src_line,
        taint_sink_span,
        redaction_applied,
    )


__all__ = [
    "_WHOLE_BODY_READER_RE",
    "_extract_dataflow_info",
    "_flatten_trace_nodes",
    "_parse_trace_node",
    "_refine_whole_body_source",
    "_strip_login_placeholder",
    "sanitize_sink_text",
]

