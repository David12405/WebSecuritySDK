"""Deterministic Semgrep static analysis and sink candidate extraction (M2-T03)."""

from __future__ import annotations

import hashlib
import json
import re
from collections.abc import Mapping, Set
from datetime import UTC, datetime
from pathlib import Path, PurePosixPath
from typing import Any

from pydantic import Field

from mcp_servers.websec_tools.analysis.source import is_exposure_safe
from mcp_servers.websec_tools.errors import ToolError
from websecuritycheck.domain import (
    ArtifactManifest,
    ArtifactType,
    EvidenceArtifactRecord,
    Id,
)
from websecuritycheck.domain.analysis_models import (
    ConfidenceLevel,
    CweId,
    EvidenceId,
    Module2AnalysisRequest,
    SinkCandidate,
    SinkId,
    SinkKind,
    StrictModel,
)
from websecuritycheck.recon.evidence import RecordIdAllocator

from .semgrep_adapter import (
    AsyncSourceAnalysisPort,
    LocalSemgrepAdapter,
    validate_source_analysis_scope,
)

_IGNORED_DIRS = frozenset(
    {
        ".git",
        ".hg",
        ".svn",
        ".venv",
        "venv",
        "env",
        "node_modules",
        "vendor",
        "dist",
        "build",
        "target",
        "__pycache__",
        ".pytest_cache",
        ".mypy_cache",
        ".ruff_cache",
        "coverage",
        "htmlcov",
        ".tox",
    }
)

_CWE_EXTRACT_RE = re.compile(r"\bCWE-([1-9][0-9]*)\b", re.IGNORECASE)

_NON_SINK_CWES = frozenset(
    {
        "CWE-16",
        "CWE-200",
        "CWE-259",
        "CWE-295",
        "CWE-311",
        "CWE-312",
        "CWE-319",
        "CWE-326",
        "CWE-327",
        "CWE-328",
        "CWE-352",
        "CWE-489",
        "CWE-522",
        "CWE-532",
        "CWE-614",
        "CWE-798",
        "CWE-942",
        "CWE-1004",
        "CWE-1275",
    }
)

_SINK_CWES = frozenset(
    {
        "CWE-22",
        "CWE-23",
        "CWE-36",
        "CWE-73",
        "CWE-77",
        "CWE-78",
        "CWE-79",
        "CWE-80",
        "CWE-83",
        "CWE-88",
        "CWE-89",
        "CWE-90",
        "CWE-94",
        "CWE-95",
        "CWE-96",
        "CWE-564",
        "CWE-643",
        "CWE-943",
        "CWE-1336",
    }
)

_NON_SINK_RULE_PATTERNS = (
    "hardcoded-",
    "detected-private-key",
    "jwt-hardcoded",
    "password-in-",
    "secret-in-",
    "api-key-detected",
    "plaintext-password",
    "cookie-",
    "httponly",
    "samesite",
    "secure-flag",
    "missing-csrf",
    "csrf-disabled",
    "cors-misconfiguration",
    "debug-enabled",
    "hsts-",
    "clickjacking",
    "x-frame-options",
    "weak-hash",
    "md5-",
    "sha1-",
    "weak-crypto",
    "insecure-cipher",
    "tls-version",
    "ssl-verify",
)

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


class SinkCorrelationMetadata(StrictModel):
    """Structured static metadata preserved for M2-T05 correlation."""

    sink_id: SinkId
    primary_rule_id: str = Field(min_length=1)
    all_rule_ids: list[str] = Field(default_factory=list)
    cwe_ids: list[CweId] = Field(default_factory=list)
    severities: list[str] = Field(default_factory=list)
    messages: list[str] = Field(default_factory=list)
    start_column: int | None = Field(default=None, ge=1)
    end_column: int | None = Field(default=None, ge=1)
    taint_source_snippet: str | None = None
    taint_source_file: str | None = None
    taint_source_line: int | None = Field(default=None, ge=1)
    all_taint_sources: list[str] = Field(default_factory=list)


class SinkExtractionResult(StrictModel):
    """Deterministic output of Module 2 Semgrep sink candidate extraction."""

    sink_candidates: list[SinkCandidate] = Field(default_factory=list)
    analysis_evidence_records: list[EvidenceArtifactRecord] = Field(default_factory=list)
    artifact_manifests: list[ArtifactManifest] = Field(default_factory=list)
    sink_metadata: dict[SinkId, SinkCorrelationMetadata] = Field(default_factory=dict)
    scanned_files: list[str] = Field(default_factory=list)
    semgrep_version: str | None = None
    ruleset_sha256: str | None = None
    execution_ref: str | None = None
    source_revision: str | None = None
    source_repository_ref: str | None = None
    source_repo_path: str | None = None
    source_tree_sha256: str | None = None
    worktree_dirty: bool | None = None
    limitations: list[str] = Field(default_factory=list)
    warnings: list[str] = Field(default_factory=list)


def normalize_sink_file_path(path_str: str) -> str:
    """Normalize a sink file path to a clean forward-slash relative path."""
    cleaned = path_str.strip().replace("\\", "/")
    while cleaned.startswith("./"):
        cleaned = cleaned[2:]
    cleaned = re.sub(r"/+", "/", cleaned)
    return cleaned.strip("/")


def is_safe_sink_path(path_str: str) -> bool:
    """Validate that a relative path stays within the repository and avoids ignored dirs."""
    if not path_str or path_str.startswith(("/", "\\")) or ":" in path_str:
        return False
    parts = PurePosixPath(path_str).parts
    if not parts or ".." in parts:
        return False
    return not any(part in _IGNORED_DIRS for part in parts)


def sanitize_sink_text(
    text: str | None, file_path: str, *, max_chars: int = 500
) -> tuple[str | None, bool]:
    """Apply unified fail-closed redaction to snippet or message text."""
    if text is None:
        return None, False

    # Level 1: Sensitive file check
    if not is_exposure_safe(Path(file_path)):
        return None, True

    # Level 3 pre-check: PEM block / SSH keys -> fail closed
    if _PEM_KEY_RE.search(text):
        return None, True

    redaction_applied = False
    cleaned = text

    # Level 2 regex redactions
    if _CREDENTIAL_URL_RE.search(cleaned):
        cleaned = _CREDENTIAL_URL_RE.sub("<redacted-url>", cleaned)
        redaction_applied = True
    if _AUTH_HEADER_RE.search(cleaned):
        cleaned = _AUTH_HEADER_RE.sub("Bearer <redacted>", cleaned)
        redaction_applied = True
    if _JWT_TOKEN_RE.search(cleaned):
        cleaned = _JWT_TOKEN_RE.sub("<redacted-jwt>", cleaned)
        redaction_applied = True
    if _AWS_KEY_RE.search(cleaned):
        cleaned = _AWS_KEY_RE.sub("<redacted-key>", cleaned)
        redaction_applied = True
    if _GITHUB_TOKEN_RE.search(cleaned):
        cleaned = _GITHUB_TOKEN_RE.sub("<redacted-token>", cleaned)
        redaction_applied = True
    if _SLACK_TOKEN_RE.search(cleaned):
        cleaned = _SLACK_TOKEN_RE.sub("<redacted-token>", cleaned)
        redaction_applied = True

    if _ASSIGNMENT_SECRET_RE.search(cleaned):
        cleaned = _ASSIGNMENT_SECRET_RE.sub(r'\1 = "<redacted>"', cleaned)
        redaction_applied = True
    if _DICT_SECRET_RE.search(cleaned):
        cleaned = _DICT_SECRET_RE.sub(r'"\2": "<redacted>"', cleaned)
        redaction_applied = True

    # Level 3 post-check: if sensitive variable assignments still contain raw secrets
    if _UNRESOLVED_SECRET_KEYWORD_RE.search(cleaned) and re.search(
        r"""(?i)\b(password|secret|key)\b\s*[:=]\s*['"][^<]""", cleaned
    ):
        return None, True

    if len(cleaned) > max_chars:
        cleaned = cleaned[:max_chars]
        redaction_applied = True

    return cleaned, redaction_applied


def _extract_cwes(metadata: Mapping[str, Any] | None) -> list[CweId]:
    if not metadata or not isinstance(metadata, Mapping):
        return []
    raw = metadata.get("cwe")
    candidates: list[str] = []
    if isinstance(raw, str):
        candidates.append(raw)
    elif isinstance(raw, (list, tuple, set)):
        candidates.extend(str(item) for item in raw)

    found: set[str] = set()
    for text in candidates:
        for match in _CWE_EXTRACT_RE.finditer(text):
            found.add(f"CWE-{match.group(1)}")
    return sorted(CweId(cwe) for cwe in found)


def is_non_sink_finding(
    rule_id: str,
    metadata: Mapping[str, Any] | None,
    *,
    has_taint_trace: bool,
) -> tuple[bool, str | None]:
    """Determine whether a Semgrep finding is a non-sink configuration or coding practice check."""
    if has_taint_trace:
        return False, None

    meta = metadata or {}
    category = meta.get("category")
    if isinstance(category, str):
        cat_lower = category.strip().lower()
        if cat_lower and cat_lower not in {"security", "audit"}:
            return True, f"category {category!r} is not security/audit"

    rule_lower = rule_id.lower()
    for pattern in _NON_SINK_RULE_PATTERNS:
        if pattern in rule_lower:
            return True, f"rule_id matches non-sink pattern {pattern!r}"

    cwes = {str(c) for c in _extract_cwes(meta)}
    if cwes and cwes.issubset(_NON_SINK_CWES) and not (cwes & _SINK_CWES):
        return True, f"CWEs {sorted(cwes)} belong exclusively to non-sink categories"

    return False, None


def classify_sink_kind(
    rule_id: str,
    metadata: Mapping[str, Any] | None = None,
    *,
    has_taint_trace: bool = False,
) -> tuple[SinkKind | None, list[CweId], str | None]:
    """Classify a finding into a supported SinkKind using strict 9-tier priority."""
    non_sink, reason = is_non_sink_finding(rule_id, metadata, has_taint_trace=has_taint_trace)
    if non_sink:
        return None, [], reason

    meta = metadata or {}
    cwes = _extract_cwes(meta)
    cwe_strs = {str(c) for c in cwes}

    rule_lower = rule_id.lower()
    subcat = str(meta.get("subcategory") or "").lower()
    vuln_class = str(meta.get("vuln_class") or "").lower()
    technology = str(meta.get("technology") or "").lower()
    id_tokens = f"{rule_lower} {subcat} {vuln_class} {technology}"

    # Tier 1: ORM_QUERY
    orm_tokens = (
        "orm-injection",
        "django-orm",
        "extra-where",
        "raw-query-orm",
        "hibernate-hql",
        "jpql",
        "sequelize-where",
        "active-record-sqli",
        "gorm-sqli",
    )
    if "CWE-564" in cwe_strs or any(tok in id_tokens for tok in orm_tokens):
        return SinkKind.ORM_QUERY, cwes, None

    # Tier 2: LDAP_OR_XPATH
    ldap_xpath_tokens = (
        "ldap-injection",
        "ldap-query",
        "ldap-search",
        "xpath-injection",
        "xpath-query",
    )
    if (
        "CWE-90" in cwe_strs
        or "CWE-643" in cwe_strs
        or any(tok in id_tokens for tok in ldap_xpath_tokens)
    ):
        return SinkKind.LDAP_OR_XPATH, cwes, None

    # Tier 3: NOSQL_QUERY
    nosql_tokens = (
        "nosql-injection",
        "nosql-query",
        "mongodb-injection",
        "pymongo-query",
        "mongoose-where",
        "couchdb-injection",
    )
    if any(tok in id_tokens for tok in nosql_tokens) or (
        "CWE-943" in cwe_strs and not ({"CWE-89", "CWE-90", "CWE-643"} & cwe_strs)
    ):
        return SinkKind.NOSQL_QUERY, cwes, None

    # Tier 4: TEMPLATE_RENDER
    ssti_tokens = (
        "ssti",
        "template-injection",
        "render-template-string",
        "jinja2-template",
        "from-string-template",
        "freemarker-ssti",
        "twig-ssti",
        "velocity-ssti",
        "mako-ssti",
    )
    if "CWE-1336" in cwe_strs or any(tok in id_tokens for tok in ssti_tokens):
        return SinkKind.TEMPLATE_RENDER, cwes, None

    # Tier 5: SQL_QUERY
    sqli_tokens = (
        "sql-injection",
        "sqli",
        "raw-sql",
        "formatted-sql",
        "sql-string",
        "cursor-execute",
        "jdbc-sqli",
        "sqlalchemy-text",
        "sequelize-query",
    )
    if "CWE-89" in cwe_strs or any(tok in id_tokens for tok in sqli_tokens):
        return SinkKind.SQL_QUERY, cwes, None

    # Tier 6: OS_COMMAND
    cmdi_tokens = (
        "command-injection",
        "cmd-injection",
        "cmdi",
        "os-system",
        "subprocess-call",
        "subprocess-popen",
        "child-process-exec",
        "shell-exec",
        "popen-sink",
    )
    if ({"CWE-78", "CWE-77", "CWE-88"} & cwe_strs) or any(tok in id_tokens for tok in cmdi_tokens):
        return SinkKind.OS_COMMAND, cwes, None

    # Tier 7: CODE_EVAL
    eval_tokens = (
        "code-injection",
        "eval-injection",
        "unsafe-eval",
        "eval-use",
        "exec-use",
        "dynamic-code",
        "vm-run",
        "new-function-eval",
    )
    if ({"CWE-94", "CWE-95", "CWE-96"} & cwe_strs) or any(tok in id_tokens for tok in eval_tokens):
        return SinkKind.CODE_EVAL, cwes, None

    # Tier 8: PATH_ACCESS
    path_tokens = (
        "path-traversal",
        "directory-traversal",
        "file-inclusion",
        "lfi",
        "arbitrary-file-read",
        "arbitrary-file-write",
        "send-file-traversal",
    )
    if ({"CWE-22", "CWE-23", "CWE-36", "CWE-73"} & cwe_strs) or any(
        tok in id_tokens for tok in path_tokens
    ):
        return SinkKind.PATH_ACCESS, cwes, None

    # Tier 9: HTML_OUTPUT
    xss_tokens = (
        "xss",
        "cross-site-scripting",
        "dangerouslysetinnerhtml",
        "innerhtml-sink",
        "v-html",
        "mark-safe",
        "unescaped-html",
        "response-write-xss",
        "document-write-xss",
    )
    if ({"CWE-79", "CWE-80", "CWE-83"} & cwe_strs) or any(tok in id_tokens for tok in xss_tokens):
        return SinkKind.HTML_OUTPUT, cwes, None

    return None, cwes, "rule does not map to a supported SinkKind"


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
    inter_raw = dataflow_trace.get("intermediate_vars") or []
    inter_nodes = (
        [inter_raw]
        if isinstance(inter_raw, (list, tuple))
        and len(inter_raw) == 2
        and isinstance(inter_raw[0], str)
        and inter_raw[0] in {"CliLoc", "CliCall"}
        else (inter_raw if isinstance(inter_raw, list) else [inter_raw])
    )
    sink_nodes = _flatten_trace_nodes(dataflow_trace.get("taint_sink"))

    if not source_nodes or not sink_nodes:
        return False, [], None, None, None, None, False

    source_parsed = _parse_trace_node(source_nodes[0], file_path)
    sink_parsed = _parse_trace_node(sink_nodes[-1], file_path)
    if not source_parsed or not sink_parsed:
        return False, [], None, None, None, None, False

    src_file, src_line, _sc, _ec, src_content = source_parsed
    snk_file, snk_line, snk_sc, snk_ec, snk_content = sink_parsed

    redaction_applied = False
    clean_src, r1 = sanitize_sink_text(src_content, src_file, max_chars=120)
    clean_snk, r2 = sanitize_sink_text(snk_content, snk_file, max_chars=120)
    redaction_applied = r1 or r2

    steps: list[str] = [f"{src_file}:{src_line} (source: {clean_src or '<redacted>'})"]

    for item in inter_nodes:
        parsed = _parse_trace_node(item, file_path)
        if parsed:
            p_file, p_line, _c1, _c2, p_content = parsed
            clean_p, rp = sanitize_sink_text(p_content, p_file, max_chars=120)
            redaction_applied = redaction_applied or rp
            steps.append(f"{p_file}:{p_line} (propagator: {clean_p or '<redacted>'})")

    steps.append(f"{snk_file}:{snk_line} (sink: {clean_snk or '<redacted>'})")

    taint_sink_span: tuple[int, int, int, int] | None = None
    if snk_file == file_path and snk_sc is not None and snk_ec is not None:
        taint_sink_span = (snk_line, snk_line, snk_sc, snk_ec)

    return (
        True,
        steps,
        clean_src,
        src_file,
        src_line,
        taint_sink_span,
        redaction_applied,
    )


def _compute_confidence(
    raw_conf: str | None, raw_sev: str | None, has_taint_flow: bool
) -> ConfidenceLevel:
    conf_u = (raw_conf or "").upper()
    sev_u = (raw_sev or "").upper()

    if has_taint_flow:
        if conf_u == "HIGH" or (not conf_u and sev_u in {"ERROR", "HIGH"}):
            return ConfidenceLevel.HIGH
        if conf_u == "LOW":
            return ConfidenceLevel.LOW
        return ConfidenceLevel.MEDIUM

    # Unverified static sink without taint flow: capped at MEDIUM
    if conf_u in {"HIGH", "MEDIUM"} or sev_u in {"ERROR", "HIGH", "WARNING", "MEDIUM"}:
        return ConfidenceLevel.MEDIUM
    return ConfidenceLevel.LOW


def sink_identity_key(
    file_path: str,
    start_line: int,
    end_line: int | None,
    sink_kind: SinkKind,
    *,
    canonical_span: tuple[int, int, int, int] | None = None,
    ambiguous_discriminator: str = "",
) -> tuple[str, str, int, int, int, int, str]:
    """Build a deterministic identity key for sink deduplication."""
    norm_path = normalize_sink_file_path(file_path)
    resolved_end = end_line if end_line is not None else start_line
    if canonical_span is not None:
        s_line, e_line, s_col, e_col = canonical_span
        return (norm_path, sink_kind.value, s_line, e_line, s_col, e_col, "")
    return (
        norm_path,
        sink_kind.value,
        start_line,
        resolved_end,
        0,
        0,
        ambiguous_discriminator,
    )


class _SinkAccumulator:
    """Internal grouping accumulator for deduplicating identical sinks."""

    def __init__(
        self,
        *,
        file_path: str,
        start_line: int,
        end_line: int | None,
        start_column: int | None,
        end_column: int | None,
        sink_kind: SinkKind,
        rule_id: str,
        confidence: ConfidenceLevel,
        has_static_taint_flow: bool,
        dataflow_steps: list[str],
        snippet: str | None,
        cwe_ids: list[CweId],
        severity: str | None,
        message: str | None,
        taint_source_snippet: str | None,
        taint_source_file: str | None,
        taint_source_line: int | None,
        redaction_applied: bool,
    ) -> None:
        self.file_path = file_path
        self.start_line = start_line
        self.end_line = end_line
        self.start_column = start_column
        self.end_column = end_column
        self.sink_kind = sink_kind

        self.rule_ids: set[str] = {rule_id}
        self.taint_rule_ids: set[str] = {rule_id} if has_static_taint_flow else set()
        self.confidence = confidence
        self.has_static_taint_flow = has_static_taint_flow
        self.dataflow_steps = dataflow_steps
        self.snippets: list[str] = [snippet] if snippet else []
        self.cwe_ids: set[CweId] = set(cwe_ids)
        self.severities: set[str] = {severity} if severity else set()
        self.messages: set[str] = {message} if message else set()
        self.taint_sources: list[tuple[str | None, str | None, int | None]] = (
            [(taint_source_snippet, taint_source_file, taint_source_line)]
            if taint_source_snippet
            else []
        )
        self.redaction_applied = redaction_applied

    def merge(
        self,
        *,
        rule_id: str,
        confidence: ConfidenceLevel,
        has_static_taint_flow: bool,
        dataflow_steps: list[str],
        snippet: str | None,
        cwe_ids: list[CweId],
        severity: str | None,
        message: str | None,
        taint_source_snippet: str | None,
        taint_source_file: str | None,
        taint_source_line: int | None,
        redaction_applied: bool,
    ) -> None:
        self.rule_ids.add(rule_id)
        if has_static_taint_flow:
            self.taint_rule_ids.add(rule_id)
            self.has_static_taint_flow = True

        # Confidence: take highest
        order = {
            ConfidenceLevel.LOW: 1,
            ConfidenceLevel.MEDIUM: 2,
            ConfidenceLevel.HIGH: 3,
        }
        if order[confidence] > order[self.confidence]:
            self.confidence = confidence

        # Dataflow steps: prefer longer/more detailed trace
        if has_static_taint_flow and (
            not self.dataflow_steps
            or len(dataflow_steps) > len(self.dataflow_steps)
            or (
                len(dataflow_steps) == len(self.dataflow_steps)
                and tuple(dataflow_steps) < tuple(self.dataflow_steps)
            )
        ):
            self.dataflow_steps = dataflow_steps

        if snippet:
            self.snippets.append(snippet)
        self.cwe_ids.update(cwe_ids)
        if severity:
            self.severities.add(severity)
        if message:
            self.messages.add(message)
        if taint_source_snippet:
            self.taint_sources.append((taint_source_snippet, taint_source_file, taint_source_line))
        self.redaction_applied = self.redaction_applied or redaction_applied


def verify_sink_evidence_integrity(
    record: EvidenceArtifactRecord, manifest: ArtifactManifest
) -> bool:
    """Verify that an EvidenceArtifactRecord matches its ArtifactManifest content and hash."""
    if record.artifact_ref != manifest.artifact_ref:
        return False
    if (
        record.artifact_type != ArtifactType.SOURCE_ARTIFACT
        or manifest.artifact_type != ArtifactType.SOURCE_ARTIFACT
    ):
        return False
    if manifest.content is None:
        return False
    content_bytes = manifest.content.encode("utf-8")
    actual_digest = hashlib.sha256(content_bytes).hexdigest()
    if record.sha256_hash.lower() != actual_digest:
        return False
    if manifest.sha256_hash and manifest.sha256_hash.lower() != actual_digest:
        return False
    if record.size_bytes != len(content_bytes) or (
        manifest.size_bytes is not None and manifest.size_bytes != len(content_bytes)
    ):
        return False
    try:
        parsed = json.loads(manifest.content)
        if (
            not isinstance(parsed, dict)
            or parsed.get("schema") != "websecuritycheck.semgrep_sink_artifact.v1"
        ):
            return False
    except (json.JSONDecodeError, UnicodeDecodeError):
        return False
    return True


def extract_sink_candidates(
    request: Module2AnalysisRequest,
    semgrep_payload: Mapping[str, Any] | None = None,
    *,
    sink_allocator: RecordIdAllocator | None = None,
    evidence_allocator: RecordIdAllocator | None = None,
    existing_evidence_ids: Set[str] | None = None,
    captured_at: datetime | None = None,
) -> SinkExtractionResult:
    """Synchronously extract and normalize SinkCandidate objects from a Semgrep payload."""
    # Step 1: Authorization and Scope Guard
    _authorized_path, refusal_reason = validate_source_analysis_scope(
        request, require_existing_filesystem=False
    )
    if refusal_reason is not None:
        return SinkExtractionResult(limitations=[refusal_reason])

    if semgrep_payload is None:
        return SinkExtractionResult(
            limitations=[
                "No Semgrep payload provided to extract_sink_candidates; skipped sink extraction"
            ]
        )

    # Validate top-level payload structure
    raw_data = (
        semgrep_payload.get("data")
        if isinstance(semgrep_payload.get("data"), Mapping)
        else semgrep_payload
    )
    raw_results = raw_data.get("findings")
    if raw_results is None:
        raw_results = raw_data.get("results")
    if not isinstance(raw_results, list):
        return SinkExtractionResult(
            limitations=[
                "Malformed Semgrep output payload: missing valid 'findings' or 'results' list"
            ]
        )

    provenance_tool = str(raw_data.get("tool") or "semgrep")
    provenance_version = raw_data.get("version")
    provenance_ruleset = str(raw_data.get("ruleset") or "local-approved")
    provenance_ruleset_ref = str(
        raw_data.get("ruleset_ref") or raw_data.get("ruleset") or "local-ruleset"
    )
    provenance_ruleset_path = raw_data.get("ruleset_path")
    provenance_ruleset_sha256 = raw_data.get("ruleset_sha256")
    provenance_execution_ref = raw_data.get("execution_ref")
    provenance_source_revision = raw_data.get("source_revision")
    provenance_source_repository_ref = raw_data.get("source_repository_ref")
    provenance_source_repo_path = raw_data.get("source_repo_path")
    provenance_source_tree_sha256 = raw_data.get("source_tree_sha256")
    provenance_worktree_dirty = raw_data.get("worktree_dirty")
    scan_path = str(raw_data.get("path") or ".")
    scanned_files_raw = raw_data.get("scanned_files")
    scanned_files = (
        sorted({str(item) for item in scanned_files_raw})
        if isinstance(scanned_files_raw, list)
        and all(isinstance(item, str) for item in scanned_files_raw)
        else []
    )
    is_truncated = bool(semgrep_payload.get("truncated") or raw_data.get("truncated"))

    limitations: set[str] = set()
    warnings: set[str] = set()
    if raw_data.get("files_scanned") == 0:
        limitations.add("SEMGREP_SCAN_EMPTY")

    # Scope check on top-level payload scan path if absolute
    if scan_path and (scan_path.startswith("/") or bool(re.match(r"^[A-Za-z]:", scan_path))):
        approved_root = request.target_model.scope_rules.source_repository_ref  # type: ignore[union-attr]
        try:
            norm_scan = normalize_sink_file_path(scan_path)
            norm_app = normalize_sink_file_path(approved_root or "")
            if not PurePosixPath(norm_scan).is_relative_to(PurePosixPath(norm_app)):
                return SinkExtractionResult(
                    limitations=[
                        "Refused Semgrep payload: scan path "
                        f"{scan_path!r} lies outside approved scope {approved_root!r}"
                    ]
                )
        except (ValueError, TypeError):
            pass

    # Accumulator dictionary for deduplication
    accumulators: dict[tuple[str, str, int, int, int, int, str], _SinkAccumulator] = {}

    for item in raw_results:
        if not isinstance(item, Mapping):
            continue
        rule_id = item.get("rule_id") or item.get("check_id")
        file_raw = item.get("file") or item.get("path")
        if not isinstance(rule_id, str) or not isinstance(file_raw, str):
            continue

        norm_file = normalize_sink_file_path(file_raw)

        # Check for absolute path escape in findings
        if file_raw.startswith("/") or bool(re.match(r"^[A-Za-z]:", file_raw)):
            approved_root = request.target_model.scope_rules.source_repository_ref  # type: ignore[union-attr]
            try:
                norm_app = normalize_sink_file_path(approved_root or "")
                if not PurePosixPath(norm_file).is_relative_to(PurePosixPath(norm_app)):
                    warnings.add(
                        f"Skipped finding with path {file_raw!r} lying outside approved repository"
                    )
                    continue
                # Make relative to approved root
                norm_file = str(PurePosixPath(norm_file).relative_to(PurePosixPath(norm_app)))
            except (ValueError, TypeError):
                warnings.add(f"Skipped finding with invalid absolute path {file_raw!r}")
                continue

        if not is_safe_sink_path(norm_file):
            warnings.add(
                f"Skipped finding from rule {rule_id!r}: unsafe repository file path {file_raw!r}"
            )
            continue

        start_line = item.get("start_line")
        if start_line is None and isinstance(item.get("start"), Mapping):
            start_line = item["start"].get("line")
        if not isinstance(start_line, int) or start_line < 1:
            continue

        end_line = item.get("end_line")
        if end_line is None and isinstance(item.get("end"), Mapping):
            end_line = item["end"].get("line")
        if isinstance(end_line, int) and end_line < start_line:
            end_line = start_line

        start_col = item.get("start_column")
        if start_col is None and isinstance(item.get("start"), Mapping):
            start_col = item["start"].get("col")
        if not isinstance(start_col, int) or start_col < 1:
            start_col = None

        end_col = item.get("end_column")
        if end_col is None and isinstance(item.get("end"), Mapping):
            end_col = item["end"].get("col")
        if not isinstance(end_col, int) or end_col < 1:
            end_col = None

        extra = item.get("extra") if isinstance(item.get("extra"), Mapping) else {}
        metadata = item.get("metadata") or extra.get("metadata")
        dataflow_trace = item.get("dataflow_trace") or extra.get("dataflow_trace")
        message_raw = item.get("message") or extra.get("message")
        severity_raw = item.get("severity") or extra.get("severity")
        snippet_raw = item.get("snippet") or extra.get("lines")

        (
            has_taint,
            steps,
            src_snip,
            src_file,
            src_line,
            taint_span,
            trace_redacted,
        ) = _extract_dataflow_info(dataflow_trace, norm_file)

        sink_kind, cwes, skip_reason = classify_sink_kind(
            rule_id, metadata, has_taint_trace=has_taint
        )
        if sink_kind is None:
            warnings.add(
                f"Skipped Semgrep finding from rule {rule_id!r} at "
                f"{norm_file}:{start_line}: {skip_reason}"
            )
            continue

        clean_snippet, snip_redacted = sanitize_sink_text(snippet_raw, norm_file, max_chars=500)
        clean_msg, msg_redacted = sanitize_sink_text(message_raw, norm_file, max_chars=300)
        item_redaction = trace_redacted or snip_redacted or msg_redacted

        confidence = _compute_confidence(
            metadata.get("confidence") if isinstance(metadata, Mapping) else None,
            severity_raw,
            has_taint,
        )

        # Coordinate Anchor extraction for conservative deduplication
        canonical_span: tuple[int, int, int, int] | None = None
        ambiguous_discriminator = ""

        if taint_span is not None:
            canonical_span = taint_span
        elif start_col is not None and end_col is not None:
            canonical_span = (start_line, end_line or start_line, start_col, end_col)
        else:
            snip_hash = hashlib.sha256((clean_snippet or "").encode("utf-8")).hexdigest()[:12]
            ambiguous_discriminator = f"{rule_id}:{snip_hash}"

        key = sink_identity_key(
            norm_file,
            start_line,
            end_line,
            sink_kind,
            canonical_span=canonical_span,
            ambiguous_discriminator=ambiguous_discriminator,
        )

        if key in accumulators:
            accumulators[key].merge(
                rule_id=rule_id,
                confidence=confidence,
                has_static_taint_flow=has_taint,
                dataflow_steps=steps,
                snippet=clean_snippet,
                cwe_ids=cwes,
                severity=severity_raw,
                message=clean_msg,
                taint_source_snippet=src_snip,
                taint_source_file=src_file,
                taint_source_line=src_line,
                redaction_applied=item_redaction,
            )
        else:
            accumulators[key] = _SinkAccumulator(
                file_path=norm_file,
                start_line=start_line,
                end_line=end_line,
                start_column=start_col,
                end_column=end_col,
                sink_kind=sink_kind,
                rule_id=rule_id,
                confidence=confidence,
                has_static_taint_flow=has_taint,
                dataflow_steps=steps,
                snippet=clean_snippet,
                cwe_ids=cwes,
                severity=severity_raw,
                message=clean_msg,
                taint_source_snippet=src_snip,
                taint_source_file=src_file,
                taint_source_line=src_line,
                redaction_applied=item_redaction,
            )

    # Sort accumulators deterministically
    sorted_accs = sorted(
        accumulators.values(),
        key=lambda acc: (
            acc.file_path,
            acc.start_line,
            acc.end_line or acc.start_line,
            acc.sink_kind.value,
            sorted(acc.rule_ids)[0],
        ),
    )

    # Seed allocators
    all_known_evidence: set[str] = set()
    for evd in request.evidence_records:
        all_known_evidence.add(str(evd.evidence_id))
    for ep in request.target_model.endpoints:
        all_known_evidence.update(str(r) for r in ep.evidence_refs)
        for p in ep.observed_parameters:
            all_known_evidence.update(str(r) for r in p.evidence_refs)
    for tech in request.target_model.technologies:
        all_known_evidence.update(str(r) for r in tech.evidence_refs)
    for obs in request.observations:
        all_known_evidence.update(str(r) for r in obs.evidence_refs)
    if existing_evidence_ids:
        all_known_evidence.update(str(x) for x in existing_evidence_ids)

    snk_alloc = sink_allocator or RecordIdAllocator()
    evd_alloc = evidence_allocator or RecordIdAllocator(all_known_evidence)

    capture_time = captured_at or request.target_model.last_updated or datetime.now(UTC)

    sink_candidates: list[SinkCandidate] = []
    evidence_records: list[EvidenceArtifactRecord] = []
    artifact_manifests: list[ArtifactManifest] = []
    sink_metadata_map: dict[SinkId, SinkCorrelationMetadata] = {}

    for acc in sorted_accs:
        sink_id = SinkId(snk_alloc.new("SNK"))
        evidence_id = Id(evd_alloc.new("EVD"))
        artifact_ref = f"semgrep-sink-{sink_id.lower()}"

        # Determine primary rule_id
        if acc.taint_rule_ids:
            primary_rule_id = sorted(acc.taint_rule_ids)[0]
        else:
            primary_rule_id = sorted(acc.rule_ids)[0]

        # Selected snippet
        selected_snippet = sorted(acc.snippets)[0] if acc.snippets else None

        # Format taint sources
        all_sources: list[str] = []
        for ts_snip, ts_f, ts_l in acc.taint_sources:
            if ts_snip and ts_f and ts_l:
                all_sources.append(f"{ts_f}:{ts_l}: {ts_snip}")
        all_sources = sorted(set(all_sources))

        # Build canonical artifact content payload
        canonical_payload: dict[str, Any] = {
            "schema": "websecuritycheck.semgrep_sink_artifact.v1",
            "assessment_id": request.target_model.assessment_id,
            "artifact_ref": artifact_ref,
            "sink_id": sink_id,
            "sink_kind": acc.sink_kind.value,
            "file_path": acc.file_path,
            "start_line": acc.start_line,
            "end_line": acc.end_line,
            "start_column": acc.start_column,
            "end_column": acc.end_column,
            "primary_rule_id": primary_rule_id,
            "rule_ids": sorted(acc.rule_ids),
            "cwe_ids": sorted(str(c) for c in acc.cwe_ids),
            "severities": sorted(acc.severities),
            "messages": sorted(acc.messages),
            "snippet": selected_snippet,
            "has_static_taint_flow": acc.has_static_taint_flow,
            "dataflow_steps": acc.dataflow_steps,
            "all_taint_sources": all_sources,
            "redaction_applied": acc.redaction_applied,
            "truncated": is_truncated,
            "provenance": {
                "tool": provenance_tool,
                "version": provenance_version,
                "ruleset": provenance_ruleset,
                "ruleset_ref": provenance_ruleset_ref,
                "ruleset_path": provenance_ruleset_path,
                "ruleset_sha256": provenance_ruleset_sha256,
                "source_revision": provenance_source_revision,
                "source_repository_ref": provenance_source_repository_ref,
                "source_repo_path": provenance_source_repo_path,
                "source_tree_sha256": provenance_source_tree_sha256,
                "worktree_dirty": provenance_worktree_dirty,
                "execution_ref": provenance_execution_ref,
                "scan_path": scan_path,
                "derivation_modality": "static_source_snapshot",
            },
        }

        content_str = json.dumps(
            canonical_payload,
            sort_keys=True,
            separators=(",", ":"),
            ensure_ascii=False,
        )
        content_bytes = content_str.encode("utf-8")
        sha256_hash = hashlib.sha256(content_bytes).hexdigest()
        size_bytes = len(content_bytes)

        manifest = ArtifactManifest(
            artifact_ref=artifact_ref,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            content=content_str,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            redaction_applied=acc.redaction_applied,
            truncated=is_truncated,
            metadata={
                "sink_id": sink_id,
                "sink_kind": acc.sink_kind.value,
                "file_path": acc.file_path,
                "primary_rule_id": primary_rule_id,
            },
        )
        artifact_manifests.append(manifest)

        evd_record = EvidenceArtifactRecord(
            evidence_id=evidence_id,
            assessment_id=request.target_model.assessment_id,
            artifact_type=ArtifactType.SOURCE_ARTIFACT,
            artifact_ref=artifact_ref,
            sha256_hash=sha256_hash,
            size_bytes=size_bytes,
            media_type="application/json",
            captured_at=capture_time,
            source_tool_id="semgrep",
            execution_ref=(
                Id(str(provenance_execution_ref)) if provenance_execution_ref else None
            ),
            provenance={
                "tool": provenance_tool,
                "version": provenance_version,
                "ruleset": provenance_ruleset,
                "ruleset_ref": provenance_ruleset_ref,
                "ruleset_path": provenance_ruleset_path,
                "ruleset_sha256": provenance_ruleset_sha256,
                "source_revision": provenance_source_revision,
                "source_repository_ref": provenance_source_repository_ref,
                "source_repo_path": provenance_source_repo_path,
                "source_tree_sha256": provenance_source_tree_sha256,
                "worktree_dirty": provenance_worktree_dirty,
                "execution_ref": provenance_execution_ref,
                "scan_path": scan_path,
                "derivation_modality": "static_source_snapshot",
            },
            redaction_applied=acc.redaction_applied,
            truncated=is_truncated,
            metadata={
                "sink_id": sink_id,
                "sink_kind": acc.sink_kind.value,
                "file_path": acc.file_path,
                "start_line": acc.start_line,
                "end_line": acc.end_line,
                "primary_rule_id": primary_rule_id,
                "rule_ids": sorted(acc.rule_ids),
                "cwe_ids": sorted(str(c) for c in acc.cwe_ids),
                "severities": sorted(acc.severities),
                "has_static_taint_flow": acc.has_static_taint_flow,
            },
        )
        evidence_records.append(evd_record)

        sink_candidate = SinkCandidate(
            sink_id=sink_id,
            sink_kind=acc.sink_kind,
            file_path=acc.file_path,
            start_line=acc.start_line,
            end_line=acc.end_line,
            rule_id=primary_rule_id,
            snippet=selected_snippet,
            has_static_taint_flow=acc.has_static_taint_flow,
            dataflow_steps=acc.dataflow_steps,
            confidence=acc.confidence,
            evidence_refs=[EvidenceId(str(evidence_id))],
            observation_refs=[],
        )
        sink_candidates.append(sink_candidate)

        first_ts_snip = acc.taint_sources[0][0] if acc.taint_sources else None
        first_ts_file = acc.taint_sources[0][1] if acc.taint_sources else None
        first_ts_line = acc.taint_sources[0][2] if acc.taint_sources else None

        sink_metadata_map[sink_id] = SinkCorrelationMetadata(
            sink_id=sink_id,
            primary_rule_id=primary_rule_id,
            all_rule_ids=sorted(acc.rule_ids),
            cwe_ids=sorted(acc.cwe_ids),
            severities=sorted(acc.severities),
            messages=sorted(acc.messages),
            start_column=acc.start_column,
            end_column=acc.end_column,
            taint_source_snippet=first_ts_snip,
            taint_source_file=first_ts_file,
            taint_source_line=first_ts_line,
            all_taint_sources=all_sources,
        )

    return SinkExtractionResult(
        sink_candidates=sink_candidates,
        analysis_evidence_records=evidence_records,
        artifact_manifests=artifact_manifests,
        sink_metadata=sink_metadata_map,
        scanned_files=scanned_files,
        semgrep_version=(
            str(provenance_version) if provenance_version is not None else None
        ),
        ruleset_sha256=(
            str(provenance_ruleset_sha256) if provenance_ruleset_sha256 else None
        ),
        execution_ref=(str(provenance_execution_ref) if provenance_execution_ref else None),
        source_revision=(
            str(provenance_source_revision) if provenance_source_revision else None
        ),
        source_repository_ref=(
            str(provenance_source_repository_ref) if provenance_source_repository_ref else None
        ),
        source_repo_path=(
            str(provenance_source_repo_path) if provenance_source_repo_path else None
        ),
        source_tree_sha256=(
            str(provenance_source_tree_sha256) if provenance_source_tree_sha256 else None
        ),
        worktree_dirty=(
            bool(provenance_worktree_dirty) if provenance_worktree_dirty is not None else None
        ),
        limitations=sorted(limitations),
        warnings=sorted(warnings),
    )


async def aextract_sink_candidates(
    request: Module2AnalysisRequest,
    *,
    analyzer: AsyncSourceAnalysisPort | None = None,
    semgrep_payload: Mapping[str, Any] | None = None,
    subpath: str = ".",
    sink_allocator: RecordIdAllocator | None = None,
    evidence_allocator: RecordIdAllocator | None = None,
    existing_evidence_ids: Set[str] | None = None,
    captured_at: datetime | None = None,
) -> SinkExtractionResult:
    """Asynchronously execute Semgrep analysis or process a pre-captured payload."""
    if semgrep_payload is not None:
        return extract_sink_candidates(
            request,
            semgrep_payload=semgrep_payload,
            sink_allocator=sink_allocator,
            evidence_allocator=evidence_allocator,
            existing_evidence_ids=existing_evidence_ids,
            captured_at=captured_at,
        )

    # Validate scope with filesystem check
    authorized_path, refusal_reason = validate_source_analysis_scope(
        request, require_existing_filesystem=True
    )
    if refusal_reason is not None:
        return SinkExtractionResult(limitations=[refusal_reason])

    active_analyzer = analyzer or LocalSemgrepAdapter()

    approved_repo = None
    if request.target_model.scope_rules:
        approved_repo = request.target_model.scope_rules.source_repository_ref

    try:
        import inspect
        sig = inspect.signature(active_analyzer.analyze)
        if "source_repository_ref" in sig.parameters:
            payload = await active_analyzer.analyze(
                authorized_path or "", subpath=subpath, source_repository_ref=approved_repo
            )
        else:
            payload = await active_analyzer.analyze(authorized_path or "", subpath=subpath)
    except ToolError as exc:
        return SinkExtractionResult(
            limitations=[f"Semgrep static analysis failed ({exc.code}): {exc.message}"]
        )

    return extract_sink_candidates(
        request,
        semgrep_payload=payload,
        sink_allocator=sink_allocator,
        evidence_allocator=evidence_allocator,
        existing_evidence_ids=existing_evidence_ids,
        captured_at=captured_at,
    )


__all__ = [
    "SinkCorrelationMetadata",
    "SinkExtractionResult",
    "aextract_sink_candidates",
    "classify_sink_kind",
    "extract_sink_candidates",
    "is_non_sink_finding",
    "normalize_sink_file_path",
    "sanitize_sink_text",
    "sink_identity_key",
    "verify_sink_evidence_integrity",
]
