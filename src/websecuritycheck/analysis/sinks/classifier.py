"""CWE taxonomy, non-sink filtering, and 9-tier SinkKind classifier."""

from __future__ import annotations

import re
from collections.abc import Mapping
from typing import Any

from websecuritycheck.domain.analysis_models import CweId, SinkKind

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
    """Determine whether an Opengrep finding is a non-sink configuration or practice check."""
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


_CLASSIFICATION_TIERS: tuple[tuple[SinkKind, frozenset[str], tuple[str, ...]], ...] = (
    (
        SinkKind.ORM_QUERY,
        frozenset({"CWE-564"}),
        (
            "orm-injection",
            "django-orm",
            "extra-where",
            "raw-query-orm",
            "hibernate-hql",
            "jpql",
            "sequelize-where",
            "active-record-sqli",
            "gorm-sqli",
        ),
    ),
    (
        SinkKind.LDAP_OR_XPATH,
        frozenset({"CWE-90", "CWE-643"}),
        (
            "ldap-injection",
            "ldap-query",
            "ldap-search",
            "xpath-injection",
            "xpath-query",
        ),
    ),
    (
        SinkKind.NOSQL_QUERY,
        frozenset({"CWE-943"}),
        (
            "nosql-injection",
            "nosql-query",
            "mongodb-injection",
            "pymongo-query",
            "mongoose-where",
            "couchdb-injection",
        ),
    ),
    (
        SinkKind.TEMPLATE_RENDER,
        frozenset({"CWE-1336"}),
        (
            "ssti",
            "template-injection",
            "render-template-string",
            "jinja2-template",
            "from-string-template",
            "freemarker-ssti",
            "twig-ssti",
            "velocity-ssti",
            "mako-ssti",
        ),
    ),
    (
        SinkKind.SQL_QUERY,
        frozenset({"CWE-89"}),
        (
            "sql-injection",
            "sqli",
            "raw-sql",
            "formatted-sql",
            "sql-string",
            "cursor-execute",
            "jdbc-sqli",
            "sqlalchemy-text",
            "sequelize-query",
        ),
    ),
    (
        SinkKind.OS_COMMAND,
        frozenset({"CWE-78", "CWE-77", "CWE-88"}),
        (
            "command-injection",
            "cmd-injection",
            "cmdi",
            "os-system",
            "subprocess-call",
            "subprocess-popen",
            "child-process-exec",
            "shell-exec",
            "popen-sink",
        ),
    ),
    (
        SinkKind.CODE_EVAL,
        frozenset({"CWE-94", "CWE-95", "CWE-96"}),
        (
            "code-injection",
            "eval-injection",
            "unsafe-eval",
            "eval-use",
            "exec-use",
            "dynamic-code",
            "vm-run",
            "new-function-eval",
        ),
    ),
    (
        SinkKind.PATH_ACCESS,
        frozenset({"CWE-22", "CWE-23", "CWE-36", "CWE-73"}),
        (
            "path-traversal",
            "directory-traversal",
            "file-inclusion",
            "lfi",
            "arbitrary-file-read",
            "arbitrary-file-write",
            "send-file-traversal",
        ),
    ),
    (
        SinkKind.HTML_OUTPUT,
        frozenset({"CWE-79", "CWE-80", "CWE-83"}),
        (
            "xss",
            "cross-site-scripting",
            "dangerouslysetinnerhtml",
            "innerhtml-sink",
            "v-html",
            "mark-safe",
            "unescaped-html",
            "response-write-xss",
            "document-write-xss",
        ),
    ),
)


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

    for kind, tier_cwes, tokens in _CLASSIFICATION_TIERS:
        if kind is SinkKind.NOSQL_QUERY:
            cwe_match = "CWE-943" in cwe_strs and not ({"CWE-89", "CWE-90", "CWE-643"} & cwe_strs)
        else:
            cwe_match = bool(tier_cwes & cwe_strs)
        if cwe_match or any(tok in id_tokens for tok in tokens):
            return kind, cwes, None

    return None, cwes, "rule does not map to a supported SinkKind"


__all__ = [
    "_extract_cwes",
    "classify_sink_kind",
    "is_non_sink_finding",
]

