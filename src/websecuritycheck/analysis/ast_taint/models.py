"""Models, provenance constants, file safety helpers, and code slicing for AST taint analysis."""

from __future__ import annotations

import hashlib
import re
from pathlib import Path

from pydantic import BaseModel, ConfigDict, Field

from mcp_servers.websec_tools.analysis.source import is_exposure_safe
from websecuritycheck.domain.analysis_models import SinkKind, StrictModel
from websecuritycheck.domain.enums import InputLocation


class TrustedTaintProducer(BaseModel):
    """Registered trusted producer capable of emitting deterministic AST taint traces."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    producer_id: str = Field(min_length=1)
    approved_methods: frozenset[str]
    approved_method_digests: frozenset[str]
    review_ref: str = Field(min_length=1)


AST_TAINT_PRODUCER_ID = "ast_intraprocedural_taint"
METHOD_AST_TAINT_V1 = "ast_intraprocedural_taint_v1"
METHOD_DIGEST_AST_TAINT_V1 = hashlib.sha256(
    b"websecuritycheck.ast_taint.intraprocedural_v1"
).hexdigest()

REVIEWED_AST_TAINT_PRODUCER = TrustedTaintProducer(
    producer_id=AST_TAINT_PRODUCER_ID,
    approved_methods=frozenset({METHOD_AST_TAINT_V1}),
    approved_method_digests=frozenset({METHOD_DIGEST_AST_TAINT_V1}),
    review_ref="SEC-REV-M2-AST-TAINT-001",
)

_SAFE_SANITIZER_REGEXES = (
    r"\^\\d\+[$\\]",
    r"\^\[0-9\]\+[$\\]",
    r"\^\\d\{",
    r"\^\[a-zA-Z0-9_-\]\+[$\\]",
    r"\^\\w\+[$\\]",
)
_NUMERIC_COERCION_FUNCS = frozenset({"parseInt", "parseFloat", "Number", "int", "float"})
_STRING_PROPAGATOR_METHODS = frozenset(
    {
        "trim",
        "trimStart",
        "trimEnd",
        "toLowerCase",
        "toUpperCase",
        "toString",
        "valueOf",
        "slice",
        "substring",
        "replace",
        "strip",
        "lstrip",
        "rstrip",
        "lower",
        "upper",
        "format",
    }
)
_JS_SUFFIXES = frozenset({".js", ".jsx", ".mjs", ".cjs"})
_TS_SUFFIXES = frozenset({".ts", ".tsx"})
_PATH_TEMPLATE_PARAM_RE = re.compile(
    r"\{([A-Za-z0-9_-]+)\}|:([A-Za-z0-9_-]+)|<(?:[A-Za-z0-9_-]+:)?([A-Za-z0-9_-]+)>"
)
_SQL_SINK_METHODS = frozenset({"prepare", "query", "execute", "executemany", "raw", "exec"})
_CMDI_SINK_METHODS = frozenset(
    {
        "exec",
        "execSync",
        "spawn",
        "spawnSync",
        "system",
        "popen",
        "run",
        "call",
        "Popen",
        "check_output",
        "check_call",
    }
)
_EVAL_SINK_FUNCS = frozenset({"eval", "Function", "exec", "compile"})
_SAFE_FILE_LIMIT_BYTES = 1_000_000


class ResolvedTaintInput(StrictModel):
    """Concrete input source reached by intra-procedural backward slicing."""

    location: InputLocation
    parameter_name: str = Field(min_length=1)
    accessor_snippet: str = Field(min_length=1)
    source_file: str = ""
    source_line: int = Field(ge=1)
    propagation_steps: tuple[str, ...] = ()


class AstTaintTraceResult(StrictModel):
    """Deterministic output of intra-procedural AST taint analysis for one sink."""

    file_path: str
    sink_line: int = Field(ge=1)
    sink_kind: SinkKind
    handler_start_line: int | None = Field(default=None, ge=1)
    handler_end_line: int | None = Field(default=None, ge=1)
    sink_code_line: str | None = None
    has_taint_flow: bool = False
    is_sanitized_or_parameterized: bool = False
    sanitization_reason: str | None = None
    resolved_sources: tuple[ResolvedTaintInput, ...] = ()
    dataflow_steps: tuple[str, ...] = ()
    candidate_input_names_in_handler: tuple[str, ...] = ()
    producer_id: str = AST_TAINT_PRODUCER_ID
    method: str = METHOD_AST_TAINT_V1
    method_digest: str = METHOD_DIGEST_AST_TAINT_V1


def deduplicate_resolved_inputs(items: list[ResolvedTaintInput]) -> tuple[ResolvedTaintInput, ...]:
    """Return deterministically sorted, deduplicated ResolvedTaintInput records."""
    seen: dict[tuple[str, str, int], ResolvedTaintInput] = {}
    for item in items:
        key = (item.location.value, item.parameter_name, item.source_line)
        if key not in seen:
            seen[key] = item
    return tuple(
        sorted(seen.values(), key=lambda x: (x.source_line, x.location.value, x.parameter_name))
    )


def _resolve_repo_file(repo_root: str | Path, file_path: str) -> Path | None:
    """Safely resolve a relative source file inside repo_root without following symlinks."""
    try:
        root = Path(repo_root).resolve(strict=True)
        if not root.is_dir():
            return None
        candidate = root / file_path
        if not candidate.exists() or candidate.is_symlink() or not candidate.is_file():
            return None
        resolved = candidate.resolve(strict=True)
        resolved.relative_to(root)
        for parent in candidate.parents:
            if parent.is_symlink():
                return None
            if parent == root:
                break
        if not is_exposure_safe(resolved):
            return None
        if resolved.stat().st_size > _SAFE_FILE_LIMIT_BYTES:
            return None
        return resolved
    except (OSError, RuntimeError, ValueError):
        return None


def _route_path_params(route_path: str | None) -> list[str]:
    if not route_path:
        return []
    params: list[str] = []
    for m in _PATH_TEMPLATE_PARAM_RE.finditer(route_path):
        name = m.group(1) or m.group(2) or m.group(3)
        if name:
            params.append(name)
    return params


def _regex_guard_is_strict(pattern_text: str) -> bool:
    return any(re.search(pat, pattern_text) for pat in _SAFE_SANITIZER_REGEXES)


def extract_handler_code_slice(
    repo_root: str | Path,
    file_path: str,
    start_line: int,
    end_line: int,
    *,
    sink_line: int | None = None,
    max_lines: int = 45,
) -> str | None:
    """Extract a bounded, numbered code slice around a handler/sink safely from disk."""
    resolved = _resolve_repo_file(repo_root, file_path)
    if resolved is None:
        return None
    try:
        lines = resolved.read_text(encoding="utf-8", errors="replace").splitlines()
    except OSError:
        return None
    if not lines:
        return None

    lo = max(1, start_line)
    hi = min(len(lines), end_line)
    if hi < lo:
        return None
    if hi - lo + 1 > max_lines and sink_line is not None:
        target = max(lo, min(hi, sink_line))
        slice_lo = max(lo, target - (max_lines - 10))
        slice_hi = min(hi, slice_lo + max_lines - 1)
    else:
        slice_lo, slice_hi = lo, min(hi, lo + max_lines - 1)

    return "\n".join(f"{ln}: {lines[ln - 1]}" for ln in range(slice_lo, slice_hi + 1))


__all__ = [
    "AST_TAINT_PRODUCER_ID",
    "METHOD_AST_TAINT_V1",
    "METHOD_DIGEST_AST_TAINT_V1",
    "REVIEWED_AST_TAINT_PRODUCER",
    "_CMDI_SINK_METHODS",
    "_EVAL_SINK_FUNCS",
    "_JS_SUFFIXES",
    "_NUMERIC_COERCION_FUNCS",
    "_SQL_SINK_METHODS",
    "_STRING_PROPAGATOR_METHODS",
    "_TS_SUFFIXES",
    "AstTaintTraceResult",
    "ResolvedTaintInput",
    "TrustedTaintProducer",
    "_regex_guard_is_strict",
    "_resolve_repo_file",
    "_route_path_params",
    "deduplicate_resolved_inputs",
    "extract_handler_code_slice",
]
