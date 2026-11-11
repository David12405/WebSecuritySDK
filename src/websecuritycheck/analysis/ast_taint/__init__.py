"""Deterministic intra-procedural AST taint and def-use tracer (Step 2).

Performs flow-sensitive backward def-use slicing from a sink candidate line
within the enclosing handler/function scope using Tree-sitter (JS/TS) and Python's
standard-library `ast` module.
"""

from __future__ import annotations

from .models import (
    AST_TAINT_PRODUCER_ID,
    METHOD_AST_TAINT_V1,
    METHOD_DIGEST_AST_TAINT_V1,
    REVIEWED_AST_TAINT_PRODUCER,
    AstTaintTraceResult,
    ResolvedTaintInput,
    TrustedTaintProducer,
    extract_handler_code_slice,
)
from .python_tracer import trace_intraprocedural_sink_taint

__all__ = [
    "AST_TAINT_PRODUCER_ID",
    "METHOD_AST_TAINT_V1",
    "METHOD_DIGEST_AST_TAINT_V1",
    "REVIEWED_AST_TAINT_PRODUCER",
    "AstTaintTraceResult",
    "ResolvedTaintInput",
    "TrustedTaintProducer",
    "extract_handler_code_slice",
    "trace_intraprocedural_sink_taint",
]
