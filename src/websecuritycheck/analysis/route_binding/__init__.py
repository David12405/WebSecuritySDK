"""Deterministic, AST-based Route Binding Extraction (M2-T03b).

Extracts endpoint-to-source-handler bindings (RouteBindingArtifactRef) with
schema "websecuritycheck.route_binding_artifact.v1" using real AST parsers:
- Tree-sitter for JavaScript and TypeScript (Cloudflare Workers and JS/TS routers)
- Python ast module for framework route decorators (Flask, FastAPI, etc.)
"""

from __future__ import annotations

from .binder import extract_route_bindings
from .js_ts_extractor import _extract_js_ts_routes as _extract_js_ts_routes
from .models import (
    METHOD_CLOUDFLARE_WORKER,
    METHOD_DIGEST_CLOUDFLARE_WORKER,
    METHOD_DIGEST_JS_ROUTER,
    METHOD_DIGEST_PY_DECORATOR,
    METHOD_JS_ROUTER,
    METHOD_PY_DECORATOR,
    REVIEWED_STATIC_ROUTE_PRODUCER,
    STATIC_ROUTE_PRODUCER_ID,
    ExtractedRawRoute,
    RouteBindingArtifactRef,
    RouteBindingExtractionResult,
    TrustedRouteProducer,
)
from .models import (
    _normalize_path_segments as _normalize_path_segments,
)
from .python_extractor import _extract_python_routes as _extract_python_routes

__all__ = [
    "METHOD_CLOUDFLARE_WORKER",
    "METHOD_DIGEST_CLOUDFLARE_WORKER",
    "METHOD_DIGEST_JS_ROUTER",
    "METHOD_DIGEST_PY_DECORATOR",
    "METHOD_JS_ROUTER",
    "METHOD_PY_DECORATOR",
    "REVIEWED_STATIC_ROUTE_PRODUCER",
    "STATIC_ROUTE_PRODUCER_ID",
    "ExtractedRawRoute",
    "RouteBindingArtifactRef",
    "RouteBindingExtractionResult",
    "TrustedRouteProducer",
    "extract_route_bindings",
]
