"""Route binding models, producer registration constants, and path helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass

from pydantic import BaseModel, ConfigDict, Field

from websecuritycheck.domain import ArtifactManifest, EvidenceArtifactRecord
from websecuritycheck.domain.analysis_models import EvidenceId, StrictModel


class RouteBindingArtifactRef(BaseModel):
    """Data-plane reference to a RouteHandlerBinding artifact and manifest."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    evidence_ref: EvidenceId
    manifest: ArtifactManifest


class TrustedRouteProducer(BaseModel):
    """Registered trusted producer capable of emitting verified RouteHandlerBinding artifacts."""

    model_config = ConfigDict(extra="forbid", frozen=True)

    producer_id: str = Field(min_length=1)
    approved_methods: frozenset[str]
    approved_method_digests: frozenset[str]
    review_ref: str = Field(min_length=1)


STATIC_ROUTE_PRODUCER_ID = "static_route_extractor"

METHOD_CLOUDFLARE_WORKER = "cloudflare_worker_ast_v1"
METHOD_JS_ROUTER = "js_router_call_ast_v1"
METHOD_PY_DECORATOR = "python_decorator_ast_v1"

METHOD_DIGEST_CLOUDFLARE_WORKER = hashlib.sha256(
    b"websecuritycheck.route_binding.cloudflare_worker_ast_v1"
).hexdigest()
METHOD_DIGEST_JS_ROUTER = hashlib.sha256(
    b"websecuritycheck.route_binding.js_router_call_ast_v1"
).hexdigest()
METHOD_DIGEST_PY_DECORATOR = hashlib.sha256(
    b"websecuritycheck.route_binding.python_decorator_ast_v1"
).hexdigest()

REVIEWED_STATIC_ROUTE_PRODUCER = TrustedRouteProducer(
    producer_id=STATIC_ROUTE_PRODUCER_ID,
    approved_methods=frozenset(
        {
            METHOD_CLOUDFLARE_WORKER,
            METHOD_JS_ROUTER,
            METHOD_PY_DECORATOR,
        }
    ),
    approved_method_digests=frozenset(
        {
            METHOD_DIGEST_CLOUDFLARE_WORKER,
            METHOD_DIGEST_JS_ROUTER,
            METHOD_DIGEST_PY_DECORATOR,
        }
    ),
    review_ref="SEC-REV-M2-T03B-001",
)

_PATH_PARAM_RE = re.compile(r"\{[^}]+\}|:[a-zA-Z0-9_-]+|<(?:[a-zA-Z0-9_-]+:)?[a-zA-Z0-9_-]+>")


@dataclass(frozen=True, slots=True)
class ExtractedRawRoute:
    """Raw route handler candidate extracted directly from an AST."""

    path_template: str
    file_path: str
    start_line: int
    end_line: int
    extraction_method: str
    extraction_method_digest: str
    methods: tuple[str, ...] = ()


class RouteBindingExtractionResult(StrictModel):
    """Deterministic output of Module 2 route binding extraction."""

    route_binding_artifacts: tuple[RouteBindingArtifactRef, ...] = ()
    analysis_evidence_records: tuple[EvidenceArtifactRecord, ...] = ()
    artifact_manifests: tuple[ArtifactManifest, ...] = ()
    source_revision: str | None = None
    source_tree_sha256: str | None = None
    execution_ref: str | None = None
    limitations: tuple[str, ...] = ()
    warnings: tuple[str, ...] = ()


def _normalize_path_segments(path_str: str) -> tuple[str, ...]:
    """Split path into normalized segments with dynamic parameters replaced by '{}'."""
    clean = path_str.strip().split("?")[0].strip("/")
    if not clean:
        return ("",)
    segments = []
    for part in clean.split("/"):
        if _PATH_PARAM_RE.fullmatch(part) or part == "{param}":
            segments.append("{}")
        else:
            segments.append(part)
    return tuple(segments)


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
    "_normalize_path_segments",
]
