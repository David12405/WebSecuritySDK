"""Request template and auth materialization resolvers for Module 3 adapters."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from typing import Any, Protocol, runtime_checkable

from websecuritycheck.domain.models import ArtifactManifest


@dataclass(frozen=True)
class ResolvedAuthContext:
    """Resolved secret headers/cookies held strictly in adapter memory."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)


@dataclass(frozen=True)
class MaterializedRequest:
    """Reconstructed HTTP request template inputs ready for L6 execution."""

    headers: dict[str, str] = field(default_factory=dict)
    cookies: dict[str, str] = field(default_factory=dict)
    body: str | None = None
    raw_request: str | None = None


@runtime_checkable
class RequestMaterializerProtocol(Protocol):
    """Resolves opaque artifact/auth references without exposing secrets to prompts."""

    def resolve_request(
        self,
        *,
        request_artifact_ref: str | None = None,
        headers_ref: str | None = None,
        body_ref: str | None = None,
        auth_ref: str | None = None,
    ) -> MaterializedRequest: ...

    def record_artifact(self, manifest_dict: dict[str, Any]) -> str: ...

    def get_artifact(self, artifact_ref: str) -> ArtifactManifest | None: ...


class InMemoryRequestMaterializer:
    """Thread-local / run-scoped in-memory resolver and artifact recorder."""

    def __init__(
        self,
        *,
        raw_requests: dict[str, str] | None = None,
        headers_map: dict[str, dict[str, str]] | None = None,
        bodies_map: dict[str, str] | None = None,
        auth_contexts: dict[str, ResolvedAuthContext] | None = None,
    ) -> None:
        self._raw_requests = dict(raw_requests or {})
        self._headers_map = {k: dict(v) for k, v in (headers_map or {}).items()}
        self._bodies_map = dict(bodies_map or {})
        self._auth_contexts = dict(auth_contexts or {})
        self.artifacts: dict[str, ArtifactManifest] = {}

    def register_raw_request(self, artifact_ref: str, raw_http: str) -> None:
        self._raw_requests[artifact_ref] = raw_http

    def register_headers(self, headers_ref: str, headers: dict[str, str]) -> None:
        self._headers_map[headers_ref] = dict(headers)

    def register_body(self, body_ref: str, body: str) -> None:
        self._bodies_map[body_ref] = body

    def register_auth(self, auth_ref: str, context: ResolvedAuthContext) -> None:
        self._auth_contexts[auth_ref] = context

    def resolve_request(
        self,
        *,
        request_artifact_ref: str | None = None,
        headers_ref: str | None = None,
        body_ref: str | None = None,
        auth_ref: str | None = None,
    ) -> MaterializedRequest:
        headers: dict[str, str] = {}
        cookies: dict[str, str] = {}
        body: str | None = None
        raw_request: str | None = None

        if request_artifact_ref is not None:
            raw_request = self._raw_requests.get(request_artifact_ref)
            if raw_request is None and request_artifact_ref in self.artifacts:
                raw_request = _extract_raw_from_artifact(self.artifacts[request_artifact_ref])

        if headers_ref is not None and headers_ref in self._headers_map:
            headers.update(self._headers_map[headers_ref])

        if body_ref is not None and body_ref in self._bodies_map:
            body = self._bodies_map[body_ref]

        if auth_ref is not None:
            auth = self._auth_contexts.get(auth_ref)
            if auth is not None:
                headers.update(auth.headers)
                cookies.update(auth.cookies)

        return MaterializedRequest(
            headers=headers,
            cookies=cookies,
            body=body,
            raw_request=raw_request,
        )

    def record_artifact(self, manifest_dict: dict[str, Any]) -> str:
        manifest = ArtifactManifest.model_validate(manifest_dict)
        self.artifacts[manifest.artifact_ref] = manifest
        return manifest.artifact_ref

    def get_artifact(self, artifact_ref: str) -> ArtifactManifest | None:
        return self.artifacts.get(artifact_ref)


def _extract_raw_from_artifact(manifest: ArtifactManifest) -> str | None:
    if not manifest.content:
        return None
    if manifest.media_type == "message/http":
        return manifest.content
    if manifest.media_type == "application/json":
        try:
            payload = json.loads(manifest.content)
        except json.JSONDecodeError:
            return None
        if isinstance(payload, dict) and isinstance(payload.get("raw_request"), str):
            return payload["raw_request"]
    return None
