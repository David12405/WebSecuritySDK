"""Module 3 baseline HTTP_REQUEST adapter wrapping Layer 6 ``probes.probe_http``."""

from __future__ import annotations

import time
from collections.abc import Awaitable, Callable, Sequence
from typing import Any

from mcp_servers.websec_tools import probes as l6_probes
from mcp_servers.websec_tools.errors import ToolError
from websecuritycheck.domain.enums import CapabilityType
from websecuritycheck.domain.models import ExecutionPolicy
from websecuritycheck.policy.scope_guard import in_scope

from .models import (
    CapabilityExecutionStatus,
    HttpRequestCapabilityInput,
    HttpRequestCapabilityOutput,
)
from .resolvers import InMemoryRequestMaterializer, RequestMaterializerProtocol

ProbeCallable = Callable[..., Awaitable[dict[str, Any]]]

_WAF_SIGNATURES = (
    "access denied",
    "attention required! | cloudflare",
    "cloudflare ray id",
    "blocked by waf",
    "request blocked",
    "web application firewall",
    "mod_security",
)
_AUTH_SIGNATURES = (
    "unauthorized",
    "authentication required",
    "session expired",
    "please log in",
    "invalid token",
)


def _is_waf_blocked(status: int, headers: dict[str, str], body_text: str | None) -> bool:
    if any(key.startswith("cf-mitigated") or "waf" in key for key in headers):
        return True
    if status in {403, 406, 503} and body_text:
        lowered = body_text.casefold()
        return any(sig in lowered for sig in _WAF_SIGNATURES)
    return False


def _is_auth_failure(status: int, redirects: list[dict[str, Any]], body_text: str | None) -> bool:
    if status == 401:
        return True
    for hop in redirects:
        dest = str(hop.get("to") or "").casefold()
        if "/login" in dest or "/signin" in dest:
            return True
    if status == 403 and body_text:
        lowered = body_text.casefold()
        return any(sig in lowered for sig in _AUTH_SIGNATURES)
    return False


def _samples_are_stable(samples: list[dict[str, Any]], latencies_ms: list[float]) -> bool:
    if len(samples) < 2:
        return False
    statuses = {int(sample["status"]) for sample in samples}
    if len(statuses) != 1:
        return False

    sizes = [int(sample.get("response_body_size", 0)) for sample in samples]
    max_size = max(sizes)
    min_size = min(sizes)
    if max_size > 0 and (max_size - min_size) > max(256, int(max_size * 0.25)):
        return False

    if latencies_ms:
        min_lat = max(latencies_ms[0], 1.0)
        if max(latencies_ms) > max(min_lat * 5.0, 2000.0):
            return False
    return True


class HttpBaselineAdapter:
    """Adapter implementing ``ValidationCapability``/``HTTP_REQUEST`` baseline checks."""

    def __init__(
        self,
        *,
        authorized_scope: Sequence[str] | None = None,
        policy: ExecutionPolicy | None = None,
        materializer: RequestMaterializerProtocol | None = None,
        probe_fn: ProbeCallable | None = None,
    ) -> None:
        self._scope = list(authorized_scope) if authorized_scope is not None else None
        self._policy = policy
        self._materializer = materializer or InMemoryRequestMaterializer()
        self._probe_fn = probe_fn or l6_probes.probe_http

    @property
    def materializer(self) -> RequestMaterializerProtocol:
        return self._materializer

    async def execute(self, request: HttpRequestCapabilityInput) -> HttpRequestCapabilityOutput:
        """Send 1..3 benign baseline requests and evaluate target stability."""

        if self._scope is not None:
            decision = in_scope(request.target_url, self._scope)
            if not decision.allowed:
                return HttpRequestCapabilityOutput(
                    execution_status=CapabilityExecutionStatus.FAILED,
                    http_status=None,
                    reachable=False,
                    auth_failure_detected=None,
                    rate_limited=None,
                    waf_or_filter_detected=None,
                    target_stable=None,
                    baseline_ready=False,
                    artifact_refs=[],
                    error_code="E_SCOPE",
                )

        if (
            self._policy is not None
            and CapabilityType.HTTP_REQUEST in self._policy.blocked_capabilities
        ):
            return HttpRequestCapabilityOutput(
                execution_status=CapabilityExecutionStatus.FAILED,
                http_status=None,
                reachable=False,
                auth_failure_detected=None,
                rate_limited=None,
                waf_or_filter_detected=None,
                target_stable=None,
                baseline_ready=False,
                artifact_refs=[],
                error_code="E_SCOPE",
            )

        materialized = self._materializer.resolve_request(
            request_artifact_ref=request.request_artifact_ref,
            headers_ref=request.headers_ref,
            body_ref=request.body_ref,
            auth_ref=request.auth_ref,
        )
        headers = dict(materialized.headers)
        if materialized.cookies and not any(k.casefold() == "cookie" for k in headers):
            headers["Cookie"] = "; ".join(f"{k}={v}" for k, v in materialized.cookies.items())

        samples: list[dict[str, Any]] = []
        latencies_ms: list[float] = []
        artifact_refs: list[str] = []

        for _ in range(request.sample_count):
            start = time.monotonic()
            try:
                envelope_res = await self._probe_fn(
                    request.target_url,
                    method=request.method,
                    headers=headers or None,
                    body=materialized.body,
                )
            except ToolError as exc:
                status = (
                    CapabilityExecutionStatus.TIMEOUT
                    if exc.code == "E_TIMEOUT"
                    else CapabilityExecutionStatus.FAILED
                )
                return HttpRequestCapabilityOutput(
                    execution_status=status,
                    http_status=None,
                    reachable=False,
                    auth_failure_detected=None,
                    rate_limited=None,
                    waf_or_filter_detected=None,
                    target_stable=None,
                    baseline_ready=False,
                    artifact_refs=artifact_refs,
                    error_code=exc.code,
                )
            latencies_ms.append((time.monotonic() - start) * 1000.0)
            data = envelope_res.get("data") or {}
            samples.append(data)
            for manifest in data.get("artifact_manifests") or []:
                ref = self._materializer.record_artifact(manifest)
                if ref not in artifact_refs:
                    artifact_refs.append(ref)

        last = samples[-1]
        http_status = int(last["status"])
        auth_failed = any(
            _is_auth_failure(
                int(s["status"]),
                s.get("redirects") or [],
                s.get("response_body_text"),
            )
            for s in samples
        )
        rate_limited = any(
            int(s["status"]) == 429 or "retry-after" in (s.get("response_headers") or {})
            for s in samples
        )
        waf_detected = any(
            _is_waf_blocked(
                int(s["status"]), s.get("response_headers") or {}, s.get("response_body_text")
            )
            for s in samples
        )

        # Three-valued logic: null if sample_count < 2 per docs/CAPABILITY_CONTRACTS.md
        target_stable: bool | None = (
            None if request.sample_count < 2 else _samples_are_stable(samples, latencies_ms)
        )
        baseline_ready = (
            target_stable is True
            and not auth_failed
            and not rate_limited
            and not waf_detected
        )

        return HttpRequestCapabilityOutput(
            execution_status=CapabilityExecutionStatus.COMPLETED,
            http_status=http_status,
            reachable=True,
            auth_failure_detected=auth_failed,
            rate_limited=rate_limited,
            waf_or_filter_detected=waf_detected,
            target_stable=target_stable,
            baseline_ready=baseline_ready,
            artifact_refs=artifact_refs,
            error_code=None,
        )
