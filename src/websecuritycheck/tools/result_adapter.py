"""Translate Strands tool events into canonical executions and recon updates."""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from strands.hooks import AfterToolCallEvent, HookRegistry

from ..domain import ToolExecutionResult, ToolExecutionStatus
from ..memory.target_store import TargetStore
from ..recon import process_tool_result
from ..results.models import ErrorInfo

ADAPTER_ORDER = 0
FRAMEWORK_RESULT_TOOLS = frozenset({"retrieve_context"})

RESULT_TYPES = {
    "probe_http": "HTTPProbeResult",
    "get_response_headers": "HTTPProbeResult",
    "get_cookies": "HTTPProbeResult",
    "get_tls_info": "HTTPProbeResult",
    "get_cors_policy": "HTTPProbeResult",
    "discover_hosts": "NMAP_SCAN",
    "discover_services": "NMAP_SCAN",
    "crawl_web": "ZAP_CRAWL",
    "passive_web_analysis": "ZAP_PASSIVE",
    "fingerprint_web": "WHATWEB_FINGERPRINT",
    "parse_api_spec": "OPENAPI_SPEC",
    "explore_browser": "BROWSER_FLOW",
    "collect_proxy_traffic": "ZAP_PROXY_TRAFFIC",
}


def _text(result: Any) -> str:
    if not isinstance(result, dict):
        return ""
    return "\n".join(
        str(block["text"])
        for block in result.get("content") or []
        if isinstance(block, dict) and "text" in block
    )


def _payload(result: Any) -> dict[str, Any]:
    if not isinstance(result, dict):
        return {}
    structured = result.get("structuredContent") or result.get("structured_content")
    if isinstance(structured, dict):
        return structured
    raw = _text(result)
    try:
        value = json.loads(raw)
    except (TypeError, ValueError):
        return {"summary": raw}
    return value if isinstance(value, dict) else {"data": value}


@dataclass
class ToolResultAdapter:
    assessment_id: str
    store: TargetStore
    exempt: frozenset[str] = frozenset()
    execution_refs: dict[str, str] = field(default_factory=dict)
    errors: list[ErrorInfo] = field(default_factory=list)

    def register_hooks(self, registry: HookRegistry, **kwargs: Any) -> None:
        registry.add_callback(AfterToolCallEvent, self.after_tool_call, order=ADAPTER_ORDER)

    def after_tool_call(self, event: AfterToolCallEvent) -> None:
        name = event.tool_use.get("name") or ""
        if name in FRAMEWORK_RESULT_TOOLS or name in self.exempt or not name:
            return
        tool_use_id = event.tool_use.get("toolUseId") or ""
        execution_id = self.store.allocate_execution_id(self.assessment_id)
        if tool_use_id:
            self.execution_refs[tool_use_id] = execution_id
        raw_input = event.tool_use.get("input") or {}
        target = raw_input.get("target") if isinstance(raw_input, dict) else None
        result = event.result if isinstance(event.result, dict) else {}
        failed = bool(
            result.get("status") == "error"
            or result.get("isError")
            or result.get("is_error")
        )
        payload = _payload(result)
        now = datetime.now(UTC)
        execution = ToolExecutionResult(
            execution_id=execution_id,
            assessment_id=self.assessment_id,
            tool_id=name,
            target=target if isinstance(target, str) else None,
            result_type=RESULT_TYPES.get(name, name.upper()),
            result_data=payload,
            status=ToolExecutionStatus.FAILED if failed else ToolExecutionStatus.COMPLETED,
            started_at=now,
            finished_at=now,
            truncated=bool(payload.get("truncated")),
            errors=[_text(result)] if failed and _text(result) else [],
        )
        processing = None
        if not failed and isinstance(target, str):
            try:
                current = self.store.load_target(self.assessment_id, target)
                # The stable per-site id, so a fresh model does not default to
                # TGT-001 and collide with another site under this assessment.
                # The store keys it on the origin, so every URL of one site
                # resolves to the same id and merges into the same model.
                target_id = self.store.target_id_for(self.assessment_id, target)
                processing = process_tool_result(
                    execution, current_target_model=current, target_id=target_id
                )
            except Exception as exc:
                self.errors.append(
                    ErrorInfo(
                        kind="validation",
                        message=f"could not process {name}: {type(exc).__name__}: {exc}",
                        tool=name,
                        code="E_RECON_PROCESSING",
                        execution_ref=execution_id,
                    )
                )
        try:
            self.store.persist(execution, processing)
        except Exception as exc:
            self.errors.append(
                ErrorInfo(
                    kind="storage",
                    message=f"could not persist {execution_id}: {type(exc).__name__}: {exc}",
                    tool=name,
                    code="E_STORAGE",
                    execution_ref=execution_id,
                )
            )
