"""Stateless ZAP Spider and Passive Scanner tools for Layer 6."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import re
import uuid
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import parse_qsl, urlsplit

import httpx
from pydantic import BaseModel, ConfigDict, Field

from ..errors import ToolError, envelope, safe_message
from ..probes import _validate_target

ZAP_TIMEOUT_SECONDS = 300.0
ZAP_POLL_SECONDS = 0.2
MAX_ENDPOINTS = 1000
MAX_SIGNALS = 500
MAX_TEXT = 2048
ZapRequester = Callable[[str, dict[str, str]], Awaitable[dict[str, Any]]]


class CrawledEndpoint(BaseModel):
    model_config = ConfigDict(extra="forbid")

    url: str
    scheme: str
    host: str
    port: int | None = None
    path: str
    query_parameter_names: list[str] = Field(default_factory=list)
    method: str | None = None
    status: int | None = None
    content_type: str | None = None
    body_parameter_names: list[str] = Field(default_factory=list)
    source: str = "zap_spider"


class CrawlResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    spider: str = "traditional"
    completed: bool
    endpoints: list[CrawledEndpoint] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)


class PassiveSecuritySignal(BaseModel):
    model_config = ConfigDict(extra="forbid")

    plugin_id: str
    name: str
    risk: str
    confidence: str
    url: str
    method: str | None = None
    parameter: str | None = None
    cwe_id: int | None = None
    wasc_id: int | None = None
    description: str | None = None


class PassiveAnalysisResult(BaseModel):
    model_config = ConfigDict(extra="forbid")

    target: str
    spider_completed: bool
    passive_queue_drained: bool
    signals: list[PassiveSecuritySignal] = Field(default_factory=list)


class _ZapClient:
    def __init__(
        self,
        base_url: str,
        api_key: str | None,
        *,
        http_client: httpx.AsyncClient | None = None,
        requester: ZapRequester | None = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.api_key = api_key
        self.http_client = http_client
        self.requester = requester
        self._owned = False

    async def __aenter__(self) -> _ZapClient:
        if self.requester is None and self.http_client is None:
            self.http_client = httpx.AsyncClient(timeout=10.0)
            self._owned = True
        return self

    async def __aexit__(self, *_exc: object) -> None:
        if self._owned and self.http_client is not None:
            await self.http_client.aclose()

    async def get(self, path: str, params: dict[str, str] | None = None) -> dict[str, Any]:
        query = dict(params or {})
        if self.api_key:
            query["apikey"] = self.api_key
        if self.requester is not None:
            try:
                result = await self.requester(path, query)
            except ToolError:
                raise
            except TimeoutError as exc:
                raise ToolError("E_TIMEOUT", "ZAP API request timed out") from exc
            except Exception as exc:
                raise ToolError("E_CONNECT", "ZAP API request failed") from exc
            if not isinstance(result, dict):
                raise ToolError("E_PARSE", "ZAP API returned a non-object response")
            return result
        if self.http_client is None:
            raise ToolError("E_TOOL_UNAVAILABLE", "ZAP HTTP client is unavailable")
        try:
            response = await self.http_client.get(f"{self.base_url}{path}", params=query)
            response.raise_for_status()
            result = response.json()
        except httpx.TimeoutException as exc:
            raise ToolError("E_TIMEOUT", "ZAP API request timed out") from exc
        except httpx.HTTPStatusError as exc:
            raise ToolError("E_HTTP", f"ZAP API returned HTTP {exc.response.status_code}") from exc
        except (httpx.HTTPError, ValueError) as exc:
            raise ToolError("E_HTTP", safe_message(exc, "ZAP API request failed")) from exc
        if not isinstance(result, dict):
            raise ToolError("E_PARSE", "ZAP API returned a non-object response")
        return result


def _configuration(base_url: str | None, api_key: str | None) -> tuple[str, str | None]:
    base_url = base_url or os.getenv("WEBSEC_ZAP_BASE_URL")
    api_key = api_key if api_key is not None else os.getenv("WEBSEC_ZAP_API_KEY")
    if not base_url:
        raise ToolError("E_TOOL_UNAVAILABLE", "ZAP base URL is not configured")
    return base_url, api_key


def _origin(target: str) -> tuple[str, str]:
    parsed = urlsplit(target)
    origin = f"{parsed.scheme}://{parsed.netloc}"
    return origin, parsed.hostname or ""


def _same_origin(url: str, origin: str) -> bool:
    parsed = urlsplit(url)
    return f"{parsed.scheme}://{parsed.netloc}" == origin


def _endpoint(url: str) -> CrawledEndpoint | None:
    parsed = urlsplit(url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        return None
    query_names = sorted({key for key, _value in parse_qsl(parsed.query, keep_blank_values=True)})
    return CrawledEndpoint(
        url=url,
        scheme=parsed.scheme,
        host=parsed.hostname,
        port=parsed.port,
        path=parsed.path or "/",
        query_parameter_names=query_names,
    )


def _endpoint_record(value: Any) -> CrawledEndpoint | None:
    if isinstance(value, str):
        return _endpoint(value)
    if not isinstance(value, dict) or not isinstance(value.get("url"), str):
        return None
    item = _endpoint(value["url"])
    if item is None:
        return None
    item.method = str(value["method"]).upper() if value.get("method") else None
    raw_status = value.get("status", value.get("response_status"))
    item.status = int(raw_status) if isinstance(raw_status, int) else None
    raw_content_type = value.get("content_type", value.get("response_content_type"))
    item.content_type = str(raw_content_type) if raw_content_type else None
    raw_body_names = value.get("body_parameter_names", value.get("form_parameter_names", []))
    item.body_parameter_names = sorted(str(name) for name in raw_body_names if name)
    return item


def parse_spider_urls(raw_urls: Any, *, target: str) -> list[CrawledEndpoint]:
    origin = _origin(target)[0]
    if not isinstance(raw_urls, list):
        return []
    values = raw_urls if isinstance(raw_urls, list) else []
    endpoints = [
        item
        for value in values
        if (item := _endpoint_record(value)) is not None and _same_origin(item.url, origin)
    ]
    deduped: dict[tuple[str, str | None], CrawledEndpoint] = {}
    for item in endpoints:
        deduped[(item.url, item.method)] = item
    return [deduped[key] for key in sorted(deduped)]


def parse_passive_alerts(raw_alerts: Any, *, target: str) -> list[PassiveSecuritySignal]:
    signals: list[PassiveSecuritySignal] = []
    for alert in raw_alerts if isinstance(raw_alerts, list) else []:
        if not isinstance(alert, dict):
            continue
        signals.append(
            PassiveSecuritySignal(
                plugin_id=str(alert.get("pluginId", "")),
                name=_limited_text(alert.get("alert"), "Unknown alert") or "Unknown alert",
                risk=_limited_text(alert.get("risk"), "Unknown") or "Unknown",
                confidence=_limited_text(alert.get("confidence"), "Unknown") or "Unknown",
                url=_limited_text(alert.get("url"), target) or target,
                method=_limited_text(alert.get("method")),
                parameter=_limited_text(alert.get("param")),
                cwe_id=int(alert["cweid"]) if str(alert.get("cweid", "")).isdigit() else None,
                wasc_id=int(alert["wascid"]) if str(alert.get("wascid", "")).isdigit() else None,
                description=_limited_text(alert.get("description")),
            )
        )
    return sorted(
        signals,
        key=lambda item: (item.url, item.plugin_id, item.name, item.parameter or ""),
    )


def _context_regex(origin: str) -> str:
    return re.escape(origin) + r"(?:/|$).*"


def _limited_text(value: Any, fallback: str | None = None) -> str | None:
    if not isinstance(value, str):
        return fallback
    return value[:MAX_TEXT]


async def _new_context(client: _ZapClient, target: str) -> str:
    context_name = f"websec-{uuid.uuid4().hex}"
    origin, _host = _origin(target)
    await client.get("/JSON/context/action/newContext/", {"contextName": context_name})
    await client.get(
        "/JSON/context/action/includeInContext/",
        {"contextName": context_name, "regex": _context_regex(origin)},
    )
    return context_name


async def _remove_context(client: _ZapClient, context_name: str) -> None:
    try:
        await client.get("/JSON/context/action/removeContext/", {"contextName": context_name})
    except ToolError:
        return


async def _run_spider(client: _ZapClient, target: str) -> tuple[bool, list[Any], str]:
    context_name = await _new_context(client, target)
    try:
        response = await client.get(
            "/JSON/spider/action/scan/",
            {"url": target, "contextName": context_name, "recurse": "true"},
        )
        scan_id = response.get("scan")
        if not isinstance(scan_id, str):
            raise ToolError("E_PARSE", "ZAP spider response did not contain a scan ID")
        deadline = asyncio.get_running_loop().time() + ZAP_TIMEOUT_SECONDS
        while True:
            status_response = await client.get("/JSON/spider/view/status/", {"scanId": scan_id})
            try:
                status = int(status_response.get("status", 0))
            except (TypeError, ValueError) as exc:
                raise ToolError("E_PARSE", "ZAP spider status was invalid") from exc
            if status >= 100:
                break
            if asyncio.get_running_loop().time() >= deadline:
                raise ToolError("E_TIMEOUT", "ZAP spider timed out")
            await asyncio.sleep(ZAP_POLL_SECONDS)
        result = await client.get("/JSON/spider/view/results/", {"scanId": scan_id})
        raw_urls = result.get("results", [])
        return True, raw_urls if isinstance(raw_urls, list) else [], context_name
    except BaseException:
        await _remove_context(client, context_name)
        raise


async def crawl_web(
    target: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    requester: ZapRequester | None = None,
) -> dict[str, Any]:
    _validate_target(target)
    configured_url, configured_key = _configuration(base_url, api_key)
    async with _ZapClient(
        configured_url, configured_key, http_client=http_client, requester=requester
    ) as client:
        completed, urls, context_name = await _run_spider(client, target)
        await _remove_context(client, context_name)
    endpoints = parse_spider_urls(urls, target=target)
    truncated = len(endpoints) > MAX_ENDPOINTS
    raw_text = json.dumps(urls, sort_keys=True, separators=(",", ":"), default=str)
    result = CrawlResult(
        target=target,
        completed=completed,
        endpoints=endpoints[:MAX_ENDPOINTS],
        artifact_manifests=[
            {
                "artifact_ref": f"zap-crawl-{hashlib.sha256(raw_text.encode()).hexdigest()[:16]}",
                "artifact_type": "WEB_SCAN_RESULT",
                "content": raw_text,
                "media_type": "application/json",
                "redaction_applied": True,
            }
        ],
    )
    return envelope(
        f"ZAP discovered {len(result.endpoints)} endpoints on {target}",
        result.model_dump(mode="json"),
        truncated,
    )


async def passive_web_analysis(
    target: str,
    *,
    base_url: str | None = None,
    api_key: str | None = None,
    http_client: httpx.AsyncClient | None = None,
    requester: ZapRequester | None = None,
) -> dict[str, Any]:
    _validate_target(target)
    configured_url, configured_key = _configuration(base_url, api_key)
    async with _ZapClient(
        configured_url, configured_key, http_client=http_client, requester=requester
    ) as client:
        spider_completed, _urls, context_name = await _run_spider(client, target)
        try:
            deadline = asyncio.get_running_loop().time() + ZAP_TIMEOUT_SECONDS
            while True:
                queue = await client.get("/JSON/pscan/view/recordsToScan/")
                try:
                    remaining = int(queue.get("recordsToScan", 0))
                except (TypeError, ValueError) as exc:
                    raise ToolError("E_PARSE", "ZAP passive queue value was invalid") from exc
                if remaining <= 0:
                    break
                if asyncio.get_running_loop().time() >= deadline:
                    raise ToolError("E_TIMEOUT", "ZAP passive scanner timed out")
                await asyncio.sleep(ZAP_POLL_SECONDS)
            alerts_response = await client.get(
                "/JSON/core/view/alerts/",
                {
                    "baseurl": _origin(target)[0],
                    "start": 0,
                    "count": MAX_SIGNALS + 1,
                },
            )
        finally:
            await _remove_context(client, context_name)
    signals = parse_passive_alerts(alerts_response.get("alerts"), target=target)
    truncated = len(signals) > MAX_SIGNALS
    result = PassiveAnalysisResult(
        target=target,
        spider_completed=spider_completed,
        passive_queue_drained=True,
        signals=signals[:MAX_SIGNALS],
    )
    return envelope(
        f"ZAP passive analysis produced {len(result.signals)} signals for {target}",
        result.model_dump(mode="json"),
        truncated,
    )
