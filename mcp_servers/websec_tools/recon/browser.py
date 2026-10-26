"""Bounded Playwright browser exploration for Layer 6."""

from __future__ import annotations

import asyncio
import hashlib
import json
from collections.abc import Awaitable, Callable
from typing import Any
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from ..errors import ToolError, envelope
from ..probes import _validate_target

MAX_ACTIONS = 50
MAX_EVENTS = 1000
MAX_FORMS = 200
MAX_TEXT = 2048


class BrowserActionResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action_id: str
    kind: str
    status: str
    url: str | None = None
    error: str | None = None
    network_event_ids: list[str] = Field(default_factory=list)


class BrowserNetworkEvent(BaseModel):
    model_config = ConfigDict(extra="forbid")
    event_id: str
    url: str
    method: str
    resource_type: str | None = None
    request_content_type: str | None = None
    response_status: int | None = None
    response_content_type: str | None = None
    query_parameter_names: list[str] = Field(default_factory=list)
    request_body_field_names: list[str] = Field(default_factory=list)
    redacted_headers: list[str] = Field(default_factory=list)
    blocked: bool = False
    blocked_reason: str | None = None
    action_id: str | None = None


class BrowserForm(BaseModel):
    model_config = ConfigDict(extra="forbid")
    action: str | None = None
    method: str = "GET"
    enctype: str | None = None
    controls: list[dict[str, Any]] = Field(default_factory=list)


class BrowserRedirect(BaseModel):
    model_config = ConfigDict(extra="forbid")
    from_url: str
    to_url: str
    status: int | None = None
    followed: bool


class BrowserReconResult(BaseModel):
    model_config = ConfigDict(extra="forbid")
    target: str
    final_url: str | None = None
    visited_urls: list[str] = Field(default_factory=list)
    actions: list[BrowserActionResult] = Field(default_factory=list)
    network_events: list[BrowserNetworkEvent] = Field(default_factory=list)
    forms: list[BrowserForm] = Field(default_factory=list)
    redirects: list[BrowserRedirect] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)
    completed: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    truncated: bool = False


def _origin(url: str) -> tuple[str, str, int]:
    parsed = urlsplit(url)
    return parsed.scheme.lower(), (parsed.hostname or "").rstrip(".").lower(), parsed.port or (443 if parsed.scheme == "https" else 80)


def _same_origin(left: str, right: str) -> bool:
    return _origin(left) == _origin(right)


def _header_names(headers: dict[str, str]) -> list[str]:
    return sorted(
        name.lower()
        for name in headers
        if name.lower() in {"authorization", "cookie", "set-cookie", "proxy-authorization"}
        or "token" in name.lower()
        or "secret" in name.lower()
    )


def _body_names(value: str | None, content_type: str | None) -> list[str]:
    if not value:
        return []
    if content_type and "json" in content_type.lower():
        try:
            import json
            parsed = json.loads(value)
        except (ValueError, TypeError):
            return []
        return sorted(str(key) for key in parsed) if isinstance(parsed, dict) else []
    if content_type and "form-urlencoded" in content_type.lower():
        return sorted({part.split("=", 1)[0] for part in value.split("&") if part})
    return []


def _action_kind(action: dict[str, Any]) -> str:
    kind = str(action.get("kind") or "").lower()
    if kind not in {"navigate", "click", "fill", "submit", "wait"}:
        raise ToolError("E_INVALID_ARGUMENT", f"unsupported browser action {kind!r}")
    return kind


async def explore_browser(
    target: str,
    actions: list[dict[str, Any]] | None = None,
    auth_ref: str | None = None,
    *,
    playwright_factory: Callable[[], Awaitable[Any]] | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run bounded declarative, same-origin browser exploration."""
    _validate_target(target)
    requested_actions = actions or []
    if len(requested_actions) > MAX_ACTIONS:
        raise ToolError("E_INVALID_ARGUMENT", f"at most {MAX_ACTIONS} browser actions are allowed")
    if auth_ref and ("=" in auth_ref or "://" in auth_ref):
        raise ToolError("E_INVALID_ARGUMENT", "auth_ref must be an opaque reference")
    try:
        if playwright_factory:
            playwright = await playwright_factory()
            owns_playwright = False
        else:
            try:
                from playwright.async_api import async_playwright
            except ImportError as exc:
                raise ToolError("E_TOOL_UNAVAILABLE", "Playwright is not installed") from exc
            playwright = await async_playwright().start()
            owns_playwright = True
        browser = await playwright.chromium.launch(headless=True)
        context = await browser.new_context()
        page = await context.new_page()
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError("E_TOOL_FAILED", "browser could not be started") from exc

    events: list[dict[str, Any]] = []
    redirects: list[dict[str, Any]] = []
    visited: list[str] = []
    warnings: list[str] = []
    current_action: str | None = None

    async def route_handler(route: Any) -> None:
        request = route.request
        if not _same_origin(target, request.url):
            events.append({"event_id": f"NET-{len(events) + 1:04d}", "url": request.url, "method": request.method, "resource_type": request.resource_type, "blocked": True, "blocked_reason": "out_of_scope", "action_id": current_action})
            await route.abort()
            return
        headers = await request.all_headers()
        content_type = headers.get("content-type")
        query = urlsplit(request.url).query
        events.append({"event_id": f"NET-{len(events) + 1:04d}", "url": request.url, "method": request.method, "resource_type": request.resource_type, "request_content_type": content_type, "query_parameter_names": sorted({part.split("=", 1)[0] for part in query.split("&") if part}), "request_body_field_names": _body_names(request.post_data, content_type), "redacted_headers": _header_names(headers), "blocked": False, "action_id": current_action})
        await route.continue_()

    await page.route("**/*", route_handler)

    async def response_handler(response: Any) -> None:
        for event in reversed(events):
            if event["url"] == response.url and event.get("response_status") is None:
                headers = await response.all_headers()
                event["response_status"] = response.status
                event["response_content_type"] = headers.get("content-type")
                if 300 <= response.status < 400 and headers.get("location"):
                    redirects.append(
                        {
                            "from_url": response.url,
                            "to_url": urljoin(response.url, headers["location"]),
                            "status": response.status,
                            "followed": True,
                        }
                    )
                break

    page.on("response", response_handler)
    result_actions: list[BrowserActionResult] = []
    try:
        await asyncio.wait_for(page.goto(target, wait_until="domcontentloaded"), timeout=timeout_seconds)
        visited.append(page.url)
        for index, action in enumerate(requested_actions):
            kind = _action_kind(action)
            action_id = str(action.get("action_id") or f"ACT-{index + 1:03d}")
            current_action = action_id
            try:
                selector = str(action.get("selector") or "")
                if kind == "navigate":
                    destination = urljoin(page.url, str(action.get("url") or ""))
                    if not _same_origin(target, destination):
                        raise ToolError("E_SCOPE", "browser navigation is outside the initial origin")
                    await page.goto(destination, wait_until="domcontentloaded")
                elif kind == "click":
                    await page.locator(selector).click()
                elif kind == "fill":
                    await page.locator(selector).fill(str(action.get("value") or ""))
                elif kind == "submit":
                    await page.locator(selector).evaluate("element => element.submit()")
                elif kind == "wait":
                    await page.locator(selector).wait_for(state="visible")
                visited.append(page.url)
                result_actions.append(BrowserActionResult(action_id=action_id, kind=kind, status="completed", url=page.url, network_event_ids=[item["event_id"] for item in events if item.get("action_id") == action_id]))
            except ToolError:
                raise
            except Exception as exc:
                result_actions.append(BrowserActionResult(action_id=action_id, kind=kind, status="failed", url=page.url, error=str(exc)[:MAX_TEXT]))
        forms = await page.locator("form").evaluate_all("""forms => forms.slice(0, 200).map(form => ({action: form.action || null, method: (form.method || 'GET').toUpperCase(), enctype: form.enctype || null, controls: Array.from(form.elements).slice(0, 100).map(control => ({name: control.name || null, type: control.type || null, required: !!control.required, disabled: !!control.disabled}))}))""")
        result = BrowserReconResult(target=target, final_url=page.url, visited_urls=sorted(set(visited)), actions=result_actions, network_events=[BrowserNetworkEvent.model_validate(item) for item in events[:MAX_EVENTS]], forms=[BrowserForm.model_validate(item) for item in forms[:MAX_FORMS]], redirects=[BrowserRedirect.model_validate(item) for item in redirects], completed=True, warnings=warnings, truncated=len(events) > MAX_EVENTS)
    except asyncio.TimeoutError:
        result = BrowserReconResult(target=target, final_url=page.url, visited_urls=sorted(set(visited)), actions=result_actions, network_events=[BrowserNetworkEvent.model_validate(item) for item in events[:MAX_EVENTS]], forms=[], redirects=[], completed=False, errors=["E_TIMEOUT"], truncated=len(events) > MAX_EVENTS)
    except ToolError:
        raise
    except Exception as exc:
        result = BrowserReconResult(target=target, final_url=page.url, visited_urls=sorted(set(visited)), actions=result_actions, network_events=[BrowserNetworkEvent.model_validate(item) for item in events[:MAX_EVENTS]], forms=[], redirects=[], completed=False, errors=[str(exc)[:MAX_TEXT]])
    finally:
        await context.close()
        await browser.close()
        if owns_playwright:
            await playwright.stop()
    trace_metadata = {
        "event_count": len(result.network_events),
        "action_count": len(result.actions),
        "form_count": len(result.forms),
        "redirect_count": len(result.redirects),
    }
    trace_ref = f"browser-trace-{hashlib.sha256(json.dumps(trace_metadata, sort_keys=True).encode()).hexdigest()[:16]}"
    result.artifact_manifests = [{
        "artifact_ref": trace_ref,
        "artifact_type": "BROWSER_TRACE",
        "media_type": "application/json",
        "redaction_applied": True,
        "truncated": result.truncated,
        "metadata": trace_metadata,
    }]
    return envelope(f"Browser explored {len(result.visited_urls)} URLs from {target}", result.model_dump(mode="json"), result.truncated)
