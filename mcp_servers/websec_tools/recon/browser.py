"""Bounded Playwright browser exploration for Layer 6."""

from __future__ import annotations

import asyncio
import hashlib
import json
import os
import time
from collections import deque
from collections.abc import Awaitable, Callable
from pathlib import Path
from typing import Any
from urllib.parse import urljoin, urlsplit

from pydantic import BaseModel, ConfigDict, Field

from .._params import body_parameter_names, query_parameter_names
from .._urls import same_origin as _same_origin
from ..errors import ToolError, envelope
from ..probes import _validate_target
from .browser_rules import (
    MAX_TEXT,
    BrowserReconGap,
    GapRecorder,
    canonical_url_key,
    classify_interactive_element,
    form_dedup_key,
    is_excluded,
    is_navigable_link,
    normalize_form_entry,
    query_signature_key,
    url_origin,
)

MAX_ACTIONS = 50
MAX_EVENTS = 1000
MAX_FORMS = 200
MAX_DOM_INPUTS = 200
MAX_PAGES = 10
MAX_DEPTH = 2
MAX_REPRESENTATIVE_URLS_PER_SIGNATURE = 2

_AUTH_PATH_HINTS = ("/login", "/signin", "/auth")
_DOM_SNAPSHOT_SCRIPT = Path(__file__).with_name("browser_dom.js").read_text(encoding="utf-8")

# Re-export pure rule helpers expected by internal callers/tests.
_origin = url_origin
_canonical_url_key = canonical_url_key
_query_signature_key = query_signature_key
_classify_interactive_element = classify_interactive_element


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
    page_url: str | None = None
    action: str | None = None
    method: str = "GET"
    enctype: str | None = None
    controls: list[dict[str, Any]] = Field(default_factory=list)


class BrowserDomInput(BaseModel):
    model_config = ConfigDict(extra="forbid")
    page_url: str
    name: str
    input_type: str | None = None
    required: bool = False
    disabled: bool = False


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
    dom_inputs: list[BrowserDomInput] = Field(default_factory=list)
    redirects: list[BrowserRedirect] = Field(default_factory=list)
    recon_gaps: list[BrowserReconGap] = Field(default_factory=list)
    artifact_manifests: list[dict[str, Any]] = Field(default_factory=list)
    completed: bool = False
    warnings: list[str] = Field(default_factory=list)
    errors: list[str] = Field(default_factory=list)
    truncated: bool = False


def _trusted_proxy() -> dict[str, str] | None:
    value = os.getenv("WEBSEC_ZAP_PROXY_URL", "").strip()
    if not value:
        return None
    try:
        _validate_target(value)
    except ToolError:
        raise ToolError("E_INVALID_ARGUMENT", "configured browser proxy URL is invalid") from None
    parsed = urlsplit(value)
    port = parsed.port
    if (
        parsed.scheme.lower() not in {"http", "https"}
        or not parsed.hostname
        or parsed.username is not None
        or parsed.password is not None
        or parsed.query
        or parsed.fragment
        or parsed.path not in {"", "/"}
    ):
        raise ToolError("E_INVALID_ARGUMENT", "configured browser proxy URL is invalid")
    host = parsed.hostname
    if ":" in host and not host.startswith("["):
        host = f"[{host}]"
    server = f"{parsed.scheme.lower()}://{host}"
    if port is not None:
        server += f":{port}"
    return {"server": server}


def _header_names(headers: dict[str, str]) -> list[str]:
    return sorted(
        name.lower()
        for name in headers
        if name.lower() in {"authorization", "cookie", "set-cookie", "proxy-authorization"}
        or "token" in name.lower()
        or "secret" in name.lower()
    )


def _body_names(value: str | bytes | None, content_type: str | None) -> list[str]:
    return body_parameter_names(value, content_type, max_length=MAX_TEXT)


def _action_kind(action: dict[str, Any]) -> str:
    kind = str(action.get("kind") or "").lower()
    if kind not in {"navigate", "click", "fill", "submit", "wait"}:
        raise ToolError("E_INVALID_ARGUMENT", f"unsupported browser action {kind!r}")
    return kind


class _NetworkRecorder:
    """Stateful network interceptor, lifecycle tracker, and request_budget enforcer."""

    def __init__(self, target: str, excluded_scope: list[str], request_budget: int) -> None:
        self.target = target
        self.excluded_scope = excluded_scope
        self.request_budget = request_budget
        self.events: list[dict[str, Any]] = []
        self.redirects: list[dict[str, Any]] = []
        self.document_status_by_url: dict[str, int] = {}
        self.in_flight_requests: set[int] = set()
        self.dispatched_requests = 0
        self.budget_exhausted = False
        self.current_action: str | None = None

    async def attach(self, page: Any) -> None:
        await page.route("**/*", self.route_handler)
        page.on("request", self.on_request)
        page.on("response", self.response_handler)
        page.on("requestfinished", self.on_request_done)
        page.on("requestfailed", self.on_request_done)

    def on_request(self, request: Any) -> None:
        if _same_origin(self.target, request.url) and not is_excluded(
            request.url, self.excluded_scope
        ):
            self.in_flight_requests.add(id(request))

    def on_request_done(self, request: Any) -> None:
        self.in_flight_requests.discard(id(request))

    async def route_handler(self, route: Any) -> None:
        request = route.request
        if not _same_origin(self.target, request.url) or is_excluded(
            request.url, self.excluded_scope
        ):
            self.in_flight_requests.discard(id(request))
            self.events.append(
                {
                    "event_id": f"NET-{len(self.events) + 1:04d}",
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "blocked": True,
                    "blocked_reason": "out_of_scope",
                    "action_id": self.current_action,
                }
            )
            await route.abort()
            return
        if self.dispatched_requests >= self.request_budget:
            self.in_flight_requests.discard(id(request))
            self.budget_exhausted = True
            self.events.append(
                {
                    "event_id": f"NET-{len(self.events) + 1:04d}",
                    "url": request.url,
                    "method": request.method,
                    "resource_type": request.resource_type,
                    "blocked": True,
                    "blocked_reason": "request_budget_exceeded",
                    "action_id": self.current_action,
                }
            )
            await route.abort()
            return
        self.dispatched_requests += 1
        headers = await request.all_headers()
        content_type = headers.get("content-type")
        self.events.append(
            {
                "event_id": f"NET-{len(self.events) + 1:04d}",
                "url": request.url,
                "method": request.method,
                "resource_type": request.resource_type,
                "request_content_type": content_type,
                "query_parameter_names": query_parameter_names(request.url, max_length=MAX_TEXT),
                "request_body_field_names": _body_names(request.post_data, content_type),
                "redacted_headers": _header_names(headers),
                "blocked": False,
                "action_id": self.current_action,
            }
        )
        await route.continue_()

    async def response_handler(self, response: Any) -> None:
        headers = await response.all_headers()
        if getattr(getattr(response, "request", None), "resource_type", None) == "document":
            self.document_status_by_url[str(response.url)] = response.status
        else:
            self.document_status_by_url.setdefault(str(response.url), response.status)
        if 300 <= response.status < 400 and headers.get("location"):
            self.redirects.append(
                {
                    "from_url": response.url,
                    "to_url": urljoin(response.url, headers["location"]),
                    "status": response.status,
                    "followed": True,
                }
            )
        for event in reversed(self.events):
            if event["url"] == response.url and event.get("response_status") is None:
                event["response_status"] = response.status
                event["response_content_type"] = headers.get("content-type")
                break

    def events_for_action(self, action_id: str) -> list[str]:
        return [item["event_id"] for item in self.events if item.get("action_id") == action_id]


async def _inspect_page_dom(page: Any, target: str) -> dict[str, Any]:
    current_url = str(getattr(page, "url", "") or target)
    if hasattr(page, "evaluate"):
        try:
            snapshot = await page.evaluate(_DOM_SNAPSHOT_SCRIPT)
            if isinstance(snapshot, dict):
                snapshot.setdefault("page_url", current_url)
                snapshot.setdefault("forms", [])
                snapshot.setdefault("dom_inputs", [])
                snapshot.setdefault("links", [])
                snapshot.setdefault("interactive", [])
                return snapshot
        except Exception:
            pass
    try:
        raw_forms = await page.locator("form").evaluate_all(
            """forms => forms.slice(0, 200).map(form => ({
                action: form.action || null,
                method: (form.method || 'GET').toUpperCase(),
                enctype: form.enctype || null,
                controls: Array.from(form.elements).slice(0, 100).map(control => ({
                    name: control.name || null,
                    type: control.type || null,
                    required: !!control.required,
                    disabled: !!control.disabled
                }))
            }))"""
        )
    except Exception:
        raw_forms = []
    return {
        "page_url": current_url,
        "forms": raw_forms if isinstance(raw_forms, list) else [],
        "dom_inputs": [],
        "links": [],
        "interactive": [],
        "has_captcha": False,
        "captcha_selector": None,
        "has_password_input": False,
    }


async def _settle_page(
    page: Any,
    in_flight_requests: set[int],
    *,
    max_wait_seconds: float = 0.5,
    poll_interval_seconds: float = 0.05,
) -> None:
    """Wait briefly until in-flight requests finish and interactive DOM stabilizes."""
    deadline = time.monotonic() + max_wait_seconds
    last_dom_count: int | None = None
    stable_ticks = 0
    while True:
        dom_count: int | None = None
        if hasattr(page, "evaluate"):
            try:
                count_val = await page.evaluate(
                    "() => document.querySelectorAll("
                    "'form, input, select, textarea, button, a[href], "
                    "[role=\"tab\"], [role=\"button\"], [role=\"menuitem\"]').length"
                )
                if isinstance(count_val, int):
                    dom_count = count_val
            except Exception:
                dom_count = None
        if dom_count is not None and dom_count == last_dom_count:
            stable_ticks += 1
        else:
            stable_ticks = 0
        last_dom_count = dom_count

        if not in_flight_requests and (dom_count is None or stable_ticks >= 1):
            break
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        await asyncio.sleep(min(poll_interval_seconds, remaining))


def _record_dom_findings(
    snapshot: dict[str, Any],
    current_page_url: str,
    collected_forms: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]],
    collected_dom_inputs: dict[tuple[str, str, str], dict[str, Any]],
    gap_recorder: GapRecorder,
) -> None:
    for raw_form in snapshot.get("forms") or []:
        if not isinstance(raw_form, dict) or len(collected_forms) >= MAX_FORMS:
            continue
        normalized_form = normalize_form_entry(raw_form, current_page_url)
        collected_forms.setdefault(form_dedup_key(normalized_form), normalized_form)

        method = normalized_form["method"]
        if method != "GET":
            gap_recorder.add(
                url=current_page_url,
                reason="workflow_input_required",
                status="skipped",
                dedup_key=(
                    f"{canonical_url_key(current_page_url)}|"
                    f"{normalized_form['action']}|{method}"
                ),
                element=f"form[action={normalized_form['action']}]",
                detail=f"{method} form extracted passively without auto-submission",
            )

    for raw_input in snapshot.get("dom_inputs") or []:
        if not isinstance(raw_input, dict) or len(collected_dom_inputs) >= MAX_DOM_INPUTS:
            continue
        name = str(raw_input.get("name") or "").strip()
        if not name or raw_input.get("disabled"):
            continue
        page_url = str(raw_input.get("page_url") or current_page_url)
        input_key = (canonical_url_key(page_url), name, str(raw_input.get("input_type") or ""))
        collected_dom_inputs.setdefault(
            input_key,
            {
                "page_url": page_url,
                "name": name,
                "input_type": raw_input.get("input_type"),
                "required": bool(raw_input.get("required")),
                "disabled": bool(raw_input.get("disabled")),
            },
        )


async def _run_declarative_actions(
    page: Any,
    target: str,
    requested_actions: list[dict[str, Any]],
    excluded_scope: list[str],
    recorder: _NetworkRecorder,
    gap_recorder: GapRecorder,
    collected_forms: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]],
    collected_dom_inputs: dict[tuple[str, str, str], dict[str, Any]],
    visited: list[str],
    result_actions: list[BrowserActionResult],
    deadline: float,
) -> None:
    await asyncio.wait_for(
        page.goto(target, wait_until="domcontentloaded"),
        timeout=max(0.1, deadline - time.monotonic()),
    )
    visited.append(page.url)
    _record_dom_findings(
        await _inspect_page_dom(page, target),
        page.url,
        collected_forms,
        collected_dom_inputs,
        gap_recorder,
    )

    for index, action in enumerate(requested_actions):
        if recorder.budget_exhausted:
            gap_recorder.add(
                url=str(page.url or target),
                reason="budget_or_limit_reached",
                status="stopped",
                dedup_key="budget_or_limit_reached",
                detail=f"stopped after reaching request_budget={recorder.request_budget}",
            )
            break
        kind = _action_kind(action)
        action_id = str(action.get("action_id") or f"ACT-{index + 1:03d}")
        recorder.current_action = action_id
        try:
            selector = str(action.get("selector") or "")
            if kind == "navigate":
                destination = urljoin(page.url, str(action.get("url") or ""))
                if not _same_origin(target, destination) or is_excluded(
                    destination, excluded_scope
                ):
                    raise ToolError(
                        "E_SCOPE", "browser navigation is outside the initial origin"
                    )
                await asyncio.wait_for(
                    page.goto(destination, wait_until="domcontentloaded"),
                    timeout=max(0.1, deadline - time.monotonic()),
                )
            elif kind == "click":
                await page.locator(selector).click()
            elif kind == "fill":
                await page.locator(selector).fill(str(action.get("value") or ""))
            elif kind == "submit":
                await page.locator(selector).evaluate("element => element.submit()")
            elif kind == "wait":
                await page.locator(selector).wait_for(state="visible")
            visited.append(page.url)
            _record_dom_findings(
                await _inspect_page_dom(page, target),
                page.url,
                collected_forms,
                collected_dom_inputs,
                gap_recorder,
            )
            result_actions.append(
                BrowserActionResult(
                    action_id=action_id,
                    kind=kind,
                    status="completed",
                    url=page.url,
                    network_event_ids=recorder.events_for_action(action_id),
                )
            )
        except ToolError:
            raise
        except Exception as exc:
            result_actions.append(
                BrowserActionResult(
                    action_id=action_id,
                    kind=kind,
                    status="failed",
                    url=page.url,
                    error=str(exc)[:MAX_TEXT],
                )
            )


async def _run_deterministic_bfs(
    page: Any,
    target: str,
    auth_ref: str | None,
    excluded_scope: list[str],
    max_depth: int,
    max_pages: int,
    recorder: _NetworkRecorder,
    gap_recorder: GapRecorder,
    collected_forms: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]],
    collected_dom_inputs: dict[tuple[str, str, str], dict[str, Any]],
    visited: list[str],
    result_actions: list[BrowserActionResult],
    deadline: float,
) -> None:
    queue: deque[tuple[str, int]] = deque([(target, 0)])
    visited_url_keys: set[str] = set()
    enqueued_url_keys: set[str] = {canonical_url_key(target)}
    signature_counts: dict[tuple[Any, ...], int] = {}
    interacted_keys: set[tuple[str, str]] = set()
    action_counter = 0
    pages_visited = 0
    stopped_by_limit_detail: str | None = None

    def _enqueue_links(links: list[Any], next_depth: int) -> None:
        nonlocal stopped_by_limit_detail
        for link in links:
            if not isinstance(link, dict):
                continue
            candidate_url = str(link.get("url") or "")
            raw_href = str(link.get("raw_href") or candidate_url)
            if not is_navigable_link(candidate_url, raw_href, target, excluded_scope):
                continue
            canon = canonical_url_key(candidate_url)
            if canon in visited_url_keys or canon in enqueued_url_keys:
                continue
            if next_depth > max_depth:
                if stopped_by_limit_detail is None:
                    stopped_by_limit_detail = (
                        f"stopped following links deeper than max_depth={max_depth}"
                    )
                continue
            sig = query_signature_key(candidate_url)
            if signature_counts.get(sig, 0) >= MAX_REPRESENTATIVE_URLS_PER_SIGNATURE:
                continue
            enqueued_url_keys.add(canon)
            queue.append((candidate_url, next_depth))

    while queue:
        if recorder.budget_exhausted:
            stopped_by_limit_detail = (
                f"stopped after reaching request_budget={recorder.request_budget}"
            )
            break
        if pages_visited >= max_pages:
            stopped_by_limit_detail = (
                f"stopped with {len(queue)} queued URLs remaining at max_pages={max_pages}"
            )
            break
        if action_counter >= MAX_ACTIONS:
            stopped_by_limit_detail = f"stopped after reaching max_actions={MAX_ACTIONS}"
            break
        remaining_time = deadline - time.monotonic()
        if remaining_time <= 0:
            stopped_by_limit_detail = "stopped after reaching timeout_seconds"
            break

        url, depth = queue.popleft()
        canon_requested = canonical_url_key(url)
        sig = query_signature_key(url)
        if (
            canon_requested in visited_url_keys
            or signature_counts.get(sig, 0) >= MAX_REPRESENTATIVE_URLS_PER_SIGNATURE
        ):
            continue

        action_counter += 1
        nav_action_id = f"ACT-{action_counter:03d}"
        recorder.current_action = nav_action_id
        try:
            await asyncio.wait_for(
                page.goto(url, wait_until="domcontentloaded"),
                timeout=max(0.1, remaining_time),
            )
        except Exception as exc:
            result_actions.append(
                BrowserActionResult(
                    action_id=nav_action_id,
                    kind="navigate",
                    status="failed",
                    url=url,
                    error=str(exc)[:MAX_TEXT],
                    network_event_ids=recorder.events_for_action(nav_action_id),
                )
            )
            gap_recorder.add(
                url=url,
                reason="navigation_failed",
                status="failed",
                dedup_key=canon_requested,
                detail=str(exc)[:MAX_TEXT],
            )
            continue

        pages_visited += 1
        landed_url = str(page.url or url)
        visited.append(landed_url)
        canon_landed = canonical_url_key(landed_url)
        visited_url_keys.add(canon_requested)
        visited_url_keys.add(canon_landed)
        signature_counts[sig] = signature_counts.get(sig, 0) + 1
        landed_sig = query_signature_key(landed_url)
        if landed_sig != sig:
            signature_counts[landed_sig] = signature_counts.get(landed_sig, 0) + 1

        await _settle_page(
            page,
            recorder.in_flight_requests,
            max_wait_seconds=min(0.6, max(0.05, deadline - time.monotonic())),
        )
        result_actions.append(
            BrowserActionResult(
                action_id=nav_action_id,
                kind="navigate",
                status="completed",
                url=landed_url,
                network_event_ids=recorder.events_for_action(nav_action_id),
            )
        )

        snapshot = await _inspect_page_dom(page, target)
        _record_dom_findings(
            snapshot, landed_url, collected_forms, collected_dom_inputs, gap_recorder
        )

        doc_status = recorder.document_status_by_url.get(
            landed_url
        ) or recorder.document_status_by_url.get(url)
        landed_path_lower = urlsplit(landed_url).path.lower()
        redirected_to_auth = (
            canon_landed != canon_requested
            and any(hint in landed_path_lower for hint in _AUTH_PATH_HINTS)
            and not auth_ref
        )
        if doc_status in {401, 403} or redirected_to_auth:
            gap_recorder.add(
                url=landed_url,
                reason="auth_required",
                status="blocked",
                dedup_key=canon_landed,
                detail=f"HTTP {doc_status or 'redirect'} auth barrier without active session",
            )
            continue

        if snapshot.get("has_password_input") and not auth_ref:
            gap_recorder.add(
                url=landed_url,
                reason="auth_required",
                status="blocked",
                dedup_key=canon_landed,
                element="input[type=password]",
                detail="login/password form encountered without auth context",
            )

        if snapshot.get("has_captcha"):
            gap_recorder.add(
                url=landed_url,
                reason="captcha_or_challenge_blocked",
                status="blocked",
                dedup_key=canon_landed,
                element=snapshot.get("captcha_selector"),
                detail="anti-bot challenge detected; stopping branch",
            )
            continue

        _enqueue_links(snapshot.get("links") or [], depth + 1)

        unclassified_selectors: list[str] = []
        while not recorder.budget_exhausted and action_counter < MAX_ACTIONS:
            if deadline - time.monotonic() <= 0:
                stopped_by_limit_detail = "stopped after reaching timeout_seconds"
                break
            candidates = sorted(
                list(snapshot.get("interactive") or []),
                key=lambda item: (
                    0 if classify_interactive_element(item)[0] == "allow_disclosure" else 1
                ),
            )
            progressed = False
            for el in candidates:
                if not isinstance(el, dict) or not el.get("selector"):
                    continue
                selector = str(el["selector"])
                el_sig = "|".join(
                    [
                        selector,
                        str(el.get("tag") or ""),
                        str(el.get("role") or ""),
                        str(el.get("text") or "")[:40],
                    ]
                )
                state_key = (canon_landed, el_sig)
                if state_key in interacted_keys:
                    continue

                disposition, _detail_code = classify_interactive_element(el)
                if disposition == "deny":
                    interacted_keys.add(state_key)
                    control_label = str(el.get("id") or el.get("text") or selector).strip()
                    gap_recorder.add(
                        url=landed_url,
                        reason="unsafe_interaction_skipped",
                        status="skipped",
                        dedup_key=f"{canon_landed}|{control_label.casefold()}",
                        element=selector,
                        detail=f"skipped state-changing or sensitive control: {control_label}",
                    )
                    continue
                if disposition == "skip_workflow":
                    interacted_keys.add(state_key)
                    if not el.get("in_non_get_form"):
                        gap_recorder.add(
                            url=landed_url,
                            reason="workflow_input_required",
                            status="skipped",
                            dedup_key=f"{canon_landed}|{selector}|required_input",
                            element=selector,
                            detail="skipped search/filter trigger with empty required input",
                        )
                    continue
                if disposition == "unclassified":
                    interacted_keys.add(state_key)
                    if selector not in unclassified_selectors:
                        unclassified_selectors.append(selector)
                    continue

                if action_counter >= MAX_ACTIONS or recorder.budget_exhausted:
                    break

                interacted_keys.add(state_key)
                action_counter += 1
                click_action_id = f"ACT-{action_counter:03d}"
                recorder.current_action = click_action_id
                try:
                    await asyncio.wait_for(
                        page.locator(selector).click(),
                        timeout=max(0.1, deadline - time.monotonic()),
                    )
                    await _settle_page(
                        page,
                        recorder.in_flight_requests,
                        max_wait_seconds=min(0.4, max(0.05, deadline - time.monotonic())),
                    )
                    result_actions.append(
                        BrowserActionResult(
                            action_id=click_action_id,
                            kind="click",
                            status="completed",
                            url=str(page.url or landed_url),
                            network_event_ids=recorder.events_for_action(click_action_id),
                        )
                    )
                except Exception as exc:
                    result_actions.append(
                        BrowserActionResult(
                            action_id=click_action_id,
                            kind="click",
                            status="failed",
                            url=str(page.url or landed_url),
                            error=str(exc)[:MAX_TEXT],
                            network_event_ids=recorder.events_for_action(click_action_id),
                        )
                    )
                    gap_recorder.add(
                        url=landed_url,
                        reason="interaction_failed",
                        status="failed",
                        dedup_key=f"{canon_landed}|{selector}",
                        element=selector,
                        detail=str(exc)[:MAX_TEXT],
                    )
                    continue

                current_url_after_click = str(page.url or landed_url)
                if current_url_after_click != landed_url and _same_origin(
                    target, current_url_after_click
                ):
                    visited.append(current_url_after_click)
                snapshot = await _inspect_page_dom(page, target)
                _record_dom_findings(
                    snapshot,
                    current_url_after_click,
                    collected_forms,
                    collected_dom_inputs,
                    gap_recorder,
                )
                _enqueue_links(snapshot.get("links") or [], depth + 1)
                progressed = True
                break

            if not progressed:
                break

        if unclassified_selectors:
            sample = ", ".join(unclassified_selectors[:3])
            gap_recorder.add(
                url=landed_url,
                reason="unclassified_interactive_elements",
                status="skipped",
                dedup_key=canon_landed,
                element=unclassified_selectors[0],
                detail=(
                    f"{len(unclassified_selectors)} unclassified interactive elements "
                    f"(sample: {sample})"
                ),
            )

    if recorder.budget_exhausted and stopped_by_limit_detail is None:
        stopped_by_limit_detail = (
            f"stopped after reaching request_budget={recorder.request_budget}"
        )
    if stopped_by_limit_detail:
        gap_recorder.add(
            url=str(page.url or target),
            reason="budget_or_limit_reached",
            status="stopped",
            dedup_key="budget_or_limit_reached",
            detail=stopped_by_limit_detail,
        )


def _validate_explore_args(
    target: str,
    requested_actions: list[dict[str, Any]],
    auth_ref: str | None,
    excluded_scope: list[str],
    max_depth: int,
    max_pages: int,
    request_budget: int,
) -> None:
    _validate_target(target)
    if max_depth < 0:
        raise ToolError("E_INVALID_ARGUMENT", "max_depth must be non-negative")
    if max_pages < 1:
        raise ToolError("E_INVALID_ARGUMENT", "max_pages must be positive")
    if request_budget < 1:
        raise ToolError("E_INVALID_ARGUMENT", "request_budget must be positive")
    if len(requested_actions) > MAX_ACTIONS:
        raise ToolError("E_INVALID_ARGUMENT", f"at most {MAX_ACTIONS} browser actions are allowed")
    if any("proxy" in action or "proxy_url" in action for action in requested_actions):
        raise ToolError("E_INVALID_ARGUMENT", "browser actions cannot configure a proxy")
    if auth_ref and ("=" in auth_ref or "://" in auth_ref):
        raise ToolError("E_INVALID_ARGUMENT", "auth_ref must be an opaque reference")
    if is_excluded(target, excluded_scope):
        raise ToolError("E_SCOPE", "target URL matches excluded_scope")


async def explore_browser(
    target: str,
    actions: list[dict[str, Any]] | None = None,
    auth_ref: str | None = None,
    *,
    excluded_scope: list[str] | None = None,
    max_depth: int = MAX_DEPTH,
    max_pages: int = MAX_PAGES,
    request_budget: int = MAX_EVENTS,
    playwright_factory: Callable[[], Awaitable[Any]] | None = None,
    timeout_seconds: float = 30.0,
) -> dict[str, Any]:
    """Run bounded deterministic or declarative, same-origin browser exploration."""
    requested_actions = actions or []
    excluded = list(excluded_scope or [])
    _validate_explore_args(
        target, requested_actions, auth_ref, excluded, max_depth, max_pages, request_budget
    )

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
        proxy = _trusted_proxy()
        context = await browser.new_context(**({"proxy": proxy} if proxy else {}))
        page = await context.new_page()
    except ToolError:
        raise
    except Exception as exc:
        raise ToolError("E_TOOL_FAILED", "browser could not be started") from exc

    recorder = _NetworkRecorder(target, excluded, request_budget)
    await recorder.attach(page)
    visited: list[str] = []
    warnings: list[str] = []
    gap_recorder = GapRecorder(warnings)
    collected_forms: dict[tuple[str, str, str, tuple[str, ...]], dict[str, Any]] = {}
    collected_dom_inputs: dict[tuple[str, str, str], dict[str, Any]] = {}
    result_actions: list[BrowserActionResult] = []
    deadline = time.monotonic() + timeout_seconds

    def _build_result(
        *, completed: bool, errors: list[str] | None = None
    ) -> BrowserReconResult:
        return BrowserReconResult(
            target=target,
            final_url=page.url,
            visited_urls=sorted(set(visited)),
            actions=result_actions,
            network_events=[
                BrowserNetworkEvent.model_validate(item) for item in recorder.events[:MAX_EVENTS]
            ],
            forms=[
                BrowserForm.model_validate(item)
                for item in list(collected_forms.values())[:MAX_FORMS]
            ],
            dom_inputs=[
                BrowserDomInput.model_validate(item)
                for item in list(collected_dom_inputs.values())[:MAX_DOM_INPUTS]
            ],
            redirects=[BrowserRedirect.model_validate(item) for item in recorder.redirects],
            recon_gaps=gap_recorder.gaps,
            completed=completed,
            warnings=warnings,
            errors=errors or [],
            truncated=recorder.budget_exhausted or len(recorder.events) > MAX_EVENTS,
        )

    try:
        if requested_actions:
            await _run_declarative_actions(
                page,
                target,
                requested_actions,
                excluded,
                recorder,
                gap_recorder,
                collected_forms,
                collected_dom_inputs,
                visited,
                result_actions,
                deadline,
            )
        else:
            await _run_deterministic_bfs(
                page,
                target,
                auth_ref,
                excluded,
                max_depth,
                max_pages,
                recorder,
                gap_recorder,
                collected_forms,
                collected_dom_inputs,
                visited,
                result_actions,
                deadline,
            )
        result = _build_result(completed=True)
    except TimeoutError:
        gap_recorder.add(
            url=str(getattr(page, "url", None) or target),
            reason="budget_or_limit_reached",
            status="stopped",
            dedup_key="timeout",
            detail="navigation or exploration timed out",
        )
        result = _build_result(completed=False, errors=["E_TIMEOUT"])
    except ToolError:
        raise
    except Exception as exc:
        result = _build_result(completed=False, errors=[str(exc)[:MAX_TEXT]])
    finally:
        await context.close()
        await browser.close()
        if owns_playwright:
            await playwright.stop()

    trace_metadata = {
        "visited_url_count": len(result.visited_urls),
        "event_count": len(result.network_events),
        "action_count": len(result.actions),
        "form_count": len(result.forms),
        "dom_input_count": len(result.dom_inputs),
        "redirect_count": len(result.redirects),
        "gap_count": len(result.recon_gaps),
    }
    trace_digest = hashlib.sha256(json.dumps(trace_metadata, sort_keys=True).encode()).hexdigest()[
        :16
    ]
    result.artifact_manifests = [
        {
            "artifact_ref": f"browser-trace-{trace_digest}",
            "artifact_type": "BROWSER_TRACE",
            "media_type": "application/json",
            "redaction_applied": True,
            "truncated": result.truncated,
            "metadata": trace_metadata,
        }
    ]
    return envelope(
        f"Browser explored {len(result.visited_urls)} URLs from {target}",
        result.model_dump(mode="json"),
        result.truncated,
    )
