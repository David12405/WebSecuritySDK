"""Deterministic Playwright-wrapper tests using a fake browser backend."""

from __future__ import annotations

import asyncio
import json
from functools import wraps
from typing import Any

import pytest

from mcp_servers.websec_tools.recon import browser


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


class FakeRequest:
    def __init__(
        self,
        url: str,
        method: str = "GET",
        *,
        resource_type: str = "document",
        post_data: str | None = None,
        content_type: str = "application/json",
    ):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = post_data
        self._content_type = content_type

    async def all_headers(self):
        headers = {"authorization": "secret-token"}
        if self._content_type:
            headers["content-type"] = self._content_type
        return headers


class FakeRoute:
    def __init__(self, request):
        self.request = request
        self.aborted = False
        self.continued = False

    async def abort(self):
        self.aborted = True

    async def continue_(self):
        self.continued = True


class FakeResponse:
    def __init__(
        self,
        url: str,
        status: int = 200,
        *,
        location: str | None = None,
        content_type: str = "application/json",
        request: FakeRequest | None = None,
    ):
        self.url = url
        self.status = status
        self._location = location
        self._content_type = content_type
        self.request = request

    async def all_headers(self):
        headers = {"content-type": self._content_type}
        if self._location:
            headers["location"] = self._location
        return headers


class FakeLocator:
    def __init__(self, page, selector: str):
        self.page = page
        self.selector = selector

    async def click(self):
        if self.page.on_click:
            await self.page.on_click(self.selector, self.page)
            return
        await self.page.emit_request("https://target.test/api/click", "POST", "xhr")

    async def fill(self, _value):
        await self.page.emit_request("https://target.test/api/fill", "POST", "fetch")

    async def evaluate(self, _expression):
        await self.page.emit_request("https://target.test/api/submit", "POST", "fetch")

    async def wait_for(self, *, state):
        assert state == "visible"

    async def evaluate_all(self, _expression):
        return [
            {
                "action": "https://target.test/login",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "controls": [
                    {"name": "password", "type": "password", "required": True, "disabled": False}
                ],
            }
        ]


class FakePage:
    def __init__(
        self,
        *,
        snapshots: dict[str, dict[str, Any]] | None = None,
        on_goto: Any = None,
        on_click: Any = None,
    ):
        self.url = "about:blank"
        self.route_handler = None
        self.handlers: dict[str, list[Any]] = {
            "request": [],
            "response": [],
            "requestfinished": [],
            "requestfailed": [],
        }
        self.routes = []
        self.clicked_selectors: list[str] = []
        self.snapshots = snapshots or {}
        self.on_goto = on_goto
        self.on_click = on_click

    async def route(self, _pattern, handler):
        self.route_handler = handler

    def on(self, event, handler):
        assert event in self.handlers, f"unexpected page event {event!r}"
        self.handlers[event].append(handler)

    async def _dispatch(self, event: str, payload: Any) -> None:
        for handler in self.handlers.get(event, []):
            res = handler(payload)
            if asyncio.iscoroutine(res):
                await res

    async def emit_request(
        self,
        url,
        method="GET",
        resource_type="xhr",
        *,
        status: int = 200,
        location: str | None = None,
        post_data: str | None = None,
        content_type: str = "application/json",
        fail: bool = False,
        emit_twice_on_done: bool = False,
    ):
        req = FakeRequest(
            url,
            method,
            resource_type=resource_type,
            post_data=post_data,
            content_type=content_type,
        )
        await self._dispatch("request", req)
        route = FakeRoute(req)
        self.routes.append(route)
        await self.route_handler(route)
        if not route.aborted:
            if fail:
                await self._dispatch("requestfailed", req)
                if emit_twice_on_done:
                    await self._dispatch("requestfailed", req)
                return
            await self._dispatch(
                "response",
                FakeResponse(
                    url,
                    status=status,
                    location=location,
                    content_type=content_type,
                    request=req,
                ),
            )
            await self._dispatch("requestfinished", req)
            if emit_twice_on_done:
                await self._dispatch("requestfinished", req)

    async def goto(self, url, *, wait_until):
        assert wait_until == "domcontentloaded"
        self.url = url
        if self.on_goto:
            await self.on_goto(url, self)
            return
        await self.emit_request(url, resource_type="document")
        await self.emit_request("https://outside.test/script.js", resource_type="script")
        await self._dispatch("response", FakeResponse(url, 302, location="/redirected"))

    async def evaluate(self, expression):
        if expression.startswith("() => document.querySelectorAll("):
            snap = self.snapshots.get(self.url, {})
            return (
                len(snap.get("forms", []))
                + len(snap.get("dom_inputs", []))
                + len(snap.get("links", []))
                + len(snap.get("interactive", []))
            )
        snap = dict(self.snapshots.get(self.url, {}))
        snap.setdefault("page_url", self.url)
        snap.setdefault("forms", [])
        snap.setdefault("dom_inputs", [])
        snap.setdefault("links", [])
        snap.setdefault("interactive", [])
        snap.setdefault("has_captcha", False)
        snap.setdefault("captcha_selector", None)
        snap.setdefault("has_password_input", False)
        return snap

    def locator(self, selector):
        return FakeLocator(self, selector)


class FakeContext:
    def __init__(self, page: FakePage | None = None):
        self.page = page or FakePage()

    async def new_page(self):
        return self.page

    async def close(self):
        return None


class FakeBrowser:
    def __init__(self, page: FakePage | None = None):
        self.context = FakeContext(page)
        self.context_kwargs = []

    async def new_context(self, **kwargs):
        self.context_kwargs.append(kwargs)
        return self.context

    async def close(self):
        return None


class FakeChromium:
    def __init__(self, browser_instance):
        self.browser_instance = browser_instance

    async def launch(self, *, headless):
        assert headless is True
        return self.browser_instance


class FakePlaywright:
    def __init__(self, page: FakePage | None = None):
        self.browser_instance = FakeBrowser(page)
        self.chromium = FakeChromium(self.browser_instance)

    async def stop(self):
        return None


@async_test
async def test_browser_actions_network_correlation_forms_redirects_and_redaction(monkeypatch):
    monkeypatch.delenv("WEBSEC_ZAP_PROXY_URL", raising=False)
    fake = FakePlaywright()
    fake.browser_instance.context.page.snapshots["https://target.test/"] = {
        "forms": [
            {
                "action": "https://target.test/login",
                "method": "POST",
                "enctype": "application/x-www-form-urlencoded",
                "controls": [
                    {"name": "password", "type": "password", "required": True, "disabled": False}
                ],
            }
        ]
    }

    async def factory():
        return fake

    result = await browser.explore_browser(
        "https://target.test/",
        actions=[
            {"action_id": "ACT-001", "kind": "click", "selector": "#go"},
            {"action_id": "ACT-002", "kind": "fill", "selector": "#password", "value": "secret"},
            {"action_id": "ACT-003", "kind": "submit", "selector": "form"},
            {"action_id": "ACT-004", "kind": "wait", "selector": "#done"},
            {"action_id": "ACT-005", "kind": "navigate", "url": "/next"},
        ],
        auth_ref="AUTH-001",
        playwright_factory=factory,
    )

    serialized = json.dumps(result)
    assert "secret-token" not in serialized
    assert '"value"' not in serialized
    data = result["data"]
    assert data["completed"] is True
    assert data["forms"][0]["controls"][0]["name"] == "password"
    assert data["redirects"][0]["to_url"] == "https://target.test/redirected"
    assert any(
        item["blocked"] and item["blocked_reason"] == "out_of_scope"
        for item in data["network_events"]
    )
    assert data["artifact_manifests"][0]["artifact_type"] == "BROWSER_TRACE"
    assert any(item["action_id"] == "ACT-001" for item in data["actions"])
    assert fake.browser_instance.context_kwargs == [{}]


@async_test
async def test_browser_uses_only_trusted_proxy_configuration(monkeypatch):
    monkeypatch.setenv("WEBSEC_ZAP_PROXY_URL", "http://127.0.0.1:8080")
    fake = FakePlaywright()

    async def factory():
        return fake

    await browser.explore_browser(
        "https://target.test/",
        actions=[{"kind": "wait", "selector": "body"}],
        playwright_factory=factory,
    )

    assert fake.browser_instance.context_kwargs == [
        {"proxy": {"server": "http://127.0.0.1:8080"}}
    ]
    outside_route = next(
        route
        for route in fake.browser_instance.context.page.routes
        if route.request.url.startswith("https://outside.test/")
    )
    assert outside_route.aborted is True
    assert outside_route.continued is False


@async_test
async def test_browser_actions_cannot_override_proxy(monkeypatch):
    monkeypatch.setenv("WEBSEC_ZAP_PROXY_URL", "http://127.0.0.1:8080")
    fake = FakePlaywright()

    async def factory():
        return fake

    with pytest.raises(browser.ToolError) as error:
        await browser.explore_browser(
            "https://target.test/",
            actions=[{"kind": "wait", "selector": "body", "proxy": "http://evil.test"}],
            playwright_factory=factory,
        )
    assert error.value.code == "E_INVALID_ARGUMENT"
    assert fake.browser_instance.context_kwargs == []


@async_test
async def test_browser_rejects_untrusted_proxy_configuration(monkeypatch):
    monkeypatch.setenv("WEBSEC_ZAP_PROXY_URL", "http://user:secret@127.0.0.1:8080")
    fake = FakePlaywright()

    async def factory():
        return fake

    with pytest.raises(browser.ToolError) as error:
        await browser.explore_browser(
            "https://target.test/", actions=[], playwright_factory=factory
        )
    assert error.value.code == "E_INVALID_ARGUMENT"
    assert "secret" not in str(error.value)
    assert fake.browser_instance.context_kwargs == []


@async_test
async def test_browser_rejects_arbitrary_auth_reference_and_navigation_scope():
    fake = FakePlaywright()

    async def factory():
        return fake

    try:
        await browser.explore_browser(
            "https://target.test/",
            auth_ref="https://secrets.example/session",
            playwright_factory=factory,
        )
    except browser.ToolError as error:
        assert error.code == "E_INVALID_ARGUMENT"
    else:
        raise AssertionError("non-opaque auth_ref must be rejected")


@async_test
async def test_deterministic_explorer_static_links_and_per_page_forms(monkeypatch):
    monkeypatch.delenv("WEBSEC_ZAP_PROXY_URL", raising=False)
    snapshots = {
        "https://target.test/": {
            "links": [
                {
                    "url": "https://target.test/contact",
                    "raw_href": "/contact",
                    "text": "Contact",
                },
                {
                    "url": "https://target.test/redirect",
                    "raw_href": "/redirect",
                    "text": "Redirect",
                },
                {
                    "url": "https://target.test/logout",
                    "raw_href": "/logout",
                    "text": "Logout",
                },
                {
                    "url": "https://evil.example/out",
                    "raw_href": "https://evil.example/out",
                    "text": "Ext",
                },
            ],
            "forms": [
                {
                    "page_url": "https://target.test/",
                    "action": "https://target.test/search",
                    "method": "GET",
                    "controls": [
                        {"name": "q", "type": "text", "required": False, "disabled": False}
                    ],
                }
            ],
        },
        "https://target.test/contact": {
            "forms": [
                {
                    "page_url": "https://target.test/contact",
                    "action": "feedback",
                    "method": "POST",
                    "enctype": "application/x-www-form-urlencoded",
                    "controls": [
                        {"name": "email", "type": "email", "required": True, "disabled": False},
                        {
                            "name": "message",
                            "type": "textarea",
                            "required": False,
                            "disabled": False,
                        },
                    ],
                }
            ]
        },
        "https://target.test/final": {"links": []},
    }

    async def on_goto(url: str, page: FakePage) -> None:
        if url == "https://target.test/redirect":
            await page.emit_request(url, resource_type="document", status=302, location="/final")
            page.url = "https://target.test/final"
            await page.emit_request(
                "https://target.test/final", resource_type="document", status=200
            )
            return
        await page.emit_request(url, resource_type="document", status=200)

    page = FakePage(snapshots=snapshots, on_goto=on_goto)
    fake = FakePlaywright(page)

    async def factory():
        return fake

    result = await browser.explore_browser("https://target.test/", playwright_factory=factory)
    data = result["data"]
    assert data["completed"] is True
    assert set(data["visited_urls"]) == {
        "https://target.test/",
        "https://target.test/contact",
        "https://target.test/final",
    }
    form_actions = {(item["action"], item["method"]): item for item in data["forms"]}
    assert ("https://target.test/search", "GET") in form_actions
    assert (
        form_actions[("https://target.test/feedback", "POST")]["page_url"],
        form_actions[("https://target.test/feedback", "POST")]["action"],
    ) == ("https://target.test/contact", "https://target.test/feedback")
    assert any(gap["reason"] == "workflow_input_required" for gap in data["recon_gaps"])
    assert data["redirects"][0]["to_url"] == "https://target.test/final"
    assert '"value"' not in json.dumps(result)


@async_test
async def test_deterministic_explorer_spa_xhr_fetch_safe_interactions_and_gaps(monkeypatch):
    monkeypatch.delenv("WEBSEC_ZAP_PROXY_URL", raising=False)
    snapshots = {
        "https://target.test/": {
            "dom_inputs": [
                {
                    "page_url": "https://target.test/",
                    "name": "search-input",
                    "input_type": "text",
                    "required": False,
                    "disabled": False,
                }
            ],
            "interactive": [
                {
                    "selector": "#btn-search",
                    "tag": "button",
                    "type": "button",
                    "role": "",
                    "id": "btn-search",
                    "name": "",
                    "class_name": "",
                    "text": "Search",
                    "aria_label": "",
                    "aria_expanded": "",
                    "aria_controls": "",
                    "aria_haspopup": "",
                    "href": "",
                    "form_action": "",
                    "in_non_get_form": False,
                    "form_method": None,
                    "container_has_empty_required_input": False,
                },
                {
                    "selector": "#btn-cart-1",
                    "tag": "button",
                    "type": "button",
                    "role": "",
                    "id": "btn-cart-1",
                    "name": "",
                    "class_name": "",
                    "text": "Add to Cart",
                    "aria_label": "",
                    "aria_expanded": "",
                    "aria_controls": "",
                    "aria_haspopup": "",
                    "href": "",
                    "form_action": "",
                    "in_non_get_form": False,
                    "form_method": None,
                    "container_has_empty_required_input": False,
                },
                {
                    "selector": "#tab-advanced",
                    "tag": "button",
                    "type": "button",
                    "role": "tab",
                    "id": "tab-advanced",
                    "text": "Advanced",
                    "aria_expanded": "false",
                },
                {
                    "selector": "#menu-more",
                    "tag": "button",
                    "type": "button",
                    "role": "menuitem",
                    "id": "menu-more",
                    "text": "More Options",
                    "aria_expanded": "false",
                    "aria_controls": "submenu-more",
                },
                {
                    "selector": "#menu-delete",
                    "tag": "button",
                    "type": "button",
                    "role": "menuitem",
                    "id": "menu-delete",
                    "text": "Delete Account",
                },
                {
                    "selector": "#menu-export",
                    "tag": "button",
                    "type": "button",
                    "role": "menuitem",
                    "id": "menu-export",
                    "text": "Export",
                },
                {
                    "selector": "#custom-1",
                    "tag": "button",
                    "type": "button",
                    "role": "",
                    "id": "custom-1",
                    "text": "Do Magic",
                },
                {
                    "selector": "#custom-2",
                    "tag": "button",
                    "type": "button",
                    "role": "",
                    "id": "custom-2",
                    "text": "Run Wizard",
                },
                {
                    "selector": "#btn-empty-required",
                    "tag": "button",
                    "type": "button",
                    "role": "",
                    "id": "btn-empty-required",
                    "text": "Search Strict",
                    "container_has_empty_required_input": True,
                },
            ],
        }
    }

    async def on_goto(url: str, page: FakePage) -> None:
        await page.emit_request(url, resource_type="document")
        await page.emit_request("https://target.test/api/categories", resource_type="xhr")
        await page.emit_request(
            "https://target.test/api/products",
            resource_type="fetch",
            emit_twice_on_done=True,
        )
        # Dynamic render adds View Details button after load
        page.snapshots[url]["interactive"].append(
            {
                "selector": "#btn-details-1",
                "tag": "button",
                "type": "button",
                "role": "",
                "id": "btn-details-1",
                "text": "View Details",
                "container_has_empty_required_input": False,
            }
        )

    async def on_click(selector: str, page: FakePage) -> None:
        page.clicked_selectors.append(selector)
        if selector == "#btn-search":
            await page.emit_request(
                "https://target.test/api/search?mode=quick%20find",
                method="POST",
                resource_type="fetch",
                post_data=json.dumps({"keyword": "test", "nested": {"limit": 5}}),
                content_type="application/json",
            )
        elif selector == "#btn-details-1":
            await page.emit_request(
                "https://target.test/api/products/1",
                method="GET",
                resource_type="fetch",
            )
        elif selector == "#tab-advanced":
            await page.emit_request(
                "https://target.test/api/config",
                method="GET",
                resource_type="fetch",
            )
            page.snapshots[page.url]["forms"] = [
                {
                    "page_url": page.url,
                    "action": "https://target.test/api/advanced",
                    "method": "GET",
                    "controls": [{"name": "scope", "type": "text", "disabled": False}],
                }
            ]

    page = FakePage(snapshots=snapshots, on_goto=on_goto, on_click=on_click)
    fake = FakePlaywright(page)

    async def factory():
        return fake

    result = await browser.explore_browser("https://target.test/", playwright_factory=factory)
    data = result["data"]

    # Disclosure & safe read triggers clicked; cart/delete/plain menuitem/unclassified NOT clicked
    assert "#tab-advanced" in page.clicked_selectors
    assert "#menu-more" in page.clicked_selectors
    assert "#btn-search" in page.clicked_selectors
    assert "#btn-details-1" in page.clicked_selectors
    assert "#btn-cart-1" not in page.clicked_selectors
    assert "#menu-delete" not in page.clicked_selectors
    assert "#menu-export" not in page.clicked_selectors
    assert "#btn-empty-required" not in page.clicked_selectors

    # Verify extracted endpoints, DOM inputs, query & nested JSON body fields
    events_by_url = {(e["method"], e["url"].split("?", 1)[0]): e for e in data["network_events"]}
    search_event = events_by_url[("POST", "https://target.test/api/search")]
    assert search_event["query_parameter_names"] == ["mode"]
    assert search_event["request_body_field_names"] == ["keyword", "nested", "nested.limit"]
    assert ("GET", "https://target.test/api/products/1") in events_by_url
    assert data["dom_inputs"] == [
        {
            "page_url": "https://target.test/",
            "name": "search-input",
            "input_type": "text",
            "required": False,
            "disabled": False,
        }
    ]
    assert data["forms"][0]["action"] == "https://target.test/api/advanced"

    # Verify aggregated noise-free Recon Gaps (1 unclassified gap covering 3 elements)
    gaps_by_reason = {}
    for gap in data["recon_gaps"]:
        gaps_by_reason.setdefault(gap["reason"], []).append(gap)
    assert len(gaps_by_reason["unsafe_interaction_skipped"]) == 2
    assert len(gaps_by_reason["workflow_input_required"]) == 1
    assert len(gaps_by_reason["unclassified_interactive_elements"]) == 1
    assert "3 unclassified" in gaps_by_reason["unclassified_interactive_elements"][0]["detail"]


@async_test
async def test_deterministic_explorer_two_level_dedup_auth_captcha_and_burst_budget(monkeypatch):
    monkeypatch.delenv("WEBSEC_ZAP_PROXY_URL", raising=False)
    snapshots = {
        "https://target.test/": {
            "links": [
                {
                    "url": "https://target.test/items?id=1",
                    "raw_href": "/items?id=1",
                    "text": "Item 1",
                },
                {
                    "url": "https://target.test/items?id=1#top",
                    "raw_href": "/items?id=1#top",
                    "text": "Dup",
                },
                {
                    "url": "https://target.test/items?id=2",
                    "raw_href": "/items?id=2",
                    "text": "Item 2",
                },
                {
                    "url": "https://target.test/items?id=3",
                    "raw_href": "/items?id=3",
                    "text": "Item 3",
                },
                {
                    "url": "https://target.test/admin",
                    "raw_href": "/admin",
                    "text": "Admin",
                },
                {
                    "url": "https://target.test/protected",
                    "raw_href": "/protected",
                    "text": "Protected",
                },
            ]
        },
        "https://target.test/items?id=1": {},
        "https://target.test/items?id=2": {
            "has_captcha": True,
            "captcha_selector": "#cf-turnstile",
            "links": [
                {
                    "url": "https://target.test/hidden",
                    "raw_href": "/hidden",
                    "text": "Hidden",
                }
            ],
        },
        "https://target.test/protected": {},
    }

    async def on_goto(url: str, page: FakePage) -> None:
        if url == "https://target.test/protected":
            await page.emit_request(url, resource_type="document", status=403)
            return
        await page.emit_request(url, resource_type="document", status=200)

    page = FakePage(snapshots=snapshots, on_goto=on_goto)
    fake = FakePlaywright(page)

    async def factory():
        return fake

    result = await browser.explore_browser(
        "https://target.test/",
        excluded_scope=["/admin"],
        max_pages=10,
        request_budget=10,
        playwright_factory=factory,
    )
    data = result["data"]
    # Both /items?id=1 and /items?id=2 visited; id=3, /admin, and /hidden (after captcha) skipped
    assert "https://target.test/items?id=1" in data["visited_urls"]
    assert "https://target.test/items?id=2" in data["visited_urls"]
    assert "https://target.test/items?id=3" not in data["visited_urls"]
    assert "https://target.test/admin" not in data["visited_urls"]
    assert "https://target.test/hidden" not in data["visited_urls"]

    reasons = {g["reason"] for g in data["recon_gaps"]}
    assert {"auth_required", "captcha_or_challenge_blocked"} <= reasons

    # Now verify hard burst request_budget enforcement inside route_handler
    burst_page = FakePage(
        snapshots={
            "https://target.test/": {
                "links": [{"url": "https://target.test/next", "raw_href": "/next", "text": "Next"}]
            }
        }
    )

    async def burst_goto(url: str, p: FakePage) -> None:
        await p.emit_request(url, resource_type="document")
        for idx in range(4):
            await p.emit_request(f"https://target.test/api/burst/{idx}", resource_type="fetch")

    burst_page.on_goto = burst_goto
    burst_fake = FakePlaywright(burst_page)

    async def burst_factory():
        return burst_fake

    budget_result = await browser.explore_browser(
        "https://target.test/",
        request_budget=3,
        playwright_factory=burst_factory,
    )
    budget_data = budget_result["data"]
    assert budget_data["truncated"] is True
    allowed = [e for e in budget_data["network_events"] if not e["blocked"]]
    blocked_budget = [
        e
        for e in budget_data["network_events"]
        if e.get("blocked_reason") == "request_budget_exceeded"
    ]
    assert len(allowed) == 3
    assert len(blocked_budget) == 2
    assert "https://target.test/next" not in budget_data["visited_urls"]
    assert any(g["reason"] == "budget_or_limit_reached" for g in budget_data["recon_gaps"])


def test_body_names_handles_nested_json_urlencoded_and_multipart():
    nested_json = json.dumps({"user": {"profile": {"email": "a@b.c"}}, "tags": ["x"]})
    assert browser._body_names(nested_json, "application/json") == [
        "tags",
        "user",
        "user.profile",
        "user.profile.email",
    ]
    form_fields = browser._body_names(
        "user%5Bname%5D=alice&role=admin", "application/x-www-form-urlencoded"
    )
    assert form_fields == [
        "role",
        "user[name]",
    ]
    multipart = (
        "--bound\r\n"
        'Content-Disposition: form-data; name="avatar"; filename="a.png"\r\n\r\n'
        "binary\r\n--bound\r\n"
        'Content-Disposition: form-data; name="display_name"\r\n\r\nalice\r\n--bound--'
    )
    assert browser._body_names(multipart, "multipart/form-data; boundary=bound") == [
        "avatar",
        "display_name",
    ]


def test_browser_rules_pure_classifier_and_url_keys():
    from mcp_servers.websec_tools.recon import browser_rules

    assert browser_rules.canonical_url_key("https://TARGET.test.:443/a/./b//?y=2&x=1#frag") == (
        "https://target.test/a/b/?x=1&y=2"
    )
    assert browser_rules.canonical_url_key("https://target.test/#!//items") == (
        "https://target.test/#!//items"
    )
    assert browser_rules.query_signature_key("https://target.test/items?id=2") == (
        browser_rules.query_signature_key("https://target.test/items?id=99")
    )

    assert browser_rules.classify_interactive_element(
        {"tag": "button", "type": "button", "role": "menuitem", "text": "Logout"}
    ) == ("deny", "unsafe_interaction_skipped")
    assert browser_rules.classify_interactive_element(
        {"tag": "button", "type": "button", "role": "menuitem", "text": "Export"}
    ) == ("unclassified", "unclassified_interactive_elements")
    assert browser_rules.classify_interactive_element(
        {
            "tag": "button",
            "type": "button",
            "role": "menuitem",
            "text": "More",
            "aria_expanded": "false",
            "aria_controls": "sub",
        }
    ) == ("allow_disclosure", "disclosure")
    assert browser_rules.classify_interactive_element(
        {"tag": "button", "type": "button", "role": "", "text": "Search"}
    ) == ("allow_read", "read_trigger")
