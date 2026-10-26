"""Deterministic Playwright-wrapper tests using a fake browser backend."""

from __future__ import annotations

import asyncio
import json
from functools import wraps

from mcp_servers.websec_tools.recon import browser


def async_test(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        return asyncio.run(function(*args, **kwargs))

    return wrapper


class FakeRequest:
    def __init__(self, url: str, method: str = "GET", *, resource_type: str = "document"):
        self.url = url
        self.method = method
        self.resource_type = resource_type
        self.post_data = None

    async def all_headers(self):
        return {"authorization": "secret-token", "content-type": "application/json"}


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
    def __init__(self, url: str, status: int = 200, *, location: str | None = None):
        self.url = url
        self.status = status
        self._location = location

    async def all_headers(self):
        headers = {"content-type": "application/json"}
        if self._location:
            headers["location"] = self._location
        return headers


class FakeLocator:
    def __init__(self, page, selector: str):
        self.page = page
        self.selector = selector

    async def click(self):
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
    def __init__(self):
        self.url = "about:blank"
        self.route_handler = None
        self.response_handler = None
        self.routes = []

    async def route(self, _pattern, handler):
        self.route_handler = handler

    def on(self, event, handler):
        assert event == "response"
        self.response_handler = handler

    async def emit_request(self, url, method="GET", resource_type="xhr"):
        route = FakeRoute(FakeRequest(url, method, resource_type=resource_type))
        self.routes.append(route)
        await self.route_handler(route)
        if not route.aborted:
            await self.response_handler(FakeResponse(url))

    async def goto(self, url, *, wait_until):
        assert wait_until == "domcontentloaded"
        self.url = url
        await self.emit_request(url)
        await self.emit_request("https://outside.test/script.js", resource_type="script")
        await self.response_handler(FakeResponse(url, 302, location="/redirected"))

    def locator(self, selector):
        return FakeLocator(self, selector)


class FakeContext:
    def __init__(self):
        self.page = FakePage()

    async def new_page(self):
        return self.page

    async def close(self):
        return None


class FakeBrowser:
    def __init__(self):
        self.context = FakeContext()

    async def new_context(self):
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
    def __init__(self):
        self.browser_instance = FakeBrowser()
        self.chromium = FakeChromium(self.browser_instance)

    async def stop(self):
        return None


@async_test
async def test_browser_actions_network_correlation_forms_redirects_and_redaction():
    fake = FakePlaywright()

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
