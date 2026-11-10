import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG } from "./lib/config.mjs";

const BASE = CONFIG.BASIC_URL;

test("BASIC target — Live HTTP test suite", async (t) => {
  await t.test("GET / returns 200 HTML with recon links and forms", async () => {
    const res = await fetch(`${BASE}/`);
    assert.equal(res.status, 200);
    const ct = res.headers.get("content-type") || "";
    assert.ok(ct.includes("text/html"));
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");

    const html = await res.text();
    assert.ok(html.includes("/search?q=test"));
    assert.ok(html.includes("/redirect"));
    assert.ok(html.includes("/cookie"));
    assert.ok(html.includes("/headers"));
    assert.ok(html.includes('action="/search"'));
    assert.ok(html.includes('action="/login"'));
    assert.ok(html.includes('action="/form"'));
  });

  await t.test("GET /search?q=test returns 200 echoing query parameter safely", async () => {
    const res = await fetch(`${BASE}/search?q=security-probe`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes("security-probe"));
  });

  await t.test("GET /search without q returns 200 with empty query display", async () => {
    const res = await fetch(`${BASE}/search`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes('id="query-result"'));
  });

  await t.test("GET /redirect returns 302 pointing to /final", async () => {
    const res = await fetch(`${BASE}/redirect`, { redirect: "manual" });
    assert.equal(res.status, 302);
    assert.equal(res.headers.get("location"), "/final");
  });

  await t.test("GET /final returns 200 HTML", async () => {
    const res = await fetch(`${BASE}/final`);
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes("Final Destination"));
  });

  await t.test("GET /cookie sets test_session cookie and returns JSON", async () => {
    const res = await fetch(`${BASE}/cookie`);
    assert.equal(res.status, 200);
    const setCookie = res.headers.get("set-cookie") || "";
    assert.ok(setCookie.includes("test_session="));
    assert.ok(setCookie.includes("Path=/"));
    assert.ok(setCookie.includes("HttpOnly"));

    const data = await res.json();
    assert.equal(data.cookieName, "test_session");
  });

  await t.test("GET /headers returns selected request headers", async () => {
    const res = await fetch(`${BASE}/headers`, {
      headers: {
        "User-Agent": "ReconAgent/1.0",
        "X-Test-Header": "header-val-42"
      }
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.headers["user-agent"], "ReconAgent/1.0");
    assert.equal(data.headers["x-test-header"], "header-val-42");
  });

  await t.test("POST /login accepts urlencoded form body", async () => {
    const body = new URLSearchParams({ username: "alice", password: "secret-password" });
    const res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    assert.equal(res.status, 200);
    const html = await res.text();
    assert.ok(html.includes("alice"));
    assert.ok(html.includes("No authentication is performed"));
  });

  await t.test("POST /login rejects missing fields with 400", async () => {
    const body = new URLSearchParams({ username: "alice" });
    const res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: body.toString()
    });
    assert.equal(res.status, 400);
  });

  await t.test("POST /login rejects JSON body with 415", async () => {
    const res = await fetch(`${BASE}/login`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ username: "alice", password: "secret" })
    });
    assert.equal(res.status, 415);
  });

  await t.test("POST /form accepts multiple fields and returns sorted field names", async () => {
    const form = new URLSearchParams({
      full_name: "John Doe",
      email: "john@example.com",
      age: "28",
      country: "US",
      comment: "Testing form parameter discovery",
      subscribe: "true",
      source: "home"
    });
    const res = await fetch(`${BASE}/form`, {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body: form.toString()
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "ok");
    assert.deepEqual(data.received, [
      "age",
      "comment",
      "country",
      "email",
      "full_name",
      "source",
      "subscribe"
    ]);
  });

  await t.test("Unknown path returns deterministic 404 JSON", async () => {
    const res = await fetch(`${BASE}/this-route-does-not-exist`);
    assert.equal(res.status, 404);
    const data = await res.json();
    assert.equal(data.error, "not_found");
  });

  await t.test("Wrong HTTP method on known route returns 405 with Allow header", async () => {
    const res = await fetch(`${BASE}/search`, { method: "DELETE" });
    assert.equal(res.status, 405);
    assert.equal(res.headers.get("allow"), "GET");
  });
});
