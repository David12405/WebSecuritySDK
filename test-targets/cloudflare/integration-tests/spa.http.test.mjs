import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG } from "./lib/config.mjs";

const BASE = CONFIG.SPA_URL;

test("SPA target — Live HTTP test suite", async (t) => {
  await t.test("GET / returns HTML shell with NO direct /api/ links", async () => {
    const res = await fetch(`${BASE}/`);
    assert.equal(res.status, 200);
    const ct = res.headers.get("content-type") || "";
    assert.ok(ct.includes("text/html"));

    const html = await res.text();
    // Static crawler inspection: verify no direct <a> or <form> links to /api
    assert.ok(!html.includes('href="/api/'), "Static HTML must not contain <a href='/api/'>");
    assert.ok(!html.includes('action="/api/'), "Static HTML must not contain <form action='/api/'>");
    assert.ok(!html.includes('/api/'), "Static HTML must not contain any /api/ string");
    assert.ok(html.includes("/app.js"), "Static HTML must link to /app.js");
  });

  await t.test("GET /app.js returns client JavaScript", async () => {
    const res = await fetch(`${BASE}/app.js`);
    assert.equal(res.status, 200);
    const text = await res.text();
    assert.ok(text.includes("loadCategories"));
    assert.ok(text.includes("loadProducts"));
    assert.ok(text.includes("btn-search"));
  });

  await t.test("GET /api/products returns deterministic product list", async () => {
    const res = await fetch(`${BASE}/api/products`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 2);
    assert.equal(data[0].id, 1);
    assert.equal(data[0].name, "Product A");
  });

  await t.test("GET /api/categories returns deterministic category list", async () => {
    const res = await fetch(`${BASE}/api/categories`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data));
    assert.equal(data.length, 2);
    assert.equal(data[0].id, "cat-1");
  });

  await t.test("POST /api/search returns filtered results", async () => {
    const res = await fetch(`${BASE}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ keyword: "Product A" })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.results.length, 1);
    assert.equal(data.results[0].id, 1);
  });

  await t.test("GET /api/products/1 returns product details", async () => {
    const res = await fetch(`${BASE}/api/products/1`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.id, 1);
    assert.ok(data.description.includes("Details for product 1"));
  });

  await t.test("POST /api/cart accepts order item and returns status", async () => {
    const res = await fetch(`${BASE}/api/cart`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ productId: 1, quantity: 2 })
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.status, "added");
    assert.equal(data.productId, 1);
    assert.equal(data.quantity, 2);
  });

  await t.test("Unknown route returns 404", async () => {
    const res = await fetch(`${BASE}/unknown-route`);
    assert.equal(res.status, 404);
  });
});
