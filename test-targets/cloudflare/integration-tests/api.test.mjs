import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG } from "./lib/config.mjs";

const BASE = CONFIG.API_URL;

test("API target — Live HTTP test suite", async (t) => {
  await t.test("GET / returns root API descriptor", async () => {
    const res = await fetch(`${BASE}/`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.name, "api-target");
    assert.equal(data.openapi, "/openapi.json");
    assert.equal(res.headers.get("cache-control"), "no-store");
    assert.equal(res.headers.get("x-content-type-options"), "nosniff");
  });

  await t.test("GET /openapi.json returns valid OpenAPI 3.0.3 document", async () => {
    const res = await fetch(`${BASE}/openapi.json`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.openapi, "3.0.3");
    assert.ok(data.paths["/api/users"]);
    assert.ok(data.paths["/api/users/{id}"]);
    assert.ok(data.paths["/api/search"]);
    assert.ok(data.paths["/api/orders"]);
    assert.ok(data.paths["/api/client-info"]);
  });

  await t.test("GET /api/users returns full list when no id query provided", async () => {
    const res = await fetch(`${BASE}/api/users`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.ok(Array.isArray(data.users));
    assert.equal(data.users.length, 3);
  });

  await t.test("GET /api/users?id=1 tests QUERY input location and filters", async () => {
    const res = await fetch(`${BASE}/api/users?id=1`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.users.length, 1);
    assert.equal(data.users[0].id, 1);
    assert.equal(data.users[0].username, "alice");
  });

  await t.test("GET /api/users?id=abc returns 400 for invalid query type", async () => {
    const res = await fetch(`${BASE}/api/users?id=abc`);
    assert.equal(res.status, 400);
  });

  await t.test("GET /api/users/{id} tests PATH input location", async () => {
    const res = await fetch(`${BASE}/api/users/2`);
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.user.id, 2);
    assert.equal(data.user.username, "bob");
  });

  await t.test("GET /api/users/{id} returns 404 for unknown user", async () => {
    const res = await fetch(`${BASE}/api/users/999`);
    assert.equal(res.status, 404);
  });

  await t.test("POST /api/search tests JSON_BODY with nested filter object", async () => {
    const payload = {
      keyword: "book",
      filters: {
        category: "book",
        minPrice: 30
      }
    };
    const res = await fetch(`${BASE}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 200);
    const data = await res.json();
    assert.equal(data.keyword, "book");
    assert.equal(data.results.length, 1);
    assert.equal(data.results[0].id, 2);
    assert.equal(data.results[0].name, "Network Protocol Internals");
  });

  await t.test("POST /api/search rejects non-JSON body with 415", async () => {
    const res = await fetch(`${BASE}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "text/plain" },
      body: "keyword=test"
    });
    assert.equal(res.status, 415);
  });

  await t.test("POST /api/search rejects missing keyword with 400", async () => {
    const res = await fetch(`${BASE}/api/search`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify({ filters: {} })
    });
    assert.equal(res.status, 400);
  });

  await t.test("POST /api/orders tests nested shipping JSON object", async () => {
    const payload = {
      productId: 1,
      quantity: 2,
      shipping: {
        city: "Da Nang",
        country: "VN"
      }
    };
    const res = await fetch(`${BASE}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 201);
    const data = await res.json();
    assert.equal(data.orderId, "ORD-1-2");
    assert.equal(data.status, "accepted");
    assert.equal(data.shipping.city, "Da Nang");
    assert.equal(data.shipping.country, "VN");
  });

  await t.test("POST /api/orders returns 404 for non-existent product", async () => {
    const payload = {
      productId: 9999,
      quantity: 1,
      shipping: { city: "Hanoi", country: "VN" }
    };
    const res = await fetch(`${BASE}/api/orders`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(payload)
    });
    assert.equal(res.status, 404);
  });

  await t.test("GET /api/client-info tests required HEADER input discovery", async () => {
    // Missing header -> 400
    const resNoHeader = await fetch(`${BASE}/api/client-info`);
    assert.equal(resNoHeader.status, 400);

    // Wrong header -> 400
    const resWrongHeader = await fetch(`${BASE}/api/client-info`, {
      headers: { "X-Test-Client": "unauthorized-client" }
    });
    assert.equal(resWrongHeader.status, 400);

    // Valid header -> 200
    const resValid = await fetch(`${BASE}/api/client-info`, {
      headers: { "X-Test-Client": "web-security-agent" }
    });
    assert.equal(resValid.status, 200);
    const data = await resValid.json();
    assert.equal(data.client, "web-security-agent");
    assert.equal(data.status, "verified");
  });

  await t.test("Unknown route returns 404", async () => {
    const res = await fetch(`${BASE}/api/not-a-route`);
    assert.equal(res.status, 404);
  });
});
