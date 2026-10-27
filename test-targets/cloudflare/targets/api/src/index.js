/**
 * Cloudflare Worker — api-target
 * Deterministic REST API for testing API discovery, OpenAPI parsing,
 * path parameters, query parameters, nested JSON bodies, and custom headers.
 */

import { USERS, PRODUCTS } from "./data.js";
import { OPENAPI_SPEC } from "./openapi.js";

function baseHeaders(contentType = "application/json; charset=utf-8") {
  return {
    "Content-Type": contentType,
    "Cache-Control": "no-store",
    "X-Content-Type-Options": "nosniff"
  };
}

function jsonResponse(data, status = 200, extraHeaders = {}) {
  return new Response(JSON.stringify(data), {
    status,
    headers: {
      ...baseHeaders(),
      ...extraHeaders
    }
  });
}

export default {
  async fetch(request) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // 1. GET /
    if (path === "/") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      return jsonResponse({
        name: "api-target",
        openapi: "/openapi.json"
      });
    }

    // 2. GET /openapi.json
    if (path === "/openapi.json") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      return jsonResponse(OPENAPI_SPEC);
    }

    // 3. GET /api/users (query param: id)
    if (path === "/api/users") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const idParam = url.searchParams.get("id");
      if (idParam !== null) {
        if (!/^\d+$/.test(idParam)) {
          return jsonResponse({ error: "invalid_user_id" }, 400);
        }
        const numericId = parseInt(idParam, 10);
        const filtered = USERS.filter((u) => u.id === numericId);
        return jsonResponse({ users: filtered });
      }
      return jsonResponse({ users: USERS });
    }

    // 4. GET /api/users/{id} (path param: id)
    const userPathMatch = path.match(/^\/api\/users\/([^/]+)$/);
    if (userPathMatch) {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const rawId = userPathMatch[1];
      if (!/^\d+$/.test(rawId)) {
        return jsonResponse({ error: "invalid_user_id" }, 400);
      }
      const numericId = parseInt(rawId, 10);
      const user = USERS.find((u) => u.id === numericId);
      if (!user) {
        return jsonResponse({ error: "user_not_found" }, 404);
      }
      return jsonResponse({ user });
    }

    // 5. POST /api/search (nested JSON body: keyword, filters.category, filters.minPrice)
    if (path === "/api/search") {
      if (method !== "POST") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "POST" });
      }
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        return jsonResponse({ error: "unsupported_media_type" }, 415);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: "invalid_json" }, 400);
      }

      if (!body || typeof body !== "object" || typeof body.keyword !== "string") {
        return jsonResponse({ error: "keyword_required" }, 400);
      }

      const keyword = body.keyword.trim().toLowerCase();
      let results = PRODUCTS.filter(
        (p) =>
          p.name.toLowerCase().includes(keyword) ||
          p.category.toLowerCase().includes(keyword)
      );

      if (body.filters && typeof body.filters === "object") {
        if (typeof body.filters.category === "string" && body.filters.category.trim() !== "") {
          const cat = body.filters.category.trim().toLowerCase();
          results = results.filter((p) => p.category.toLowerCase() === cat);
        }
        if (typeof body.filters.minPrice === "number") {
          results = results.filter((p) => p.price >= body.filters.minPrice);
        }
      }

      return jsonResponse({
        keyword: body.keyword,
        results
      });
    }

    // 6. POST /api/orders (nested JSON body: productId, quantity, shipping.city, shipping.country)
    if (path === "/api/orders") {
      if (method !== "POST") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "POST" });
      }
      const contentType = request.headers.get("content-type") || "";
      if (!contentType.toLowerCase().includes("application/json")) {
        return jsonResponse({ error: "unsupported_media_type" }, 415);
      }
      let body;
      try {
        body = await request.json();
      } catch {
        return jsonResponse({ error: "invalid_json" }, 400);
      }

      if (
        !body ||
        typeof body !== "object" ||
        typeof body.productId !== "number" ||
        typeof body.quantity !== "number" ||
        body.quantity < 1 ||
        !body.shipping ||
        typeof body.shipping !== "object" ||
        typeof body.shipping.city !== "string" ||
        typeof body.shipping.country !== "string"
      ) {
        return jsonResponse({ error: "invalid_order_data" }, 400);
      }

      const product = PRODUCTS.find((p) => p.id === body.productId);
      if (!product) {
        return jsonResponse({ error: "product_not_found" }, 404);
      }

      return jsonResponse(
        {
          orderId: `ORD-${body.productId}-${body.quantity}`,
          status: "accepted",
          productId: body.productId,
          quantity: body.quantity,
          shipping: {
            city: body.shipping.city,
            country: body.shipping.country
          }
        },
        201
      );
    }

    // 7. GET /api/client-info (header input: X-Test-Client)
    if (path === "/api/client-info") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const clientHeader = request.headers.get("x-test-client");
      if (clientHeader !== "web-security-agent") {
        return jsonResponse({ error: "missing_or_invalid_header" }, 400);
      }
      return jsonResponse({
        client: "web-security-agent",
        status: "verified"
      });
    }

    // Unknown route
    return jsonResponse({ error: "not_found" }, 404);
  }
};
