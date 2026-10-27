/**
 * Cloudflare Worker — spa-target
 * Backend for SPA test target providing deterministic runtime API endpoints.
 * Static assets (/ and /app.js) are served by Cloudflare Static Assets (env.ASSETS).
 */

const PRODUCTS = Object.freeze([
  { id: 1, name: "Product A", price: 10, category: "Books", description: "Details for product 1" },
  { id: 2, name: "Product B", price: 20, category: "Electronics", description: "Details for product 2" }
]);

const CATEGORIES = Object.freeze([
  { id: "cat-1", name: "Books" },
  { id: "cat-2", name: "Electronics" }
]);

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
  async fetch(request, env) {
    const url = new URL(request.url);
    const path = url.pathname;
    const method = request.method.toUpperCase();

    // 1. GET /api/products
    if (path === "/api/products") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const summaryList = PRODUCTS.map(({ id, name, price, category }) => ({
        id,
        name,
        price,
        category
      }));
      return jsonResponse(summaryList);
    }

    // 2. GET /api/categories
    if (path === "/api/categories") {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      return jsonResponse(CATEGORIES);
    }

    // 3. POST /api/search
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
      const kw = body.keyword.trim().toLowerCase();
      const results = PRODUCTS.filter(
        (p) =>
          p.name.toLowerCase().includes(kw) ||
          p.category.toLowerCase().includes(kw) ||
          kw === "test"
      );
      return jsonResponse({ keyword: body.keyword, results });
    }

    // 4. GET /api/products/{id}
    const productMatch = path.match(/^\/api\/products\/([^/]+)$/);
    if (productMatch) {
      if (method !== "GET") {
        return jsonResponse({ error: "method_not_allowed" }, 405, { Allow: "GET" });
      }
      const rawId = productMatch[1];
      if (!/^\d+$/.test(rawId)) {
        return jsonResponse({ error: "invalid_product_id" }, 400);
      }
      const numericId = parseInt(rawId, 10);
      const product = PRODUCTS.find((p) => p.id === numericId);
      if (!product) {
        return jsonResponse({ error: "product_not_found" }, 404);
      }
      return jsonResponse(product);
    }

    // 5. POST /api/cart
    if (path === "/api/cart") {
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
        body.quantity < 1
      ) {
        return jsonResponse({ error: "invalid_cart_item" }, 400);
      }
      const product = PRODUCTS.find((p) => p.id === body.productId);
      if (!product) {
        return jsonResponse({ error: "product_not_found" }, 404);
      }
      return jsonResponse({
        status: "added",
        productId: body.productId,
        quantity: body.quantity
      });
    }

    // If env.ASSETS binding is available (Cloudflare Workers Static Assets)
    if (env && env.ASSETS) {
      const assetRes = await env.ASSETS.fetch(request);
      if (assetRes.status !== 404) {
        return assetRes;
      }
    }

    // Unknown route
    return jsonResponse({ error: "not_found" }, 404);
  }
};
