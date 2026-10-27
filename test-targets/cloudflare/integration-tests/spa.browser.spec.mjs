import { test, expect } from "@playwright/test";
import { CONFIG } from "./lib/config.mjs";

test.describe("SPA Target — Browser Runtime Discovery Verification", () => {
  test("distinguishes static crawler vs browser runtime requests and button clicks", async ({ page }) => {
    const recordedRequests = [];

    page.on("request", (req) => {
      const url = new URL(req.url());
      recordedRequests.push({
        method: req.method(),
        path: url.pathname,
        postData: req.postData()
      });
    });

    // 1. Initial page load
    await page.goto(CONFIG.SPA_URL, { waitUntil: "networkidle" });

    // Verify static HTML does not expose /api/ in links
    const content = await page.content();
    expect(content).not.toContain('href="/api/');
    expect(content).not.toContain('action="/api/');

    // Check runtime requests upon page load:
    // Should have: /, /app.js, /api/products, /api/categories
    const loadPaths = recordedRequests.map((r) => r.path);
    expect(loadPaths).toContain("/");
    expect(loadPaths).toContain("/app.js");
    expect(loadPaths).toContain("/api/products");
    expect(loadPaths).toContain("/api/categories");

    // Click-only endpoints must NOT be requested on initial load
    expect(loadPaths).not.toContain("/api/search");
    expect(loadPaths).not.toContain("/api/cart");
    expect(loadPaths.some((p) => p.startsWith("/api/products/"))).toBeFalsy();

    // 2. Click Search button
    const searchReqPromise = page.waitForRequest(
      (req) => req.url().includes("/api/search") && req.method() === "POST"
    );
    await page.click("#btn-search");
    const searchReq = await searchReqPromise;
    expect(searchReq).toBeTruthy();
    const searchData = JSON.parse(searchReq.postData() || "{}");
    expect(searchData.keyword).toBe("test");

    // 3. Click Details button on Product 1
    await page.waitForSelector("#btn-details-1");
    const detailsReqPromise = page.waitForRequest(
      (req) => req.url().includes("/api/products/1") && req.method() === "GET"
    );
    await page.click("#btn-details-1");
    const detailsReq = await detailsReqPromise;
    expect(detailsReq).toBeTruthy();

    // 4. Click Add to Cart button on Product 1
    await page.waitForSelector("#btn-cart-1");
    const cartReqPromise = page.waitForRequest(
      (req) => req.url().includes("/api/cart") && req.method() === "POST"
    );
    await page.click("#btn-cart-1");
    const cartReq = await cartReqPromise;
    expect(cartReq).toBeTruthy();
    const cartData = JSON.parse(cartReq.postData() || "{}");
    expect(cartData.productId).toBe(1);
    expect(cartData.quantity).toBe(1);
  });
});
