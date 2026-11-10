import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG } from "./lib/config.mjs";
import { loadGroundTruth } from "./lib/groundTruth.mjs";

const TARGET_MAP = {
  basic: CONFIG.BASIC_URL,
  api: CONFIG.API_URL,
  spa: CONFIG.SPA_URL
};

for (const [targetName, baseUrl] of Object.entries(TARGET_MAP)) {
  test(`Conformance Oracle — Target [${targetName}] against Ground Truth`, async (t) => {
    const gt = loadGroundTruth(targetName);

    // 1. notFoundProbe
    if (gt.notFoundProbe) {
      await t.test(`NotFound Probe: ${gt.notFoundProbe.path}`, async () => {
        const res = await fetch(`${baseUrl}${gt.notFoundProbe.path}`);
        assert.equal(
          res.status,
          gt.notFoundProbe.expect.status,
          `Expected 404 on ${gt.notFoundProbe.path}, got ${res.status}`
        );
        if (gt.notFoundProbe.expect.contentType) {
          const ct = res.headers.get("content-type") || "";
          assert.ok(
            ct.includes(gt.notFoundProbe.expect.contentType),
            `Expected Content-Type ${gt.notFoundProbe.expect.contentType}, got ${ct}`
          );
        }
      });
    }

    // 2. Each endpoint's probe
    for (const ep of gt.endpoints) {
      const probe = ep.probe;
      await t.test(`Endpoint [${ep.id}] ${ep.method} ${ep.path}`, async () => {
        const req = probe.request;
        const expect = probe.expect;
        const url = `${baseUrl}${req.path}`;
        const fetchOptions = {
          method: req.method || ep.method,
          headers: req.headers || {},
          redirect: "manual"
        };
        if (req.body) {
          fetchOptions.body = req.body;
        }

        const res = await fetch(url, fetchOptions);

        // Check Status
        assert.equal(
          res.status,
          expect.status,
          `Endpoint ${ep.id}: expected status ${expect.status}, got ${res.status}`
        );

        // Check Content-Type if expected
        if (expect.contentType) {
          const ct = res.headers.get("content-type") || "";
          assert.ok(
            ct.toLowerCase().includes(expect.contentType.toLowerCase()),
            `Endpoint ${ep.id}: expected Content-Type containing '${expect.contentType}', got '${ct}'`
          );
        }

        // Check Redirect Location if expected
        if (expect.location) {
          const loc = res.headers.get("location");
          assert.equal(
            loc,
            expect.location,
            `Endpoint ${ep.id}: expected Location '${expect.location}', got '${loc}'`
          );
        }

        // Check Set-Cookie if expected
        if (expect.setCookieName) {
          const sc = res.headers.get("set-cookie") || "";
          assert.ok(
            sc.includes(`${expect.setCookieName}=`),
            `Endpoint ${ep.id}: expected Set-Cookie '${expect.setCookieName}', got '${sc}'`
          );
        }

        // Check body contains if expected
        if (Array.isArray(expect.bodyContains) && expect.bodyContains.length > 0) {
          const text = await res.text();
          for (const snippet of expect.bodyContains) {
            assert.ok(
              text.includes(snippet),
              `Endpoint ${ep.id}: response body missing expected snippet '${snippet}'`
            );
          }
        }
      });
    }
  });
}
