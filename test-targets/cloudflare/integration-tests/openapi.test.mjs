import test from "node:test";
import assert from "node:assert/strict";
import { CONFIG } from "./lib/config.mjs";
import { loadGroundTruth } from "./lib/groundTruth.mjs";

const BASE = CONFIG.API_URL;

test("OpenAPI Specification — Verification & Ground Truth Alignment", async (t) => {
  const res = await fetch(`${BASE}/openapi.json`);
  assert.equal(res.status, 200);
  const spec = await res.json();

  const gt = loadGroundTruth("api");
  const specEndpointsInGt = gt.endpoints.filter((ep) => ep.discoverability.inSpec);

  await t.test("OpenAPI document structure is compliant with 3.0.x", () => {
    assert.match(spec.openapi, /^3\.0\.\d+$/);
    assert.ok(spec.info && spec.info.title && spec.info.version);
    assert.ok(Array.isArray(spec.servers) && spec.servers.length > 0);
    assert.ok(spec.paths && typeof spec.paths === "object");
  });

  await t.test("Every inSpec ground-truth endpoint is declared in OpenAPI spec", () => {
    for (const ep of specEndpointsInGt) {
      const pathItem = spec.paths[ep.path];
      assert.ok(pathItem, `Path '${ep.path}' missing from OpenAPI spec`);
      const methodItem = pathItem[ep.method.toLowerCase()];
      assert.ok(
        methodItem,
        `Method '${ep.method}' for path '${ep.path}' missing from OpenAPI spec`
      );
    }
  });

  await t.test("Every declared OpenAPI operation corresponds to a ground-truth endpoint", () => {
    for (const [pathStr, pathItem] of Object.entries(spec.paths)) {
      for (const [methodStr, operation] of Object.entries(pathItem)) {
        if (["parameters", "summary", "description"].includes(methodStr)) continue;
        const matchingGt = gt.endpoints.find(
          (ep) =>
            ep.path === pathStr &&
            ep.method.toUpperCase() === methodStr.toUpperCase() &&
            ep.discoverability.inSpec
        );
        assert.ok(
          matchingGt,
          `OpenAPI operation ${methodStr.toUpperCase()} ${pathStr} is not declared in ground truth with inSpec: true`
        );
      }
    }
  });

  await t.test("OpenAPI parameters match ground-truth inputs", () => {
    for (const ep of specEndpointsInGt) {
      const op = spec.paths[ep.path][ep.method.toLowerCase()];
      const opParams = op.parameters || [];

      for (const param of opParams) {
        const matchingInput = ep.inputs.find(
          (i) => i.name.toLowerCase() === param.name.toLowerCase()
        );
        assert.ok(
          matchingInput,
          `OpenAPI parameter '${param.name}' in ${ep.id} not found in ground truth inputs`
        );
      }
    }
  });
});
