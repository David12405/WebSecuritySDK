import test from "node:test";
import assert from "node:assert/strict";
import {
  loadGroundTruth,
  CANONICAL_INPUT_LOCATIONS,
  CANONICAL_DISCOVERY_SOURCES
} from "./lib/groundTruth.mjs";

const TARGETS = ["basic", "api", "spa"];

for (const targetName of TARGETS) {
  test(`Ground truth [${targetName}.json] schema and consistency`, () => {
    const doc = loadGroundTruth(targetName);

    // Root fields
    assert.equal(doc.schemaVersion, "1.0");
    assert.equal(doc.target, targetName);
    assert.ok(typeof doc.workerName === "string" && doc.workerName.length > 0);
    assert.ok(typeof doc.description === "string" && doc.description.length > 0);
    assert.ok(Array.isArray(doc.endpoints) && doc.endpoints.length > 0);

    // notFoundProbe check
    assert.ok(doc.notFoundProbe, "notFoundProbe must be defined");
    assert.equal(doc.notFoundProbe.expect.status, 404);

    const seenIdentities = new Set();
    const seenIds = new Set();

    for (const ep of doc.endpoints) {
      // Identity uniqueness (method + path)
      const identity = `${ep.method.toUpperCase()} ${ep.path}`;
      assert.ok(!seenIdentities.has(identity), `Duplicate endpoint identity: ${identity}`);
      seenIdentities.add(identity);

      // Endpoint ID uniqueness
      assert.ok(!seenIds.has(ep.id), `Duplicate endpoint id: ${ep.id}`);
      seenIds.add(ep.id);

      // Discovery sources validation
      assert.ok(Array.isArray(ep.expectedDiscoverySources));
      for (const src of ep.expectedDiscoverySources) {
        assert.ok(
          CANONICAL_DISCOVERY_SOURCES.includes(src),
          `Invalid discovery source in ${ep.id}: ${src}`
        );
      }
      for (const src of ep.optionalDiscoverySources || []) {
        assert.ok(
          CANONICAL_DISCOVERY_SOURCES.includes(src),
          `Invalid optional discovery source in ${ep.id}: ${src}`
        );
      }

      // Path parameters check: if path contains {name}, must have matching PATH input
      const pathParamMatches = [...ep.path.matchAll(/\{([^}]+)\}/g)].map((m) => m[1]);
      for (const paramName of pathParamMatches) {
        const matchingInput = ep.inputs.find(
          (i) => i.location === "PATH" && i.name === paramName
        );
        assert.ok(
          matchingInput,
          `Endpoint ${ep.id} path has '{${paramName}}' but no PATH input defined with name '${paramName}'`
        );
      }

      // Input locations and nested inputs validation
      const inputNames = new Set(ep.inputs.map((i) => i.name));
      for (const input of ep.inputs) {
        assert.ok(
          CANONICAL_INPUT_LOCATIONS.includes(input.location),
          `Invalid InputLocation in ${ep.id}: ${input.location}`
        );
        if (input.parent) {
          assert.ok(
            inputNames.has(input.parent),
            `Nested input '${input.name}' in ${ep.id} references non-existent parent '${input.parent}'`
          );
        }
      }

      // Probe validation
      assert.ok(ep.probe, `Endpoint ${ep.id} missing probe definition`);
      assert.ok(ep.probe.request, `Endpoint ${ep.id} probe missing request`);
      assert.ok(ep.probe.expect, `Endpoint ${ep.id} probe missing expect`);
      assert.ok(
        typeof ep.probe.expect.status === "number",
        `Endpoint ${ep.id} probe expect status must be a number`
      );
    }
  });
}
