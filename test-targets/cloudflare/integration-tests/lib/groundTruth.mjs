import { readFileSync } from "node:fs";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const GROUND_TRUTH_DIR = resolve(__dirname, "../../ground-truth");

export function loadGroundTruth(name) {
  const filePath = resolve(GROUND_TRUTH_DIR, `${name}.json`);
  const content = readFileSync(filePath, "utf-8");
  return JSON.parse(content);
}

export const CANONICAL_INPUT_LOCATIONS = Object.freeze([
  "QUERY",
  "PATH",
  "FORM",
  "JSON_BODY",
  "XML_BODY",
  "HEADER",
  "COOKIE",
  "MULTIPART",
  "DOM"
]);

export const CANONICAL_DISCOVERY_SOURCES = Object.freeze([
  "CRAWLER",
  "API_SPEC",
  "HTTP_OBSERVATION",
  "BROWSER",
  "SOURCE_CODE",
  "MANUAL",
  "OTHER"
]);
