/**
 * Starts all three test targets locally using Wrangler dev:
 * - basic-target on http://localhost:8787
 * - api-target on http://localhost:8788
 * - spa-target on http://localhost:8789
 *
 * Usage:
 *   node scripts/dev-all.mjs
 */

import { spawn } from "node:child_process";
import { resolve, dirname } from "node:path";
import { fileURLToPath } from "node:url";

const __dirname = dirname(fileURLToPath(import.meta.url));
const ROOT_DIR = resolve(__dirname, "..");

const TARGETS = [
  { name: "basic", config: "targets/basic/wrangler.jsonc", port: 8787 },
  { name: "api", config: "targets/api/wrangler.jsonc", port: 8788 },
  { name: "spa", config: "targets/spa/wrangler.jsonc", port: 8789 }
];

const children = [];

function startTarget(target) {
  const isWindows = process.platform === "win32";
  const cmd = isWindows ? "npx.cmd" : "npx";
  const args = [
    "wrangler",
    "dev",
    "--config",
    target.config,
    "--port",
    String(target.port),
    "--ip",
    "127.0.0.1"
  ];

  console.log(`[${target.name}] Starting wrangler dev on port ${target.port}...`);
  const child = spawn(cmd, args, {
    cwd: ROOT_DIR,
    stdio: ["ignore", "pipe", "pipe"],
    shell: isWindows
  });

  child.stdout.on("data", (data) => {
    const text = data.toString().trim();
    if (text) {
      console.log(`[${target.name}] ${text}`);
    }
  });

  child.stderr.on("data", (data) => {
    const text = data.toString().trim();
    if (text) {
      console.error(`[${target.name}:err] ${text}`);
    }
  });

  child.on("exit", (code) => {
    console.log(`[${target.name}] Process exited with code ${code}`);
  });

  children.push(child);
}

function cleanup() {
  console.log("\nShutting down dev servers...");
  for (const child of children) {
    try {
      if (process.platform === "win32") {
        spawn("taskkill", ["/pid", child.pid, "/f", "/t"]);
      } else {
        child.kill("SIGTERM");
      }
    } catch {
      // ignore
    }
  }
  process.exit(0);
}

process.on("SIGINT", cleanup);
process.on("SIGTERM", cleanup);

for (const target of TARGETS) {
  startTarget(target);
}

console.log("All three targets launched. Press Ctrl+C to terminate all.");
