/**
 * Target endpoint URL configuration.
 * Defaults to localhost ports for local wrangler dev execution.
 * Overridden by environment variables when testing deployed Cloudflare Workers.
 */

export const CONFIG = Object.freeze({
  BASIC_URL: (process.env.BASIC_URL || "http://localhost:8787").replace(/\/+$/, ""),
  API_URL: (process.env.API_URL || "http://localhost:8788").replace(/\/+$/, ""),
  SPA_URL: (process.env.SPA_URL || "http://localhost:8789").replace(/\/+$/, "")
});
