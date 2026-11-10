import { defineConfig } from "@playwright/test";

export default defineConfig({
  testDir: "./integration-tests",
  testMatch: "**/*.spec.mjs",
  timeout: 30000,
  use: {
    headless: true
  }
});
