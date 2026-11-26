import { defineConfig } from "@playwright/test";

// Run through ../e2e.sh, which starts Postgres and the server and sets these variables.
const baseURL = process.env.E2E_BASE_URL ?? "http://localhost:3290";

export default defineConfig({
  testDir: "e2e",
  fullyParallel: true,
  workers: 4,
  forbidOnly: true,
  retries: 0,
  timeout: 60_000,
  expect: { timeout: 10_000 },
  reporter: [["list"]],
  use: {
    baseURL,
    viewport: { width: 1280, height: 800 },
    colorScheme: "light",
    trace: "retain-on-failure",
    ...(process.env.CHROME_PATH
      ? { launchOptions: { executablePath: process.env.CHROME_PATH } }
      : { channel: "chrome" }),
  },
});
