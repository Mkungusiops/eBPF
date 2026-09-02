import { defineConfig, devices } from "@playwright/test";

type ProcessGlobal = typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};

const env = (globalThis as ProcessGlobal).process?.env ?? {};
const baseURL =
  env.EBPF_WEB_BASE_URL ?? env.PLAYWRIGHT_BASE_URL ?? "http://127.0.0.1:5173";
const startWebServer = env.PLAYWRIGHT_START_WEB_SERVER === "1";

export default defineConfig({
  testDir: "./e2e",
  // Probes are pinned to a RUNNING deployment and to real credentials. Picking
  // them up here would run them against the dev server, where they fail for
  // reasons that are not bugs. They have their own config
  // (playwright.probe.config.ts) and their own npm script.
  testIgnore: ["probe/**"],
  // Stated rather than defaulted, because the probe config has to stay OUTSIDE
  // it: Playwright clears this directory at the start of every run, so anything
  // nested here is deleted by a concurrent e2e run.
  outputDir: "test-results",
  fullyParallel: true,
  forbidOnly: env.CI === "true",
  retries: env.CI === "true" ? 2 : 0,
  workers: env.CI === "true" ? 2 : undefined,
  timeout: 60_000,
  expect: {
    timeout: 10_000
  },
  reporter: [
    ["list"],
    ["html", { outputFolder: "playwright-report", open: "never" }]
  ],
  use: {
    baseURL,
    ignoreHTTPSErrors: true,
    screenshot: "only-on-failure",
    trace: "retain-on-failure",
    video: "retain-on-failure"
  },
  webServer: startWebServer
    ? {
        command: "npm run dev",
        url: baseURL,
        reuseExistingServer: env.CI !== "true",
        timeout: 120_000
      }
    : undefined,
  projects: [
    {
      name: "chromium",
      use: { ...devices["Desktop Chrome"] }
    }
  ]
});
