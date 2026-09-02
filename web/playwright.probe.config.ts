import { defineConfig, devices } from "@playwright/test";

type ProcessGlobal = typeof globalThis & {
  process?: { env?: Record<string, string | undefined> };
};

const env = (globalThis as ProcessGlobal).process?.env ?? {};

/**
 * Probes: the console driven against a stack that is ALREADY RUNNING.
 *
 * These are a different kind of claim from e2e/*.spec.ts. Those render the
 * frontend against a mocked backend and answer "does the console behave?".
 * These answer "does THIS DEPLOYMENT behave?" — with a real session, real
 * agents, real telemetry and the real reverse proxy in the path. Both are
 * needed and neither substitutes for the other: a mock cannot catch an nginx
 * that buffers the SSE stream or a service worker serving a stale shell, and a
 * live rig cannot be made to produce the malformed payloads the mocked suite
 * checks.
 *
 * DELIBERATELY STARTS NOTHING. Point it at a deployment:
 *
 *   PROBE_URL=https://engine.adanianlabs.io  PROBE_KIND=engine \
 *   PROBE_USER=admin PROBE_PASSWORD=…  npm run test:probe
 *
 *   PROBE_URL=https://console.adanianlabs.io PROBE_KIND=controlplane \
 *   PROBE_USER=op-… PROBE_PASSWORD=…    npm run test:probe
 *
 * These are kept OUT of the default e2e config's testDir by that config's
 * `testIgnore`, so a normal `npm run e2e` never tries to reach a live estate.
 */
const hasCredentials = Boolean(env.PROBE_URL && env.PROBE_USER && env.PROBE_PASSWORD);

// Must agree with storageStatePath() in e2e/probe/support/global-setup.ts. Kept
// as a small duplicate rather than an import: a Playwright config is loaded
// before the test transform, so importing a spec-side module here is a
// resolution problem for a four-line function.
const probeKind =
  env.PROBE_KIND ?? (/console/i.test(env.PROBE_URL ?? "") ? "controlplane" : "engine");
const probeHost = (() => {
  try {
    return new URL(env.PROBE_URL ?? "").host.replace(/[^a-zA-Z0-9.-]/g, "_");
  } catch {
    return "unknown";
  }
})();
const storageStatePath = `.auth/probe-auth-${probeKind}-${probeHost}.json`;

export default defineConfig({
  testDir: "./e2e/probe",
  // One sign-in for the whole run, reused as storageState. The engine
  // rate-limits /api/login (5/min/IP), so a login per test trips its own
  // brute-force guard and then reports a healthy deployment as broken.
  globalSetup: hasCredentials ? "./e2e/probe/support/global-setup.ts" : undefined,
  // TOP-LEVEL, not "test-results/probe". Playwright REMOVES outputDir at the
  // start of every run, and the e2e config's outputDir is "test-results" — so
  // nesting the probe's artifacts inside it meant any concurrent `npm run e2e`
  // deleted the probe's traces mid-flight. The probe then failed on artifact
  // I/O (ENOENT on a .playwright-artifacts-N path) inside whichever test was
  // running, which reads as a product failure and is a directory collision.
  outputDir: `test-results-probe-${probeKind}`,
  // They read (and, where explicitly enabled, write) shared estate state, and
  // the engine rate-limits /api/login as brute-force defence. Serial.
  fullyParallel: false,
  workers: 1,
  retries: 0,
  // Real networks, a real OIDC redirect chain, and agent heartbeats that are
  // only eventually consistent.
  timeout: 180_000,
  expect: { timeout: 30_000 },
  // PER TARGET, for the same reason the session cache and the artifact
  // directory are: probing the engine and then the control plane is the normal
  // way to certify a release, and a shared folder means the second run
  // silently destroys the first one's traces, screenshots and videos — the
  // evidence you went and collected.
  reporter: [
    ["list"],
    ["html", { outputFolder: `playwright-report-probe-${probeKind}`, open: "never" }]
  ],
  use: {
    ...devices["Desktop Chrome"],
    // Watchable runs. Headless, every click lands in the same millisecond and
    // a human watching a --headed run sees a blur. PROBE_SLOWMO=<ms> puts a
    // pause between actions so a demo or a debugging session can be followed.
    // Unset in CI, where it would only add minutes.
    launchOptions: env.PROBE_SLOWMO ? { slowMo: Number(env.PROBE_SLOWMO) } : undefined,
    // A bounded actionability wait. Without this, `locator.click()` on a
    // control that never becomes enabled retries until the 180s TEST timeout
    // and then surfaces as an error on whatever line the teardown happens to
    // be — which is exactly how a disabled Sign-in button was reported as
    // "browserContext.close failed" 180 seconds after the fact. 15s fails fast
    // and Playwright's call log names the element and the reason.
    actionTimeout: 15_000,
    baseURL: env.PROBE_URL ?? "http://127.0.0.1:8090",
    viewport: { width: 1600, height: 1000 },
    ignoreHTTPSErrors: true,
    trace: "retain-on-failure",
    screenshot: "only-on-failure",
    video: "retain-on-failure",
    // The shared session from globalSetup. Absent when no credentials were
    // given, in which case every credentialed spec skips.
    storageState: hasCredentials ? storageStatePath : undefined,
    // The console registers a service worker. In a driven browser it
    // intercepts navigations and turns a re-goto into ERR_ABORTED with
    // multi-minute stalls. The ONE spec that is about the worker opts back in.
    serviceWorkers: "block"
  },
  // No per-project `use` override: spreading devices["Desktop Chrome"] again
  // here would silently reinstate its 1280x720 viewport over the one above,
  // and below ~900px of height the virtualised process lists render
  // zero-height rows — a layout failure that reads as missing data.
  projects: [{ name: "chromium" }]
});
