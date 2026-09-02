import type { ConsoleMessage, Page } from "@playwright/test";

import { PAGE_ROUTES, PROTECTED_PAGE_ROUTES, isServedApiPath } from "../support/contracts";
import {
  expect,
  hasCredentials,
  hasTarget,
  readProbeEnv,
  readWhoami,
  releaseBlocking,
  signIn,
  test
} from "./support/live";

/**
 * The console against a LIVE deployment.
 *
 * These run identically against either half of the platform — the single-tenant
 * engine and the multi-tenant control plane — because one frontend serves both
 * and the claims below are true of both. What differs (auth flow, wire shapes,
 * tenant scoping) is handled by the sign-in helper and by the two
 * deployment-specific probe files beside this one.
 *
 * WHY THESE ARE PROBES AND NOT E2E: every one of them is a claim about the
 * DEPLOYMENT, not about the frontend. Whether the reverse proxy leaves the SSE
 * stream unbuffered, whether the served asset hashes match the build, whether
 * a real session survives a real redirect chain — none of it is observable
 * against a mock, and all of it has broken this estate at least once.
 */

const env = readProbeEnv();

test.describe("live deployment", () => {
  test.skip(!hasTarget(env), "Set PROBE_URL to certify a deployment");
  test.describe.configure({ mode: "serial" });

  test("health and readiness answer, and readiness speaks for its dependencies", async ({ page }) => {
    const health = await page.request.get("/healthz", { failOnStatusCode: false });
    expect(health.status(), "/healthz must be a constant, dependency-free liveness signal").toBe(200);

    const ready = await page.request.get("/readyz", { failOnStatusCode: false });
    // Readiness may legitimately report NOT ready; what it must never do is
    // 404, which is how a load balancer ends up treating a broken box as fine.
    expect([200, 503], `/readyz answered ${ready.status()}`).toContain(ready.status());
  });

  // The run shares ONE signed-in session (see support/global-setup.ts), so an
  // anonymous claim needs a context of its own. Taking the `browser` fixture
  // rather than `page` is the whole point: `page` is already authenticated and
  // these two would pass while testing nothing.
  test("an unauthenticated visitor cannot read the console's data", async ({ browser }) => {
    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      // Explicitly EMPTY, not `undefined`: `browser.newContext()` inherits the
      // config's `use`, so an omitted value would hand back the shared
      // signed-in session and these tests would pass while testing nothing.
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    try {
      for (const path of ["/api/whoami", "/api/alerts", "/api/choke/circuits", "/api/stream"]) {
        const response = await context.request.get(path, { failOnStatusCode: false, timeout: 20_000 });
        expect(response.status(), `${path} answered ${response.status()} without a session`).toBe(401);
      }
    } finally {
      await context.close();
    }
  });

  test("an unauthenticated visitor is sent to a login surface", async ({ browser }) => {
    // HOW differs by deployment and both are correct: the engine 303s
    // server-side, the control plane serves the SPA shell and the client
    // redirects once /api/whoami answers 401. What must be true of both is
    // that an operator ends up somewhere they can sign in.
    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      // Explicitly EMPTY, not `undefined`: `browser.newContext()` inherits the
      // config's `use`, so an omitted value would hand back the shared
      // signed-in session and these tests would pass while testing nothing.
      storageState: { cookies: [], origins: [] },
      serviceWorkers: "block"
    });
    const page = await context.newPage();
    try {
      for (const route of PROTECTED_PAGE_ROUTES) {
        await page.goto(route.path, { waitUntil: "domcontentloaded" });
        await expect
          .poll(() => page.url(), {
            timeout: 30_000,
            message: `${route.path} left an anonymous visitor on the console`
          })
          .toMatch(/\/login|\/auth\/|\/realms\//);
      }
    } finally {
      await context.close();
    }
  });

  test("version reports which code is actually running", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    await signIn(page, env);

    const response = await page.request.get("/api/version");
    expect(response.status()).toBe(200);
    const body = (await response.json()) as Record<string, unknown>;

    // "Which code is running?" is a question this estate could not answer once:
    // the version was a hardcoded constant on one plane and a hash of the
    // frontend assets on the other.
    expect(String(body.sha ?? ""), "no build identifier reported").not.toBe("");
    expect(body.revision ?? body.sha, "no git revision reported").toBeTruthy();

    if (body.dirty === true) {
      test.info().annotations.push({
        type: "warning",
        description: `deployed from an uncommitted tree (${String(body.sha)}) — /api/version cannot identify this build`
      });
    }
  });

  test("every route renders real content with a real session, and logs nothing release-blocking", async ({
    page
  }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    // SIGN IN FIRST, THEN LISTEN.
    //
    // The order is the whole point. `signIn` is allowed to recover a stale
    // saved session, and on the control plane that recovery is noisy by
    // design: nginx serves the SPA shell 200 for every path, so the console
    // BOOTS unauthenticated, fires its whole request set, takes fourteen 401s,
    // and only then follows the OIDC chain and comes back authenticated. Those
    // 401s are a fact about the cached state file, not about the deployment —
    // and this is the one test that counts console errors, so listening across
    // sign-in made it fail on harness noise while the estate was healthy.
    // (Measured: a dead-session load of "/" logs exactly 14; a live one logs 0.)
    await signIn(page, env);

    const consoleErrors: string[] = [];
    const pageErrors: string[] = [];
    const httpFailures: string[] = [];
    const onConsole = (message: ConsoleMessage) => {
      if (message.type() === "error") consoleErrors.push(message.text());
    };
    page.on("console", onConsole);
    page.on("pageerror", (error) => pageErrors.push(error.message));
    page.on("response", (response) => {
      if (response.status() >= 500) {
        httpFailures.push(`${response.status()} ${new URL(response.url()).pathname}`);
      }
    });

    for (const route of PAGE_ROUTES.filter((r) => !r.public)) {
      await page.goto(route.path, { waitUntil: "domcontentloaded" });
      await expect(page.locator("#root"), `${route.path} rendered an empty shell`).not.toBeEmpty();
      await expect(
        page.getByRole("heading", { name: /stopped rendering/i }),
        `${route.path} fell to the error boundary`
      ).toHaveCount(0);
    }

    expect(releaseBlocking(consoleErrors), "browser console errors on a live deployment").toEqual([]);
    expect(pageErrors, "uncaught exceptions on a live deployment").toEqual([]);
    expect([...new Set(httpFailures)], "5xx responses while rendering the console").toEqual([]);
  });

  /**
   * WHAT BUG THIS PINS: the console asking a live server for a route it does
   * not serve. Against a mock every path resolves, so this is the only layer
   * that can see it — and a 404'd panel renders quiet, not broken.
   */
  test("every API the console calls is actually served here", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    const notFound: string[] = [];
    const unknownToTheContract: string[] = [];
    page.on("response", (response) => {
      const path = new URL(response.url()).pathname;
      if (!path.startsWith("/api/")) return;
      if (!isServedApiPath(path)) unknownToTheContract.push(path);
      if (response.status() === 404) notFound.push(path);
    });

    await signIn(page, env);
    for (const route of PAGE_ROUTES.filter((r) => !r.public)) {
      await page.goto(route.path, { waitUntil: "domcontentloaded" });
      await expect(page.locator("#root")).not.toBeEmpty();
    }

    expect([...new Set(unknownToTheContract)], "paths outside the declared API contract").toEqual([]);
    // 404s that are lab-gated are expected on a customer deployment: /api/attacks
    // and /api/honeypots are OFF by default and the console gates its surfaces
    // on lab_mode rather than on the 404. Anything else is a genuine miss.
    const labGated = /^\/api\/(attacks|honeypots|run-attack)$/;
    expect(
      [...new Set(notFound)].filter((path) => !labGated.test(path)),
      "the console asked this deployment for routes it does not serve"
    ).toEqual([]);
  });

  /**
   * WHAT BUG THIS PINS: an nginx that buffers the SSE stream. The engine emits
   * `X-Accel-Buffering: no` precisely so a proxy cannot hold frames, and the
   * symptom of getting this wrong is a console that looks alive and is minutes
   * behind — indistinguishable from a quiet estate.
   *
   * WHY IT IS HERE AND NOT IN E2E: the mocked suite replaces EventSource
   * outright, so the proxy is not in the path at all.
   */
  /**
   * WHAT BUG THIS PINS: a reverse proxy that BUFFERS the event stream. The
   * symptom is a console that looks alive and is minutes behind — which is
   * indistinguishable, on screen, from a quiet estate.
   *
   * WHY IT IS MEASURED AND NOT READ OFF A HEADER: both servers set
   * `X-Accel-Buffering: no`, but that header is an instruction TO nginx and
   * nginx strips it before the browser ever sees it. Asserting its presence at
   * the client fails on a correctly-configured deployment, which is exactly
   * the kind of test that gets deleted rather than believed. What can be
   * observed is behaviour: on an OPEN connection, a frame must arrive before
   * the connection ends. Both servers emit a `heartbeat` every 15s for this
   * purpose, so a buffered stream delivers nothing inside the window and an
   * unbuffered one delivers at least one frame.
   *
   * WHY IT IS HERE AND NOT IN E2E: the mocked suite replaces EventSource
   * outright, so no proxy is in the path at all.
   */
  test("the event stream opens through the real proxy and delivers frames unbuffered", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    // Two keepalive intervals plus the redirect chain.
    test.setTimeout(120_000);
    await signIn(page, env);

    let headers: Record<string, string> | null = null;
    page.on("response", (response) => {
      if (new URL(response.url()).pathname === "/api/stream" && !headers) headers = response.headers();
    });

    const result = await page.evaluate(
      () =>
        new Promise<{ opened: boolean; frames: number; firstFrameMs: number; withCredentials: boolean }>(
          (resolve) => {
            const startedAt = Date.now();
            const source = new EventSource("/api/stream");
            let frames = 0;
            let firstFrameMs = -1;
            const done = (opened: boolean) => {
              const { withCredentials } = source;
              source.close();
              resolve({ opened, frames, firstFrameMs, withCredentials });
            };
            // 35s: long enough for two 15s keepalives, so a single missed tick
            // is not a failure.
            const timer = window.setTimeout(() => done(source.readyState === EventSource.OPEN), 35_000);
            source.onmessage = () => {
              frames += 1;
              if (firstFrameMs < 0) firstFrameMs = Date.now() - startedAt;
              if (frames >= 1) {
                window.clearTimeout(timer);
                done(true);
              }
            };
            source.onerror = () => {
              window.clearTimeout(timer);
              done(false);
            };
          }
        )
    );

    expect(result.opened, "the browser could not open the event stream through this deployment").toBe(true);
    // Same-origin: withCredentials would make this a cross-origin request, and
    // the session cookie is same-site.
    expect(result.withCredentials).toBe(false);
    expect(
      result.frames,
      "no frame arrived on an open stream inside two keepalive intervals — the proxy is buffering, or the server stopped emitting keepalives"
    ).toBeGreaterThan(0);

    await expect
      .poll(() => headers, { timeout: 10_000, message: "no response headers seen for /api/stream" })
      .not.toBeNull();
    const seen = headers as unknown as Record<string, string>;
    expect(seen["content-type"] ?? "", "the stream must be served as SSE").toContain("text/event-stream");
    expect(seen["cache-control"] ?? "", "a cached security stream is a stale one").toMatch(/no-cache|no-store/);
  });

  /**
   * WHAT BUG THIS PINS, and it took this estate offline once already: HTML
   * shells must never be cached. The engine serves auth-gated pages at clean
   * URLs, so a cached "/" would let a browser answer the navigation from disk
   * and skip the login redirect entirely.
   */
  test("HTML is never cached and hashed assets always are", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    await signIn(page, env);

    for (const route of PAGE_ROUTES) {
      const response = await page.request.get(route.path, { failOnStatusCode: false });
      expect(response.status(), route.path).toBeLessThan(400);
      expect(
        response.headers()["cache-control"] ?? "",
        `${route.path} must not be cached — a cached shell can bypass the auth redirect`
      ).toMatch(/no-store|no-cache/);
    }

    const html = await (await page.request.get("/")).text();
    const assets = [...html.matchAll(/(?:src|href)="(\/assets\/[^"]+)"/g)].map((match) => match[1]);
    expect(assets.length, "the served HTML references no built assets").toBeGreaterThan(0);
    for (const asset of assets) {
      const response = await page.request.get(asset, { failOnStatusCode: false });
      expect(response.status(), asset).toBeLessThan(400);
      expect(
        response.headers()["cache-control"] ?? "",
        `${asset} is content-hashed and should be immutable`
      ).toMatch(/immutable|max-age=\d{5,}/);
    }
  });

  test("nothing is fetched from a third-party CDN", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");

    const external: string[] = [];
    const origin = new URL(env.baseURL).origin;
    page.on("request", (request) => {
      const url = new URL(request.url());
      if (url.origin !== origin && url.protocol.startsWith("http")) external.push(url.origin);
    });

    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await expect(page.locator("#root")).not.toBeEmpty();

    // An air-gapped security console that phones out for a stylesheet is both
    // a deployment failure and a disclosure one.
    expect([...new Set(external)], "the console fetched from outside its own origin").toEqual([]);
  });

  test("the operator's identity and capabilities are reported, not guessed", async ({ page }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    await signIn(page, env);

    const whoami = await readWhoami(page);
    expect(whoami.user, "whoami reported no operator").not.toBe("");

    // policy_scope is what tells the console whether a detection push reaches a
    // fleet (dispatched, not converged) or one host (applied). Absent is a
    // valid answer and means "host" — what must not happen is the console
    // inferring it from the shape of some other field.
    if (whoami.policyScope) {
      expect(["fleet", "host"]).toContain(whoami.policyScope);
    }

    await page.goto("/", { waitUntil: "domcontentloaded" });
    // The identity on screen is the identity the server reported. A console
    // showing a different user than the session holds is an audit problem.
    await expect(page.locator('[data-panel="left-sidebar"]')).toContainText(whoami.user);
  });
});

/**
 * The correlation graph and the drill panel, on real telemetry.
 *
 * A live estate produces data the fixtures cannot: thousands of ephemeral
 * processes, alerts with no lineage, agents that stop reporting mid-render.
 * These check the surfaces hold up on it rather than on a curated two-row
 * fixture.
 */
test.describe("live investigation surfaces", () => {
  test.skip(!hasCredentials(env), "Set PROBE_URL, PROBE_USER and PROBE_PASSWORD");
  test.describe.configure({ mode: "serial" });

  test("the alert queue lists real alerts and each one drills", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    const alerts = page.locator(".soc-alert-main");
    const count = await alerts.count();
    if (count === 0) {
      test.info().annotations.push({
        type: "note",
        description: "no alerts in the default window on this deployment; the drill path was not exercised"
      });
      return;
    }

    await alerts.first().click();
    const drill = page.locator('[data-panel="drill-down-slide-over"]');
    await expect(drill).toHaveClass(/is-open/);
    await expect(drill.locator(".soc-drill-hero")).not.toBeEmpty();
    await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);
  });

  test("the correlation graph draws real, connected signal", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });

    await page.getByRole("button", { name: "Correlation Graph", exact: true }).first().click();
    const surface = page.locator('[data-panel="process-correlation-graph-modal"]');
    await expect(surface).toBeVisible();

    const nodes = surface.locator("svg.soc-correlation-graph circle");
    const nodeCount = await nodes.count();
    if (nodeCount === 0) {
      test.info().annotations.push({ type: "note", description: "no graph nodes in the default window" });
      return;
    }
    // Nodes without edges are scattered dots, not a correlation. The panel's
    // whole claim is that it joins signal.
    await expect(surface.locator("svg.soc-correlation-graph line").first()).toBeVisible();
  });

  test("sensor health reports what each agent can actually contain", async ({ page }) => {
    await signIn(page, env);
    await page.goto("/", { waitUntil: "domcontentloaded" });
    await page.getByRole("button", { name: "Sensor Health", exact: true }).first().click();

    const panel = page.locator('[data-panel="sensor-health-modal"]');
    await expect(panel).toBeVisible();

    const response = await page.request.get("/api/sensor-health", { failOnStatusCode: false });
    if (response.status() !== 200) {
      await expect(panel, "an unserved endpoint must be stated, not shown as zero agents").toContainText(
        /not served|not exposed|cannot tell/i
      );
      return;
    }

    const health = (await response.json()) as { agents?: Array<Record<string, unknown>> };
    const agents = health.agents ?? [];
    expect(agents.length, "a live deployment must report at least one agent").toBeGreaterThan(0);

    // "Cannot contain" is the question this panel exists to answer. An
    // unmeasured zero is the most reassuring lie available, so where posture
    // could not be read the tile must say so rather than print 0.
    const reported = agents.filter((agent) => agent.containment);
    if (reported.length === 0) {
      await expect(panel.locator(".soc-sensor-summary")).toContainText("—");
    }
    await expect(panel).toContainText(String(agents[0].agent_id ?? ""));
  });
});

/** Shared helper kept here so the deployment-specific files can reuse it. */
export async function routeRenders(page: Page, path: string): Promise<void> {
  await page.goto(path, { waitUntil: "domcontentloaded" });
  await expect(page.locator("#root"), `${path} rendered nothing`).not.toBeEmpty();
  await expect(page.getByRole("heading", { name: /stopped rendering/i }), `${path} crashed`).toHaveCount(0);
}
