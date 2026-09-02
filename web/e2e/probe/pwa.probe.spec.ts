import { expect, hasCredentials, hasTarget, readProbeEnv, signIn, test } from "./support/live";

/**
 * The installed-app surface, against a live deployment.
 *
 * WHAT BUG THIS PINS, and it is the reason this file exists: after one deploy
 * the console came up BLANK for anyone who had visited before. An old service
 * worker was serving a stale shell, because `sw.js` shipped with no
 * `Cache-Control` and browsers were holding it. `curl` cannot see this — the
 * bytes on the server were correct the whole time. Only a browser that
 * registers the worker can.
 *
 * WHY IT IS HERE AND NOT IN E2E: a service worker is a per-ORIGIN, persistent
 * install. Whether one is registered, what scope it claims, and what it
 * answers a navigation with are properties of the deployed origin plus the
 * headers its server sends — none of which a mocked run has.
 */

const env = readProbeEnv();

test.describe("progressive web app", () => {
  test.skip(!hasTarget(env), "Set PROBE_URL to certify a deployment");

  test("the service worker itself is never cached", async ({ page }) => {
    const response = await page.request.get("/sw.js", { failOnStatusCode: false });
    expect(response.status(), "/sw.js must be served — the console registers it").toBe(200);

    const cacheControl = response.headers()["cache-control"] ?? "";
    expect(
      cacheControl,
      "sw.js with no Cache-Control is how a browser keeps serving last month's console shell after a deploy"
    ).toMatch(/no-cache|no-store|max-age=0/);

    const contentType = response.headers()["content-type"] ?? "";
    expect(contentType, "sw.js must be served as JavaScript or the browser refuses to register it").toMatch(
      /javascript/
    );
  });

  test("the manifest is served and describes an installable console", async ({ page }) => {
    const response = await page.request.get("/manifest.webmanifest", { failOnStatusCode: false });
    expect(response.status()).toBe(200);

    const manifest = (await response.json()) as {
      name?: string;
      start_url?: string;
      display?: string;
      icons?: Array<{ src: string; sizes?: string; purpose?: string }>;
    };
    expect(manifest.name, "the manifest must name the app").toBeTruthy();
    expect(manifest.start_url, "the manifest must declare a start_url").toBeTruthy();
    expect(manifest.display).toBe("standalone");

    // Every icon it advertises must actually be there. A 404'd icon is why an
    // installed app lands on a home screen as a blank square.
    const icons = manifest.icons ?? [];
    expect(icons.length, "the manifest advertises no icons").toBeGreaterThan(0);
    for (const icon of icons) {
      const iconResponse = await page.request.get(icon.src, { failOnStatusCode: false });
      expect(iconResponse.status(), `${icon.src} is advertised by the manifest but not served`).toBe(200);
    }
    // A maskable icon is what stops Android cropping the logo into a circle.
    expect(
      icons.some((icon) => (icon.purpose ?? "").includes("maskable")),
      "no maskable icon: installed Android launchers will crop this"
    ).toBe(true);
  });

  /**
   * The worker is deliberately allowed to register here — every other probe
   * blocks it, because in a driven browser it turns re-navigation into
   * ERR_ABORTED. This one is ABOUT the worker, so it opts back in with its own
   * context.
   */
  test("the worker registers, takes control, and never answers a navigation from cache", async ({ browser }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    test.setTimeout(180_000);

    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      viewport: { width: 1600, height: 1000 },
      serviceWorkers: "allow"
    });
    const page = await context.newPage();

    try {
      await signIn(page, env);
      await page.goto("/", { waitUntil: "load" });

      const controlled = await page
        .waitForFunction(() => Boolean(navigator.serviceWorker?.controller), null, { timeout: 60_000 })
        .then(() => true)
        .catch(() => false);

      if (!controlled) {
        test.info().annotations.push({
          type: "note",
          description: "no service worker took control within 60s; the console still rendered without one"
        });
        await expect(page.locator("#root")).not.toBeEmpty();
        return;
      }

      const scope = await page.evaluate(async () => {
        const registration = await navigator.serviceWorker.getRegistration();
        return registration?.scope ?? "";
      });
      expect(scope, "the worker must claim the whole origin").toContain(new URL(env.baseURL).origin);

      // THE ASSERTION THIS FILE EXISTS FOR. With a worker in control, a fresh
      // navigation must still reach the network: the server-side auth check
      // runs on the navigation, so a shell answered from cache would let a
      // signed-out browser see the console frame.
      const fromNetwork: string[] = [];
      page.on("response", (response) => {
        const url = new URL(response.url());
        if (url.pathname === "/" && response.request().resourceType() === "document") {
          fromNetwork.push(response.headers()["cache-control"] ?? "");
        }
      });
      await page.reload({ waitUntil: "load" });

      await expect(page.locator("#root"), "the console rendered blank under a controlling worker").not.toBeEmpty();
      await expect(page.getByRole("heading", { name: /stopped rendering/i })).toHaveCount(0);
      expect(
        fromNetwork.length,
        "the navigation was answered without reaching the server — a cached shell bypasses the auth redirect"
      ).toBeGreaterThan(0);
      for (const cacheControl of fromNetwork) {
        expect(cacheControl, "the HTML shell must not be cacheable").toMatch(/no-store|no-cache/);
      }
    } finally {
      await context.close();
    }
  });

  test("the worker never caches an API response", async ({ browser }) => {
    test.skip(!hasCredentials(env), "Set PROBE_USER and PROBE_PASSWORD");
    test.setTimeout(180_000);

    const context = await browser.newContext({
      baseURL: env.baseURL,
      ignoreHTTPSErrors: true,
      serviceWorkers: "allow"
    });
    const page = await context.newPage();

    try {
      await signIn(page, env);
      await page.goto("/", { waitUntil: "load" });
      await page
        .waitForFunction(() => Boolean(navigator.serviceWorker?.controller), null, { timeout: 60_000 })
        .catch(() => undefined);

      // This is an authenticated, realtime security console. Telemetry sitting
      // in a browser's cache outlives the session that was allowed to read it.
      const cachedApiUrls = await page.evaluate(async () => {
        if (!("caches" in window)) return [];
        const names = await caches.keys();
        const found: string[] = [];
        for (const name of names) {
          const cache = await caches.open(name);
          for (const request of await cache.keys()) {
            if (new URL(request.url).pathname.startsWith("/api/")) found.push(request.url);
          }
        }
        return found;
      });

      expect(cachedApiUrls, "the service worker has cached API responses").toEqual([]);
    } finally {
      await context.close();
    }
  });
});
