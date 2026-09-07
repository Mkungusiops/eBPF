import { installMockApi } from "./support/mock-api";
import { expect, socNavLink, test } from "./support/test";

/**
 * What the console does when the platform under it misbehaves.
 *
 * WHY THIS FILE EXISTS: every other spec renders a healthy backend. A security
 * console is read hardest when things are NOT healthy, and its failure modes
 * have a specific shape here — a page that reports "nothing to see" when it
 * actually could not see is more dangerous than one that reports an error,
 * because an operator acts on the first and investigates the second.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: these are whole-page behaviours —
 * a client-side redirect on 401, an error boundary catching a render throw, a
 * banner driven by the passage of time since the last stream frame. jsdom can
 * be made to simulate each in isolation and none of them in composition.
 */

const CRASH_FREE = /stopped rendering/i;

test.describe("degraded backends", () => {
  /**
   * WHAT BUG THIS PINS: a 200 whose body omits a field the console
   * dereferences. `/api/assistant` answers `{enabled, agents, reason}` and the
   * console reads `capability.agents.find(...)` behind an optional chain that
   * only guards the OUTER object. Both servers happen to send `agents: []`
   * today (no `omitempty` on the field), so the crash is latent rather than
   * live — but the code path that produces it is the one whose own comment
   * promises the assistant "must never take the drill panel down with it".
   *
   * FIXED 2026-09-02 in src/features/assistant/useAssistant.ts: the capability
   * read is guarded, and a body the console cannot read now degrades the
   * assistant panel rather than the route — saying which of the three states it
   * is in (disabled by the deployment, enabled with no agents for this surface,
   * or unreadable) instead of collapsing all three into "not configured".
   */
  test("survives an assistant capability whose body omits `agents`", async ({ page }) => {
    await installMockApi(page, {
      routes: { "/api/assistant": { enabled: false, reason: "older server, no agents field" } }
    });
    await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
    await page.goto("/");
    await page.getByRole("button", { name: /Credential file read/i }).click();

    await expect(page.getByRole("heading", { name: CRASH_FREE })).toHaveCount(0);
    // NOT toBeVisible(): SlideOver's <aside> is always mounted and "closed" is
    // only a CSS transform, so toBeVisible() passes on an unopened panel.
    // Probed. The claim here is that the drill actually opened.
    await expect(page.locator('[data-panel="drill-down-slide-over"]')).toHaveClass(/is-open/);
  });

  test("renders every route when the optional device and fleet APIs are switched off", async ({ page }) => {
    const disabled = {
      status: 503,
      body: { error: "network device choke not enabled (start engine with -devchoke-iface)" }
    };
    await installMockApi(page, {
      routes: {
        "/api/choke/device-state": disabled,
        "/api/choke/devices": disabled,
        "/api/choke/device-flows": disabled,
        "/api/fleet/hosts": disabled,
        "/api/fleet/state": disabled,
        "/api/fleet/cgroups": disabled,
        "/api/fleet/decisions": disabled,
        "/api/fleet/alerts": disabled,
        "/api/fleet/devices": disabled
      }
    });

    for (const path of ["/", "/choke", "/devices", "/fleet"]) {
      await page.goto(path);
      await expect(page.locator("#root"), `${path} rendered nothing`).not.toBeEmpty();
      await expect(page.getByRole("heading", { name: CRASH_FREE }), `${path} crashed`).toHaveCount(0);
    }
  });

  test("a disabled device plane is stated, not shown as an empty inventory", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/choke/device-state": {
          status: 503,
          body: { error: "network device choke not enabled (start engine with -devchoke-iface)" }
        }
      }
    });
    await page.goto("/devices");

    // "Off" and "nothing found" are different claims. An operator who reads an
    // empty device table as "no devices on this segment" has been told
    // something false by a feature that is simply not running.
    await expect(page.locator("body")).toContainText(/not enabled|disabled|unavailable/i);
  });

  test("a 500 from a core read does not blank the console", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/alerts": { status: 500, body: { error: "store query failed" } },
        "/api/events": { status: 500, body: { error: "store query failed" } },
        "/api/decisions": { status: 500, body: { error: "store query failed" } }
      }
    });
    await page.goto("/");

    // The chrome an operator navigates by must survive a failing store — that
    // is how they reach Sensor Health to find out why.
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();
    await expect(page.locator('[data-panel="top-bar"]')).toBeVisible();
    await expect(page.getByRole("heading", { name: CRASH_FREE })).toHaveCount(0);
  });

  test("a non-JSON body where JSON was promised does not crash the route", async ({ page }) => {
    // An HTML error page from a reverse proxy is the classic version of this:
    // the request succeeds, the content-type lies, and JSON.parse throws deep
    // inside a render.
    await installMockApi(page, {
      routes: {
        "/api/choke/state": { status: 502, contentType: "text/html", body: "<html><body>502 Bad Gateway</body></html>" }
      }
    });
    await page.goto("/choke");

    await expect(page.locator("#root")).not.toBeEmpty();
    await expect(page.getByRole("heading", { name: CRASH_FREE })).toHaveCount(0);
  });
});

test.describe("session expiry", () => {
  /**
   * WHAT BUG THIS PINS: an expired session must take the operator to the login
   * page. Leaving them on a console whose panels quietly stop updating is the
   * worst outcome — the screen still looks like a live security console.
   */
  test("a 401 from any read redirects to the login page", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/whoami": { status: 401, body: { error: "unauthorized", redirect: "/login" } },
        "/api/alerts": { status: 401, body: { error: "unauthorized", redirect: "/login" } }
      }
    });

    await page.goto("/");

    // Polled rather than waitForURL: the console redirects with
    // `window.location.href`, and a navigation that starts while waitForURL is
    // still attaching reports ERR_ABORTED — a race in the test, not in the app.
    await expect
      .poll(() => page.url(), { timeout: 15_000, message: "an expired session never reached the login page" })
      .toMatch(/\/login/);
  });
});

test.describe("stream health", () => {
  /**
   * WHAT BUG THIS PINS: a stream that is CONNECTED and silent looks identical
   * to a quiet estate. The banner is the only thing that distinguishes "nothing
   * is happening" from "we stopped being told what is happening".
   */
  test("names a silent stream rather than presenting it as a quiet estate", async ({ page }) => {
    // The clock is driven, not waited on. A stream that CONNECTS and then goes
    // quiet is only stale after 30 seconds, and a test that actually slept for
    // them would be the slowest in the suite and still racy.
    await page.clock.install();
    await installMockApi(page, { stream: "silent" });
    await page.goto("/");

    const banner = page.locator('[data-panel="stale-data-banner"]');
    // Precondition: an open, freshly-connected stream is NOT stale. Without
    // this the assertion below would pass on a banner that is always visible.
    await expect(banner).not.toHaveClass(/is-visible/);

    await page.clock.fastForward("00:40");

    await expect(banner).toHaveClass(/is-visible/);
    await expect(banner).toContainText(/Stream silent/i);
    // And it says what IS still trustworthy, so the operator knows what they
    // can act on rather than distrusting the whole screen.
    await expect(banner).toContainText(/snapshots remain available/i);
  });

  test("a stream that never connects still leaves the dashboard usable", async ({ page }) => {
    await installMockApi(page, { stream: "error" });
    await page.goto("/");

    await expect(page.locator('[data-panel="kpi-row"]')).toBeVisible();
    await expect(page.locator('[data-panel="stale-data-banner"]')).toHaveClass(/is-visible/);
    await expect(page.getByRole("heading", { name: CRASH_FREE })).toHaveCount(0);
  });

  test("the live pill offers a reconnect rather than requiring a page reload", async ({ page }) => {
    await installMockApi(page, { stream: "error" });
    await page.goto("/");

    // The stream state pill is in the top bar; opening it must offer the
    // recovery action. An operator who has to reload the console loses every
    // local triage state the page holds (acks, pins, notes).
    await page.locator('[data-panel="top-bar"]').getByRole("button", { name: /live|stream|reconnect/i }).first().click();
    await expect(page.locator('[data-panel="pill-popovers"]').first()).toContainText(/reconnect/i);
  });
});

test.describe("error boundary", () => {
  /**
   * The boundary's copy is a safety statement, not decoration: an operator
   * whose console just died needs to know within one sentence whether the
   * ESTATE is also unprotected. It is not — agents apply policy on the host.
   */
  test("a render fault says enforcement is unaffected and offers a reload", async ({ page }) => {
    // Force a throw from a real render path by handing a body of the wrong
    // TYPE where the console expects a collection.
    await installMockApi(page, { routes: { "/api/alerts": 42 } });
    await page.goto("/");

    const crashed = page.getByRole("heading", { name: CRASH_FREE });
    if (await crashed.count()) {
      await expect(page.getByText(/Enforcement is unaffected/i)).toBeVisible();
      await expect(page.getByRole("button", { name: /Reload console/i })).toBeVisible();
    } else {
      // Not crashing is the better outcome, and is what the assertion in the
      // degraded-backends block above requires. This branch exists so the
      // boundary's copy is still covered wherever it does fire.
      await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();
    }
  });
});

test.describe("cross-route consistency", () => {
  test("every route reaches the others without a dead end", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    // The two choke gateways are the platform's headline capability; they are
    // reached from the SOC nav and must actually resolve.
    await socNavLink(page, "Choke Gateway").click();
    await page.waitForURL(/\/choke/);
    await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();

    await page.goto("/");
    await socNavLink(page, "Device Choke").click();
    await page.waitForURL(/\/devices/);
    await expect(page.locator("#root")).not.toBeEmpty();
  });
});
