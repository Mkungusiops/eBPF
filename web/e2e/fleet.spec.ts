import type { Page } from "@playwright/test";

import { FLEET_SURFACE_HASH, PAGE_ROUTES } from "./support/contracts";
import { installMockApi } from "./support/mock-api";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

/**
 * The fleet view renders — as a SURFACE of the SOC console, which is where it
 * lives now.
 *
 * It was its own page at /fleet with its own topbar, its own four-console nav
 * and its own sign-out, so an operator drilling estate → customer → hosts left
 * one console for another to do it. The panels are the same panels; what
 * changed is how they are reached, and that the second chrome is gone.
 *
 * /fleet was NOT deleted. It is a redirect into the console with the surface
 * open, because the address is bookmarked, the live probe suite signs in at it
 * and the command palette offers it as a route — all three are covered below.
 */

/** The surface's shell. Every assertion is scoped to it: the console behind is real. */
const FLEET_PANEL = '[data-panel="fleet-console-modal"]';

function fleet(page: Page) {
  return page.locator(FLEET_PANEL);
}

/**
 * Open the surface by its address.
 *
 * The fragment is the surface's canonical name (features/fleet/address.ts), so
 * this is the same door the /fleet redirect and a bookmark come through — and
 * it needs no rail interaction, which keeps the tests below about the fleet
 * panels rather than about the sidebar.
 */
async function openFleetSurface(page: Page) {
  await page.goto(`/${FLEET_SURFACE_HASH}`);
  await expect(
    fleet(page),
    "the fleet surface never opened, so nothing below is under test"
  ).toHaveClass(/is-open/);
}

test.describe("Fleet surface", () => {
  test("renders fleet controls, tables, and live feed panels", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    await openFleetSurface(page);

    const panel = fleet(page);
    await expect(panel.getByText("Fleet size")).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Apply Changes To" })).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Posture Preset" })).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Thresholds" })).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Emergency Controls" })).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Live Decisions" })).toBeVisible();
    await expect(panel.getByRole("heading", { name: "Alerts" })).toBeVisible();
    await expect(panel.getByRole("row", { name: /alpha-edge.*live.*enforcing/i })).toBeVisible();
    await expect(panel.getByRole("row", { name: /bravo-edge.*live.*detect-only/i })).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  /**
   * THE SECOND CHROME IS THE THING THE MOVE REMOVED.
   *
   * The old page carried a brand line reading "Choke Fleet Console" over a
   * tenant caption of its own, a nav across to the other three consoles, and a
   * sign-out — every one of them a few pixels under the SOC shell's own. The
   * tenant caption was the dangerous one: it was built from an unscoped whoami,
   * so it named the account's default customer while the rows beneath it were
   * the SELECTED customer's.
   */
  test("carries no chrome of its own — one console, one topbar, one caption", async ({ page }) => {
    await installMockApi(page);
    await openFleetSurface(page);

    const panel = fleet(page);
    await expect(panel.getByText("Choke Fleet Console")).toHaveCount(0);
    await expect(panel.getByRole("navigation", { name: "Console navigation" })).toHaveCount(0);
    await expect(panel.getByRole("link", { name: "Sign out" })).toHaveCount(0);
    // The SOC shell's own rail still offers both, once each.
    await expect(page.getByRole("link", { name: "Sign out", exact: true })).toHaveCount(1);

    // What it DOES keep: the fan-out's health, which nothing in the SOC chrome
    // reports — the shell's live pill watches the SSE stream and this surface
    // has no stream, only the five-second poll.
    await expect(panel.getByText("connected")).toBeVisible();
    await expect(panel.getByText(/auto-refresh \d+s/)).toBeVisible();

    // AND THE SCOPE CAPTION. This surface is full-screen and opaque, so it
    // covers the dashboard's own scope banner — without a caption of its own
    // there would be nothing on screen saying whose hosts these are, on the
    // page that fires the estate-wide kill-switch. On this fixture the server
    // names no customer and claims no cross-tenant account, which is the
    // single-tenant product, so the honest caption is the product line.
    await expect(
      panel.locator(".fleet-scope-caption"),
      "the fleet surface names no scope at all"
    ).toBeVisible();
    await expect(panel.locator(".fleet-scope-caption")).toContainText("eBPF Threat Gateway");
  });

  /**
   * THE CAPTION HAS TO NAME THE CUSTOMER, not merely exist.
   *
   * A provider account reaches customers by name and belongs to none, so a
   * full-screen surface showing one customer's hosts with an armed estate-wide
   * kill-switch must say WHICH customer. This is the browser-level version of
   * the defect the surface was shipped with: the caption lived on the topbar
   * that the consolidation deleted, and for a while nothing replaced it.
   */
  test("names the customer whose hosts it is showing, to a provider account", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/whoami": {
          user: "msoc@provider",
          username: "msoc@provider",
          host: "all tenants",
          hostname: "all tenants",
          cross_tenant: true,
          viewing_tenant: "fixture-tenant",
          can_respond: true
        }
      }
    });
    await openFleetSurface(page);

    const caption = fleet(page).locator(".fleet-scope-caption");
    await expect(caption, "the provider is shown one customer's hosts with no customer named").toBeVisible();
    await expect(
      caption,
      "the caption does not name the customer these hosts and writes belong to"
    ).toContainText("fixture-tenant");
    // The product line is the SINGLE-TENANT caption. Showing it to a provider
    // would say "one customer" without saying which, which is the defect.
    await expect(caption).not.toContainText("eBPF Threat Gateway");
  });

  /**
   * /fleet IS A REDIRECT, NOT A 404 AND NOT A PAGE.
   *
   * Three things still use the address: operator bookmarks, the live probe
   * suite (e2e/probe/console.probe.spec.ts signs in AT /fleet), and the command
   * palette's "Open Fleet Console" route entry. All three have to land on the
   * surface, so the entry is kept and does exactly one thing.
   */
  test("/fleet redirects into the console with the surface open", async ({ page }) => {
    await installMockApi(page);

    const response = await page.goto("/fleet");
    expect(response?.status(), "the /fleet address stopped being served").toBeLessThan(400);

    await expect(page, "a /fleet bookmark did not reach the console").toHaveURL(
      new RegExp(`${FLEET_SURFACE_HASH}$`)
    );
    await expect(
      fleet(page),
      "the redirect landed on the console with nothing open, so the bookmark shows a dashboard"
    ).toHaveClass(/is-open/);
    await expect(fleet(page).getByText("Fleet size")).toBeVisible();

    // The contract says the same thing, so a spec and a probe reading it agree
    // about what this address now is.
    const route = PAGE_ROUTES.find((entry) => entry.path === "/fleet");
    expect(route?.redirectsTo, "the route contract still describes /fleet as a page").toBe(
      `/${FLEET_SURFACE_HASH}`
    );
  });

  /**
   * The rail is the door an operator actually uses, and it must not pay for the
   * redirect: the surface is already in this document.
   */
  test("the rail opens it in place, without leaving the console", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    await page.getByRole("link", { name: "Fleet Console", exact: true }).click();

    await expect(fleet(page), "the rail entry did not open the fleet surface").toHaveClass(/is-open/);
    await expect(
      page,
      "the rail reloaded the whole console to reach a surface it already hosts"
    ).not.toHaveURL(/\/fleet$/);
    await expect(fleet(page).getByText("Fleet size")).toBeVisible();
  });
});
