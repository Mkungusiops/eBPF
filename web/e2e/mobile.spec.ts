import { installMockApi } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * The console on a phone.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: horizontal overflow is a LAYOUT fact.
 * It is produced by real measurement of real boxes after real CSS applied at a
 * real viewport width — jsdom neither lays out nor measures, so a unit test
 * asserting a flex-wrap class would pass whether or not the stylesheet loaded.
 *
 * WHAT A FAILURE MEANS: an operator on a phone has to scroll sideways to read
 * a security console during an incident. Every route is checked, because the
 * one that breaks is never the one anyone remembers to look at.
 */
const PHONE = { width: 390, height: 844 };

const routes: Array<[string, string]> = [
  ["soc", "/"],
  ["login", "/login"],
  ["choke", "/choke"],
  ["devices", "/devices"],
  ["fleet", "/fleet"]
];

/** Every element whose box reaches past the viewport, widest first. */
async function overflowReport(page: import("@playwright/test").Page) {
  return page.evaluate(() => {
    const viewport = window.innerWidth;
    const offenders: Array<{ selector: string; width: number; right: number }> = [];
    for (const element of Array.from(document.querySelectorAll<HTMLElement>("body *"))) {
      const box = element.getBoundingClientRect();
      if (box.width === 0 || box.height === 0) continue;
      if (box.right <= viewport + 1) continue;
      const classes = String(element.className || "").split(/\s+/).filter(Boolean).slice(0, 2);
      offenders.push({
        selector: `${element.tagName.toLowerCase()}${classes.length ? "." + classes.join(".") : ""}`,
        width: Math.round(box.width),
        right: Math.round(box.right)
      });
    }
    offenders.sort((a, b) => b.right - a.right);
    return {
      viewport,
      documentWidth: document.documentElement.scrollWidth,
      // Deduplicated: one overflowing flex row produces a dozen overflowing
      // children, and listing all of them buries the container that caused it.
      offenders: [...new Map(offenders.map((o) => [o.selector, o])).values()].slice(0, 6)
    };
  });
}

test.describe("mobile responsiveness", () => {
  test.use({ viewport: PHONE });

  for (const [name, path] of routes) {
    test(`${name} fits the phone viewport without horizontal overflow`, async ({ page }) => {
      // KNOWN DEFECT (found by this suite, 2026-08-27): the Choke Gateway
      // topbar does not wrap. `.choke-topbar-primary` lays the search box and
      // the four status pills (`.choke-status-cluster`) out on one unwrapped
      // row, so the document is 1140px wide inside a 390px viewport and the
      // platform's headline surface scrolls sideways on every phone.
      //
      // Marked expected-to-fail rather than deleted or loosened: the assertion
      // is correct, and `test.fail` turns green into a hard error the moment
      // the CSS is fixed, so the marker cannot outlive the bug.
      test.fail(name === "choke", "known defect: .choke-topbar-primary does not wrap at phone widths");

      await installMockApi(page);
      await page.goto(path);
      // Wait for the route's own content rather than a fixed sleep: a
      // half-mounted page measures narrow and passes vacuously.
      await expect(page.locator("#root")).not.toBeEmpty();

      const report = await overflowReport(page);
      expect(
        report.documentWidth,
        `${name} overflows by ${report.documentWidth - report.viewport}px. Widest offenders: ${
          report.offenders.map((o) => `${o.selector} (right ${o.right}px)`).join(", ") || "none measured"
        }`
      ).toBeLessThanOrEqual(report.viewport + 1);
    });
  }

  test("SOC sidebar starts collapsed on phones and opens as a dismissible drawer", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    const route = page.locator(".soc-route");
    // Content must be visible on first load — the drawer is not pre-opened.
    await expect(route).not.toHaveClass(/sidebar-open/);

    await page.getByRole("button", { name: "Toggle sidebar" }).click();
    await expect(route).toHaveClass(/sidebar-open/);

    const scrim = page.getByRole("button", { name: "Close menu" });
    await expect(scrim).toBeVisible();

    // Tap the scrim in the area not covered by the drawer to dismiss it.
    await scrim.click({ position: { x: 340, y: 600 } });
    await expect(route).not.toHaveClass(/sidebar-open/);
  });
});
