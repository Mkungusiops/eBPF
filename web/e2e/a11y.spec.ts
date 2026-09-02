import type { Page } from "@playwright/test";

import { PAGE_ROUTES } from "./support/contracts";
import { installMockApi } from "./support/mock-api";
import { expect, test } from "./support/test";

/**
 * Keyboard and assistive-technology access to the console.
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: an accessible name is COMPUTED by the
 * browser from a chain of fallbacks — aria-label, aria-labelledby, then the
 * element's own rendered text, minus anything aria-hidden. jsdom implements
 * none of that chain, so a component test asserting `aria-label` passes for a
 * control that a screen reader still announces as "button". Focus order,
 * focus-visible styling and whether Escape actually returns focus are likewise
 * only observable in a real browser.
 *
 * WHAT THESE PIN, specifically for THIS product: an incident is exactly when
 * an operator is typing rather than pointing. A console whose containment
 * controls are unreachable by keyboard is unusable at the moment it matters.
 */

/**
 * Every visibly-rendered interactive control that a screen reader would
 * announce with no name at all.
 *
 * Deliberately computed in the page from the same fallbacks the platform uses,
 * rather than by asserting an attribute: a button whose only content is an
 * aria-hidden icon has an aria-label in the source and NO name in practice,
 * which is the bug this looks for.
 */
async function unnamedControls(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const nameOf = (element: Element): string => {
      const labelled = element.getAttribute("aria-labelledby");
      if (labelled) {
        const text = labelled
          .split(/\s+/)
          .map((id) => document.getElementById(id)?.textContent ?? "")
          .join(" ")
          .trim();
        if (text) return text;
      }
      const label = element.getAttribute("aria-label")?.trim();
      if (label) return label;
      if (element instanceof HTMLInputElement && element.labels?.length) {
        const text = Array.from(element.labels).map((l) => l.textContent ?? "").join(" ").trim();
        if (text) return text;
      }
      // Rendered text, minus anything hidden from the accessibility tree.
      const clone = element.cloneNode(true) as HTMLElement;
      clone.querySelectorAll("[aria-hidden='true']").forEach((node) => node.remove());
      const text = (clone.textContent ?? "").replace(/\s+/g, " ").trim();
      if (text) return text;
      const title = element.getAttribute("title")?.trim();
      return title ?? "";
    };

    const offenders: string[] = [];
    const selector = "button, a[href], input:not([type='hidden']), select, textarea, [role='button'], [role='tab']";
    for (const element of Array.from(document.querySelectorAll(selector))) {
      const box = element.getBoundingClientRect();
      // Hidden overlays are mounted-but-invisible by design (SocModals.tsx
      // keeps every body in the DOM), so only judge what is actually painted.
      if (box.width === 0 || box.height === 0) continue;
      if (element.getAttribute("aria-hidden") === "true") continue;
      if (element.hasAttribute("disabled")) continue;
      if (nameOf(element)) continue;
      const classes = String((element as HTMLElement).className || "").split(/\s+/).filter(Boolean).slice(0, 2);
      offenders.push(`${element.tagName.toLowerCase()}${classes.length ? "." + classes.join(".") : ""}`);
    }
    return [...new Set(offenders)];
  });
}

/**
 * Controls that are unnamed TODAY, recorded so the check can run against the
 * rest of the console instead of being deleted.
 *
 * Every entry is a text input whose only description is a `placeholder`, which
 * is not an accessible name: a screen reader announces "edit text, blank" and
 * the placeholder vanishes the moment anything is typed. Each needs an
 * `aria-label` (or a visible <label>) — a one-line change per control.
 *
 * This list may only ever SHRINK. A new unnamed control fails the test, which
 * is the whole point of writing the gap down rather than lowering the bar.
 */
const KNOWN_UNNAMED_CONTROLS: Record<string, string[]> = {
  login: [],
  soc: ["input.soc-stream-filter"],
  choke: ["input.choke-search", "input.choke-tape-search", "input"],
  devices: ["input.devices-input.devices-reason-input", "input.devices-input.devices-revert-input"],
  fleet: []
};

test.describe("accessible names", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  for (const route of PAGE_ROUTES) {
    test(`${route.name} announces every visible control`, async ({ page }) => {
      await installMockApi(page);
      await page.goto(route.path);
      await expect(page.locator("#root")).not.toBeEmpty();

      const known = KNOWN_UNNAMED_CONTROLS[route.name] ?? [];
      const offenders = await unnamedControls(page);
      const unexpected = offenders.filter((offender) => !known.includes(offender));

      expect(
        unexpected,
        `${route.name} has NEW controls a screen reader would announce as blank: ${unexpected.join(", ")}`
      ).toEqual([]);

      // The allowlist must not outlive the gap it records. A name that has
      // been fixed has to be struck from the list, or the list slowly becomes
      // a place where regressions hide.
      const stale = known.filter((entry) => !offenders.includes(entry));
      expect(
        stale,
        `${route.name}: these are named now and must be removed from KNOWN_UNNAMED_CONTROLS: ${stale.join(", ")}`
      ).toEqual([]);
    });
  }
});

test.describe("keyboard operation", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  test("the command palette opens on Ctrl+K and closes on Escape", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    const palette = page.locator('[data-panel="command-palette"]');
    await expect(palette).toBeHidden();

    await page.keyboard.press("Control+k");
    await expect(palette).toBeVisible();

    await page.keyboard.press("Escape");
    await expect(palette).toBeHidden();
  });

  /**
   * KNOWN DEFECT (found by this suite, 2026-08-27): Ctrl+K opens the palette
   * but leaves focus on <body>, so the next keystroke goes nowhere and the
   * operator has to reach for the mouse — which defeats the only reason a
   * command palette exists.
   *
   * CAUSE: every modal body is mounted at route load and hidden with CSS (see
   * SocModals.tsx), so cmdk's `autoFocus` fires once, on a hidden input, long
   * before the palette is opened. Opening it changes no React state that would
   * re-run focus.
   *
   * Expected-to-fail rather than deleted: the assertion is right, and this
   * turns green into a hard error the moment focus is moved on open.
   */
  test("the command palette takes focus when it opens", async ({ page }) => {
    test.fail(true, "known defect: Ctrl+K opens the palette but focus stays on <body>");

    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    await page.keyboard.press("Control+k");
    await expect(page.locator('[data-panel="command-palette"] input')).toBeFocused();
  });

  test("the palette filters and selects a surface", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    await page.keyboard.press("Control+k");
    const palette = page.locator('[data-panel="command-palette"]');
    // Clicked, not tabbed to: focus does not land here on open (see the
    // expected-to-fail test above). When that is fixed this line becomes
    // redundant rather than wrong.
    const input = palette.locator("input");
    await input.click();
    await input.fill("help");
    await page.keyboard.press("Enter");

    await expect(page.locator('[data-panel="help-modal"]')).toBeVisible();
  });

  test("`/` focuses the search box without typing into it", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="top-bar"]')).toBeVisible();

    await page.keyboard.press("/");
    const search = page.locator('[data-panel="top-bar"] input').first();
    await expect(search).toBeFocused();
    // The keystroke that opened the box must not also land in it.
    await expect(search).toHaveValue("");
  });

  test("Escape closes the alert drill and does not swallow the next one", async ({ page }) => {
    await installMockApi(page);
    await page.addInitScript(() => window.localStorage.setItem("soc.prefDefaultRange", "525600"));
    await page.goto("/");

    const drill = page.locator('[data-panel="drill-down-slide-over"]');
    await page.getByRole("button", { name: /Credential file read/i }).click();
    // NOT toBeVisible(): SlideOver renders its <aside> unconditionally and
    // soc.css hides the closed panel with `transform: translateX(102%)`, which
    // does not affect Playwright's visibility computation. Probed: asserting
    // toBeVisible() on this panel WITHOUT clicking the alert passes. "Open" has
    // to be read off the class.
    await expect(drill).toHaveClass(/is-open/);

    await page.keyboard.press("Escape");
    // The slide-over stays mounted and is hidden by losing `is-open` — it keeps
    // local state across opens on purpose — so "closed" is a class, not an
    // absence.
    await expect(drill).not.toHaveClass(/is-open/);

    // Re-openable. A close handler that leaves stale state behind makes the
    // second open a dead click, which is the kind of thing only a browser
    // driving the real sequence catches.
    await page.getByRole("button", { name: /Credential file read/i }).click();
    await expect(drill).toHaveClass(/is-open/);
  });

  test("the containment ladder is reachable and operable from the keyboard", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/choke");
    await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();

    // Every rung is a real button, focusable and named. A ladder painted with
    // divs is a containment control an operator cannot reach under pressure.
    const rungs = page.locator('[data-panel="containment-ladder"] button');
    const count = await rungs.count();
    expect(count, "the containment ladder rendered no operable rungs").toBeGreaterThan(2);

    await rungs.first().focus();
    await expect(rungs.first()).toBeFocused();
  });
});

test.describe("theme", () => {
  test.use({ viewport: { width: 1600, height: 1000 } });

  for (const scheme of ["light", "dark"] as const) {
    test(`every route paints in ${scheme} mode`, async ({ page }) => {
      await page.emulateMedia({ colorScheme: scheme });
      await installMockApi(page);

      for (const route of PAGE_ROUTES) {
        await page.goto(route.path);
        await expect(page.locator("html"), `${route.name} did not follow the OS scheme`).toHaveClass(
          new RegExp(`theme-${scheme}`)
        );
        // A themed class with no painted background is the failure that makes
        // a console borrow whatever the browser puts behind it. The app paints
        // with a radial GRADIENT rather than a flat colour, so either counts —
        // what must not happen is neither.
        const painted = await page.evaluate(() => {
          const style = getComputedStyle(document.body);
          const colour = style.backgroundColor;
          const image = style.backgroundImage;
          return {
            colour,
            image,
            painted: (colour !== "rgba(0, 0, 0, 0)" && colour !== "transparent") || image !== "none"
          };
        });
        expect(
          painted.painted,
          `${route.name} body paints nothing in ${scheme} (colour ${painted.colour}, image ${painted.image})`
        ).toBe(true);
      }
    });
  }
});
