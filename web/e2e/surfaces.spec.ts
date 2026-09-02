import type { ConsoleMessage, Page } from "@playwright/test";

import {
  SOC_LAB_SURFACES,
  SOC_SURFACES_ALWAYS_AVAILABLE,
  isServedApiPath,
  type SocSurface
} from "./support/contracts";
import { installMockApi, RequestLog } from "./support/mock-api";
import { expect, socNavItem, test } from "./support/test";

/**
 * Every tool the SOC console advertises, opened.
 *
 * WHAT BUG THIS PINS: the console's fifteen tool surfaces are mounted
 * unconditionally and hidden with CSS (see SocModals.tsx), so a body that
 * throws on render does not fail at import time and does not fail on the
 * dashboard — it fails the first time an analyst clicks the nav item, and it
 * takes the whole route down with it through the error boundary. Exactly that
 * happened to the drill panel: `useAssistant` dereferenced a field the server
 * need not send, and the SOC console rendered "This view stopped rendering".
 *
 * WHY IT IS HERE AND NOT IN UNIT TESTS: the failure mode is a real React
 * render inside a real error boundary, reached by a real click on the real
 * nav. A unit test that renders one body in isolation cannot see a surface
 * that is unreachable, mis-wired to the wrong shell, or opened onto an empty
 * shell because its body silently bailed.
 *
 * SHAPE: Pattern A — one lane per worker over a shared queue, failures
 * collected and asserted once, so a run reports all fifteen broken surfaces
 * rather than the first.
 */

const LANES = 3;

/** Console noise that is not a defect. */
const IGNORED_CONSOLE = /Download the React DevTools|\[vite\]/i;

type SurfaceFailure = { nav: string; reason: string };

async function openAndInspect(page: Page, surface: SocSurface): Promise<SurfaceFailure | null> {
  const errors: string[] = [];
  const onPageError = (error: Error) => errors.push(`pageerror: ${error.message}`);
  const onConsole = (message: ConsoleMessage) => {
    if (message.type() === "error" && !IGNORED_CONSOLE.test(message.text())) {
      errors.push(`console: ${message.text()}`);
    }
  };
  page.on("pageerror", onPageError);
  page.on("console", onConsole);

  try {
    const nav = socNavItem(page, surface.nav);
    if ((await nav.count()) === 0) {
      return { nav: surface.nav, reason: "no sidebar control with this accessible name" };
    }
    await nav.click();

    const shell = page.locator(`[data-panel="${surface.panel}"]`);
    // Either the surface opened, or the route fell to its error boundary.
    // Waiting only for the shell would hang for the full timeout on a throw
    // and report "not visible" rather than the crash that caused it.
    await Promise.race([
      shell.waitFor({ state: "visible", timeout: 15_000 }),
      page.getByRole("heading", { name: /stopped rendering/i }).waitFor({ timeout: 15_000 })
    ]).catch(() => undefined);

    if (await page.getByRole("heading", { name: /stopped rendering/i }).count()) {
      return {
        nav: surface.nav,
        reason: `route crashed into the error boundary: ${errors[0] ?? "no error captured"}`
      };
    }
    if (!(await shell.isVisible().catch(() => false))) {
      return { nav: surface.nav, reason: `[data-panel="${surface.panel}"] never became visible` };
    }

    // The shell being visible is not the claim. ModalShell renders an empty
    // body just as happily as a populated one, so require content the surface
    // itself is responsible for.
    const text = (await shell.innerText().catch(() => "")).replace(/\s+/g, " ");
    if (!surface.contains.test(text)) {
      return {
        nav: surface.nav,
        reason: `opened but its body matched nothing of ${surface.contains}; text was "${text.slice(0, 160)}"`
      };
    }
    if (errors.length) {
      return { nav: surface.nav, reason: `opened, but logged: ${errors[0].slice(0, 200)}` };
    }

    await page.keyboard.press("Escape");
    await shell.waitFor({ state: "hidden", timeout: 5_000 }).catch(() => undefined);
    if (await shell.isVisible().catch(() => false)) {
      return { nav: surface.nav, reason: "Escape did not close it (an operator has no way out)" };
    }
    return null;
  } catch (error) {
    return { nav: surface.nav, reason: String((error as Error).message).split("\n")[0] };
  } finally {
    page.off("pageerror", onPageError);
    page.off("console", onConsole);
  }
}

test.describe("SOC surfaces", () => {
  test("every advertised tool opens, renders a body, and closes", async ({ browser }) => {
    test.setTimeout(5 * 60_000);

    const queue = [...SOC_SURFACES_ALWAYS_AVAILABLE];
    expect(queue.length, "the surface contract must not be empty").toBeGreaterThan(8);

    const failures: SurfaceFailure[] = [];
    await Promise.all(
      Array.from({ length: LANES }, async () => {
        // One context per LANE, reused across its items: creating a context
        // costs more than opening a modal does.
        const context = await browser.newContext({ viewport: { width: 1600, height: 1000 } });
        const page = await context.newPage();
        try {
          await installMockApi(page);
          await page.goto("/");
          await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

          for (let surface = queue.pop(); surface; surface = queue.pop()) {
            const failure = await openAndInspect(page, surface);
            if (failure) failures.push(failure);
          }
        } finally {
          await context.close();
        }
      })
    );

    expect(
      failures.map((failure) => `${failure.nav}: ${failure.reason}`),
      `${failures.length} of ${SOC_SURFACES_ALWAYS_AVAILABLE.length} SOC surfaces failed`
    ).toEqual([]);
  });

  /**
   * The lab surfaces write FABRICATED findings into whatever evidence store the
   * deployment is pointed at. On a customer deployment that is the tenant's
   * real one, which is why they are gated on the server's lab_mode flag and
   * why their absence has to be tested as carefully as their presence.
   */
  test("lab-only surfaces are hidden unless the server reports lab mode", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    for (const surface of SOC_LAB_SURFACES) {
      await expect(
        socNavItem(page, surface.nav),
        `${surface.nav} must not be offered on a deployment that did not report lab_mode`
      ).toHaveCount(0);
    }
  });

  test("lab surfaces appear, and open, when the server reports lab mode", async ({ page }) => {
    await installMockApi(page, {
      routes: {
        "/api/version": { sha: "fixture-sha", started_at: "2026-06-25T09:00:00Z", lab_mode: true }
      }
    });
    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    const failures: SurfaceFailure[] = [];
    for (const surface of SOC_LAB_SURFACES) {
      const failure = await openAndInspect(page, surface);
      if (failure) failures.push(failure);
    }
    expect(failures.map((failure) => `${failure.nav}: ${failure.reason}`)).toEqual([]);
  });

  /**
   * WHAT BUG THIS PINS: a panel that calls an endpoint no server implements
   * does not look broken — it looks quiet. This console has shipped that class
   * three times (most recently a tool advertising eleven filter parameters no
   * server read), so the requests the page actually makes are checked against
   * the routes the two servers actually register.
   */
  test("the console only asks for endpoints its servers serve", async ({ page }) => {
    const recorder = new RequestLog();
    await installMockApi(page, { recorder });

    await page.goto("/");
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();

    // Drive the surfaces so the lazily-fetching bodies (Settings, Sensor
    // Health, Behaviour & Intel) actually issue their reads. Without this the
    // assertion only covers the dashboard's own polling and passes vacuously.
    for (const surface of SOC_SURFACES_ALWAYS_AVAILABLE) {
      const nav = socNavItem(page, surface.nav);
      if (await nav.count()) {
        await nav.click();
        await page.locator(`[data-panel="${surface.panel}"]`).waitFor({ state: "visible", timeout: 10_000 }).catch(() => undefined);
        await page.keyboard.press("Escape");
      }
    }

    const requested = recorder.paths();
    expect(requested.length, "no API calls were recorded, so nothing is under test").toBeGreaterThan(5);

    const unknown = requested.filter((path) => !isServedApiPath(path));
    expect(
      unknown,
      "these paths are requested by the console but registered by neither server"
    ).toEqual([]);
  });
});
