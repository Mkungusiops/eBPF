import { installMockApi } from "./support/mock-api";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

test.describe("SOC route", () => {
  test("renders the primary SOC panels and command surface", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    await page.goto("/");

    await expect(page.getByText("eBPF SOC")).toBeVisible();
    await expect(page.locator('[data-panel="left-sidebar"]')).toBeVisible();
    await expect(page.locator('[data-panel="top-bar"]')).toBeVisible();
    await expect(page.locator('[data-panel="kpi-row"]')).toBeVisible();
    await expect(page.locator('[data-panel="live-event-stream"]')).toBeVisible();
    await expect(page.getByRole("button", { name: /file_open cat \/etc\/shadow/i })).toBeVisible();

    await page.getByRole("button", { name: "Briefing" }).click();
    await expect(page.getByLabel("Briefing mode")).toContainText("What is happening");
    await expect(page.getByLabel("Briefing decision lenses")).toContainText("Business impact");
    const affectedCopy = page.locator(".soc-briefing-item").nth(2).locator("p");
    await affectedCopy.evaluate((node) => {
      node.textContent =
        "137 active processes observed; top signal is ZDJlMjUwYjEzODYxOjMyOTkzNzk4OTEyMDM1MjoxNTM0Mzg0.";
    });
    await expect
      .poll(() => affectedCopy.evaluate((node) => node.scrollWidth <= node.clientWidth))
      .toBe(true);

    await page.getByRole("button", { name: "Command palette" }).click();
    await expect(page.locator('[data-panel="command-palette"]')).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("opens the correlation graph as a full-screen surface, not a cramped modal", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    // The graph builds from range-filtered alerts/events; widen the window so the
    // fixed-timestamp fixtures fall inside it (on live, events stream in real time).
    await page.addInitScript(() => {
      window.localStorage.setItem("soc.prefDefaultRange", "525600");
    });
    await page.goto("/");

    await page.getByRole("button", { name: "Correlation Graph" }).click();

    const surface = page.locator('[data-panel="process-correlation-graph-modal"]');
    await expect(surface).toBeVisible();
    // The graph is a dedicated full-viewport page now, not a centered modal card.
    await expect(surface).toHaveClass(/is-fullscreen/);
    await expect(surface).toHaveClass(/is-open/);

    // The graph must correlate signal, not scatter disconnected exec_id dots:
    // readable process/policy/file labels joined by rendered edges.
    const svg = surface.locator("svg.soc-correlation-graph");
    await expect(svg.locator("line").first()).toBeVisible();
    await expect(svg.getByText("cat", { exact: true })).toBeVisible();
    await expect(svg.getByText("override-credential-read")).toBeVisible();
    await expect(svg.getByText("/etc/shadow")).toBeVisible();

    await surface.getByRole("button", { name: "Maximize graph" }).click();
    await expect(surface.locator(".soc-graph-shell")).toHaveClass(/is-maximized/);
    await expect(surface.locator(".soc-graph-selection")).toBeHidden();

    await surface.getByRole("button", { name: "Minimize graph" }).click();
    await expect(surface.locator(".soc-graph-shell")).not.toHaveClass(/is-maximized/);
    await expect(surface.locator(".soc-graph-selection")).toBeVisible();

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("account/profile modal exposes a discoverable sign-out control", async ({ page }) => {
    await installMockApi(page);
    await page.goto("/");

    await page.getByRole("button", { name: /operator/i }).click();
    const modal = page.locator('[data-panel="account-profile-modal"]');
    await expect(modal).toBeVisible();

    const signOut = modal.getByRole("link", { name: "Sign out" });
    await expect(signOut).toBeVisible();
    await expect(signOut).toHaveAttribute("href", "/api/logout");
  });

  test("opens an alert drill panel with investigation context", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);
    await page.addInitScript(() => {
      window.localStorage.setItem("soc.prefDefaultRange", "525600");
    });
    await page.goto("/");

    await page.getByRole("button", { name: /Credential file read/i }).click();

    const drill = page.locator('[data-panel="drill-down-slide-over"]');
    await expect(drill).toBeVisible();
    await expect(drill.locator(".soc-drill-hero")).toContainText("Credential file read");
    await expect(drill.locator(".soc-drill-grid")).toContainText("Chain depth");
    await expect(drill.locator(".soc-drill-narrative")).toContainText("2-process chain");
    await expect(drill).toContainText("Choke response");
    await expect(drill).toContainText("Process lineage");
    // Event timeline is the shared replay widget; it lists the kernel events.
    await expect(drill.locator(".event-replay")).toContainText("file_open");
    await expect(drill.getByRole("button", { name: /Replay event timeline/i })).toBeVisible();

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
