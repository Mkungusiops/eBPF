import { installMockApi } from "./support/mock-api";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

test.describe("Choke route", () => {
  test("renders the Choke workbench panels and mocked process state", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    await page.goto("/choke");

    await expect(page.getByText("Choke Gateway")).toBeVisible();
    await expect(page.locator('[data-panel="topbar-row-1"]')).toBeVisible();
    await expect(page.locator('[data-panel="topbar-row-2"]')).toBeVisible();
    await expect(page.locator('[data-panel="active-filter-strip"]')).toBeVisible();
    await expect(page.locator('[data-panel="threat-intelligence-ribbon"]')).toBeVisible();
    await expect(page.locator('[data-panel="engine-stack-panel"]')).toBeVisible();
    await expect(page.locator('[data-panel="thresholds-panel"]')).toBeVisible();
    await expect(page.locator('[data-panel="policy-workbench"]')).toBeVisible();
    await expect(page.locator('[data-panel="operations-status-bar"]')).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Select exec-fixture-1" })).toBeVisible();

    await page.getByRole("button", { name: "Command palette" }).click();
    await expect(page.locator('[data-panel="command-palette"]')).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("opens a process drill panel with response context", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);
    await page.setViewportSize({ width: 1440, height: 1000 });

    await page.goto("/choke");
    const processLink = page.locator('[data-panel="tracked-processes-list"] button[title="exec-fixture-1"]');
    await expect(processLink).toBeVisible();
    await processLink.click();

    const drill = page.locator('[data-panel="process-drill-in-slide-over"]');
    await expect(drill).toBeVisible();
    await expect(drill.locator(".choke-drill-hero")).toContainText("cat");
    await expect(drill.locator(".choke-drill-stats")).toContainText("Chain depth");
    await expect(drill.locator(".choke-drill-narrative")).toContainText("2-process chain");
    await expect(drill).toContainText("Response");
    await expect(drill).toContainText("Process lineage");
    await expect(drill).toContainText("Event timeline");

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("keeps the policy preview readable and clears the alerts badge", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);
    await page.setViewportSize({ width: 1440, height: 900 });

    await page.goto("/choke");

    await page.getByRole("button", { name: "Preview matches" }).click();
    await expect(page.locator(".choke-preview-head")).toContainText("fixture-live");
    await expect(page.locator(".choke-preview-effects")).toContainText("any non-pristine");

    const stateValue = page.locator(".choke-preview-effects strong").filter({ hasText: "any non-pristine" });
    const stateBox = await stateValue.boundingBox();
    expect(stateBox?.width ?? 0).toBeGreaterThan(90);
    expect(stateBox?.height ?? 999).toBeLessThan(40);

    await expect(page.locator(".choke-notif-dot")).toHaveText("1");
    await page.getByRole("button", { name: "Notifications" }).click();
    await page.locator('[data-panel="notifications-panel"]').getByRole("button", { name: "Clear all" }).click();
    await expect(page.locator(".choke-notif-dot")).toHaveCount(0);

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
