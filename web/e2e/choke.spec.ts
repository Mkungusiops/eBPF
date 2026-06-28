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
    // The active-filter bar only appears once a filter is applied — no empty "Filters none" band.
    await expect(page.locator('[data-panel="active-filter-strip"]')).toHaveCount(0);
    await page.locator("[data-choke-global-search]").fill("bash");
    await expect(page.locator('[data-panel="active-filter-strip"]')).toBeVisible();
    await page.getByRole("button", { name: "Clear all" }).click();
    await expect(page.locator('[data-panel="active-filter-strip"]')).toHaveCount(0);
    await expect(page.locator('[data-panel="threat-intelligence-ribbon"]')).toBeVisible();
    await expect(page.locator('[data-panel="engine-stack-panel"]')).toBeVisible();
    await expect(page.locator('[data-panel="thresholds-panel"]')).toBeVisible();
    await expect(page.locator('[data-panel="policy-workbench"]')).toBeVisible();
    await expect(page.locator('[data-panel="operations-status-bar"]')).toBeVisible();
    await expect(page.getByRole("checkbox", { name: "Select exec-fixture-1" })).toBeVisible();

    const processTable = page.locator('[data-panel="tracked-processes-list"] .choke-process-table');
    const stateHeader = processTable.locator('.choke-process-head [data-choke-col="state"]');
    const stateCell = processTable.locator(".choke-process-row .choke-state-badge").first();
    const pidHeader = processTable.locator('.choke-process-head [data-choke-col="pid"]');
    const pidCell = processTable.locator('.choke-process-row [data-choke-col="pid"]').first();
    await expect(processTable.locator('.choke-process-head [data-choke-col="select"]')).toHaveText("select");
    await expect(stateHeader).toHaveText("status");
    await expect(pidHeader).toHaveText("process id");
    await expect(processTable.locator(".choke-process-bulkbar")).toContainText("Select all visible");
    await expect(processTable.locator(".choke-process-bulkbar")).toContainText("Clear selection");
    await expect(processTable.locator(".choke-process-virtual > .choke-process-head")).toBeVisible();
    await expect
      .poll(() => stateHeader.evaluate((node) => getComputedStyle(node.closest(".choke-process-head")!).position))
      .toBe("static");
    await expect(stateHeader).toBeVisible();
    await expect(pidHeader).toBeVisible();
    await expect(stateCell).toContainText("quarantined");
    await expect(pidCell).toHaveText("4242");

    const stateHeaderBox = await stateHeader.boundingBox();
    const stateCellBox = await stateCell.boundingBox();
    const pidHeaderBox = await pidHeader.boundingBox();
    const pidCellBox = await pidCell.boundingBox();
    expect(stateHeaderBox).not.toBeNull();
    expect(stateCellBox).not.toBeNull();
    expect(pidHeaderBox).not.toBeNull();
    expect(pidCellBox).not.toBeNull();
    expect(Math.abs(stateHeaderBox!.x - stateCellBox!.x)).toBeLessThan(3);
    expect(Math.abs(pidHeaderBox!.x - pidCellBox!.x)).toBeLessThan(3);

    // Command palette is reached through the profile menu (secondary controls are tucked there).
    await page.getByRole("button", { name: "Profile and tools" }).click();
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
