import { installMockApi } from "./support/mock-api";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

test.describe("Devices route", () => {
  test("renders device panels, bulk controls, and flow expander", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    await page.goto("/devices");

    await expect(page.getByRole("heading", { name: "Network Choke - Devices" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Enforcement mode" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Bulk actions" })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Device", exact: true })).toBeVisible();
    await expect(page.getByRole("columnheader", { name: "Hostname" })).toBeVisible();
    await expect(page.getByRole("row", { name: /02:00:00:00:00:10.*fixture-laptop.*quarantined/i })).toBeVisible();
    await expect(page.getByRole("row", { name: /02:00:00:00:00:01.*protected-gateway.*pristine/i })).toBeVisible();

    await page.getByTitle("Expand device flows").first().click();
    await expect(page.getByText("Connecting to (device -> destination)")).toBeVisible();
    await expect(page.getByText("10.0.0.25:443")).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
