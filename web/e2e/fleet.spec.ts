import { installMockApi } from "./support/mock-api";
import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

test.describe("Fleet route", () => {
  test("renders fleet controls, tables, and live feed panels", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);

    await page.goto("/fleet");

    await expect(page.getByText("Choke Fleet Console")).toBeVisible();
    await expect(page.getByText("Fleet size")).toBeVisible();
    await expect(page.getByRole("heading", { name: "Apply Changes To" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Posture Preset" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Thresholds" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Emergency Controls" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Live Decisions" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Alerts" })).toBeVisible();
    await expect(page.getByRole("row", { name: /alpha-edge.*live.*enforcing/i })).toBeVisible();
    await expect(page.getByRole("row", { name: /bravo-edge.*live.*detect-only/i })).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
