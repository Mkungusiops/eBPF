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
    // The narrative is now told twice — once in plain English for a responder
    // and once technically — so assert the pair rather than a single block.
    await expect(drill.locator(".choke-narrative-plain")).toContainText("In plain English");
    await expect(drill.locator(".choke-narrative-tech")).toContainText("2-process chain");
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

// The mode control on this page governs the ENGINE only. Tetragon policies
// enforce independently, so a host can be killing processes while the console
// reads detect-only — threat-model EN-3, which cost this project an SSH lockout
// and three hosts of broken package state. The control plane reports the
// divergence; these pin that an operator actually SEES it, since a safety signal
// that only exists in an API response is not a safety signal.
test.describe("Choke route — kernel enforcement posture", () => {
  const chokeState = (kernel: unknown) => ({
    mode: "detect-only",
    dry_run: false,
    kill_switched: false,
    tracked: 2,
    counts: { pristine: 1, throttled: 1, tarpit: 0, quarantined: 1, severed: 0 },
    thresholds: { throttle_at: 5, tarpit_at: 15, quarantine_at: 25, sever_at: 40 },
    audit: { ok: true, total: 2 },
    kernel
  });

  // Routes registered later win in Playwright, so this overrides the catch-all
  // mock installed above it.
  const withKernel = async (page: Parameters<typeof installMockApi>[0], kernel: unknown) => {
    await installMockApi(page);
    await page.route("**/api/choke/state", async (route) => {
      await route.fulfill({
        status: 200,
        contentType: "application/json",
        body: JSON.stringify(chokeState(kernel))
      });
    });
  };

  test("warns, and names the agents, when the kernel is armed behind a detect-only console", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await withKernel(page, {
      agents_reporting: 2,
      agents_total: 2,
      enforcing_agents: ["agent-aaa111"],
      diverged: true,
      diverged_agents: ["agent-aaa111"],
      enforce_actions: 3
    });

    await page.goto("/choke");

    const banner = page.locator('[data-panel="kernel-divergence-banner"]');
    await expect(banner).toBeVisible();
    // The agent has to be named: "somewhere in your fleet" is not actionable.
    await expect(banner).toContainText("agent-aaa111");
    // Actions that already fired are evidence, not risk — say so plainly.
    await expect(banner).toContainText("3 enforcement actions have already fired");

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("stays quiet when every agent reports a monitor-mode kernel", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await withKernel(page, {
      agents_reporting: 2,
      agents_total: 2,
      enforcing_agents: [],
      diverged: false,
      diverged_agents: [],
      enforce_actions: 0
    });

    await page.goto("/choke");

    await expect(page.locator('[data-panel="topbar-row-1"]')).toBeVisible();
    await expect(page.locator('[data-panel="kernel-divergence-banner"]')).toHaveCount(0);
    await expect(page.locator('[data-panel="kernel-posture-unknown-banner"]')).toHaveCount(0);

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("flags unverified posture when an agent never reported its policies", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    // Silence is not safety: the divergence check cannot see a host that did not
    // answer, so a green posture would be a claim the data does not support.
    await withKernel(page, {
      agents_reporting: 1,
      agents_total: 3,
      enforcing_agents: [],
      diverged: false,
      diverged_agents: [],
      enforce_actions: 0
    });

    await page.goto("/choke");

    const banner = page.locator('[data-panel="kernel-posture-unknown-banner"]');
    await expect(banner).toBeVisible();
    await expect(banner).toContainText("2 of 3 agents");
    await expect(page.locator('[data-panel="kernel-divergence-banner"]')).toHaveCount(0);

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});
