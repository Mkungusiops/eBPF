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
    // The Containment Command hero and its ladder are the dual-mode redesign's
    // shared spine: both the Command and the Assurance lens hang off them, so
    // they are what "the workbench rendered" now means.
    await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();
    await expect(page.locator('[data-panel="state-ladder-panel"]')).toBeVisible();
    await expect(page.locator('[data-panel="choke-map-bpf-mirror"]')).toBeVisible();
    await expect(page.locator('[data-panel="decision-tape"]')).toBeVisible();
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

  /**
   * The Command ⇄ Assurance lens.
   *
   * WHAT THIS REPLACED: a "policy preview" workbench that no longer exists.
   * The dual-mode redesign removed it and put two LENSES on one containment
   * surface in its place — Command for the responder acting now, Assurance for
   * the reader asking whether the control works. The old spec kept clicking a
   * "Preview matches" button that had been deleted, so the Choke route's
   * headline redesign shipped with no browser coverage at all.
   *
   * WHY IT IS HERE AND NOT IN UNIT TESTS: the two lenses are mutually
   * exclusive renders of one route behind a tablist. jsdom can assert the
   * component swaps; only a browser can show that the swap actually replaces
   * what is on screen and that the shared hero survives it.
   */
  test("switches between the Command and Assurance lenses over one shared hero", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);
    await page.setViewportSize({ width: 1440, height: 900 });

    await page.goto("/choke");

    const lens = page.getByRole("tablist", { name: "View mode" });
    const command = lens.getByRole("tab", { name: "Command" });
    const assurance = lens.getByRole("tab", { name: "Assurance" });

    // Command is the default: the responder's lens, with the live process work.
    await expect(command).toHaveAttribute("aria-selected", "true");
    await expect(page.locator('[data-panel="tracked-processes-list"]')).toBeVisible();
    await expect(page.locator('[data-panel="assurance-view"]')).toHaveCount(0);

    await assurance.click();

    await expect(assurance).toHaveAttribute("aria-selected", "true");
    const assuranceView = page.locator('[data-panel="assurance-view"]');
    await expect(assuranceView).toBeVisible();
    await expect(assuranceView.getByRole("heading", { name: "Security posture" })).toBeVisible();
    await expect(assuranceView.getByRole("heading", { name: "Audit integrity" })).toBeVisible();
    await expect(assuranceView.getByRole("heading", { name: "Enforcement & reversibility" })).toBeVisible();
    // The lens SWAPS the body. If the process list survived the switch the two
    // views would be stacked rather than alternatives, which is the layout bug
    // the redesign exists to avoid.
    await expect(page.locator('[data-panel="tracked-processes-list"]')).toHaveCount(0);

    // The hero and its ladder belong to neither lens and must outlive both.
    await expect(page.locator('[data-panel="containment-ladder"]')).toBeVisible();

    await command.click();
    await expect(page.locator('[data-panel="tracked-processes-list"]')).toBeVisible();

    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("clears the alerts badge from the notifications panel", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installMockApi(page);
    await page.setViewportSize({ width: 1440, height: 900 });

    await page.goto("/choke");

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
