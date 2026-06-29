import type { Page, Route } from "@playwright/test";

import {
  attachBrowserDiagnostics,
  expect,
  expectNoCdnRequests,
  expectNoReleaseBlockingBrowserErrors,
  test
} from "./support/test";

type JsonObject = Record<string, unknown>;

type MockCall = {
  method: string;
  path: string;
  body: JsonObject;
  csrfToken?: string;
};

const now = "2026-06-25T09:00:00Z";

const baseDeviceState: JsonObject = {
  data_plane: "attached",
  links_attached: 2,
  frames_seen: 128,
  devices_seen: 2,
  mode: "enforcing",
  enforcing: true,
  dry_run: false,
  kill_switched: false,
  tracked: 2,
  devices_known: 2,
  counts: {
    pristine: 1,
    throttled: 1,
    tarpit: 0,
    quarantined: 1,
    severed: 0
  }
};

const baseDevices: JsonObject[] = [
  {
    mac: "02:00:00:00:00:10",
    device_id: "fixture-laptop",
    last_ip: "192.168.1.42",
    hostname: "fixture-laptop",
    vendor: "Fixture Labs",
    state: "quarantined",
    protected: false,
    packets: 812,
    source: "arp",
    first_seen: now,
    last_seen: now,
    bucket: { rate_per_sec: 25, burst: 50, tokens: 12, flags: 4 },
    flows: 1,
    revert_pending: true
  },
  {
    mac: "02:00:00:00:00:01",
    device_id: "protected-gateway",
    last_ip: "192.168.1.1",
    hostname: "protected-gateway",
    vendor: "Fixture Labs",
    state: "pristine",
    protected: true,
    packets: 1200,
    source: "dhcp",
    first_seen: now,
    last_seen: now,
    flows: 0
  }
];

const baseFlows = [
  { dest_ip: "10.0.0.25", dest_port: 443, proto: "tcp", packets: 12, bytes: 4096 },
  { dest_ip: "10.0.0.53", dest_port: 53, proto: "udp", packets: 2, bytes: 900 }
];

test.describe("Devices route", () => {
  test.describe.configure({ mode: "serial" });

  test("renders telemetry, device rows, refresh, flow drill-in, and theme persistence", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    const api = await installDevicesApi(page);

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await expect(page.getByRole("heading", { name: "Network Choke - Devices" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Enforcement mode" })).toBeVisible();
    await expect(page.getByRole("heading", { name: "Bulk actions" })).toBeVisible();
    await expect(page.getByLabel("Device data-plane state")).toContainText("plane attached");
    await expect(page.getByLabel("Device data-plane state")).toContainText("links 2");
    await expect(page.getByLabel("Device data-plane state")).toContainText("frames 128");
    await expect(page.locator(".devices-count--pristine .devices-count-value")).toHaveText("1");
    await expect(page.locator(".devices-count--quarantined .devices-count-value")).toHaveText("1");
    await expect(page.getByRole("columnheader", { name: "Device", exact: true })).toBeVisible();
    await expect(page.getByRole("row", { name: /02:00:00:00:00:10.*fixture-laptop.*quarantined/i })).toBeVisible();
    await expect(page.getByRole("row", { name: /02:00:00:00:00:01.*protected-gateway.*pristine/i })).toBeVisible();
    await expect(page.getByLabel("Auto-revert pending")).toBeVisible();

    await page.getByTitle("Expand device flows").first().click();
    await expect(page.getByText("Connecting to (device -> destination)")).toBeVisible();
    await expect(page.getByText("10.0.0.25:443")).toBeVisible();
    await expect(page.getByText("10.0.0.53:53")).toBeVisible();

    const stateReadsBeforeRefresh = api.readCount("/api/choke/device-state");
    await page.getByRole("button", { name: "Refresh" }).click();
    await expect.poll(() => api.readCount("/api/choke/device-state")).toBeGreaterThan(stateReadsBeforeRefresh);

    await page.getByLabel("Toggle theme").click();
    await expect(page.locator("main.devices-route")).toHaveClass(/theme-light/);
    await page.reload();
    await expect(page.locator("main.devices-route")).toHaveClass(/theme-light/);

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("validates and submits bulk choke and thaw actions", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    const api = await installDevicesApi(page);

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await page.getByRole("button", { name: "Choke" }).click();
    await expect(page.locator(".devices-toast")).toHaveText("select at least one device");

    await page.getByLabel("Select 02:00:00:00:00:10").check();
    await expect(page.getByText("1 selected")).toBeVisible();
    await page.getByRole("button", { name: "Choke" }).click();
    await expect(page.locator(".devices-toast")).toHaveText("reason is required for the audit log");

    await page.getByLabel("Device choke action").selectOption("sever");
    await page.getByPlaceholder("reason (required for audit)").fill("incident containment");
    await page.getByPlaceholder("revert after (s)").fill("120");
    await page.getByRole("button", { name: "Choke" }).click();

    await expect.poll(() => api.callsFor("/api/choke/device-jail").length).toBe(1);
    expect(api.callsFor("/api/choke/device-jail")[0]).toMatchObject({
      method: "POST",
      path: "/api/choke/device-jail",
      csrfToken: "mock-csrf",
      body: {
        macs: ["02:00:00:00:00:10"],
        action: "sever",
        reason: "incident containment",
        revert_after_seconds: 120
      }
    });
    await expect(page.locator(".devices-toast")).toHaveText("1/1 choked");

    await page.getByPlaceholder("reason (required for audit)").fill("");
    await page.getByRole("button", { name: "Thaw" }).click();

    await expect.poll(() => api.callsFor("/api/choke/device-thaw").length).toBe(1);
    expect(api.callsFor("/api/choke/device-thaw")[0]).toMatchObject({
      method: "POST",
      path: "/api/choke/device-thaw",
      csrfToken: "mock-csrf",
      body: {
        macs: ["02:00:00:00:00:10"],
        reason: "operator thaw"
      }
    });
    await expect(page.locator(".devices-toast")).toHaveText("1/1 thawed");
    await expect(page.getByText("0 selected")).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("confirms mode changes and enforces the reason gate", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    const api = await installDevicesApi(page);

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await page.getByRole("button", { name: "Switch to detect-only" }).click();
    await expect(page.getByRole("dialog", { name: "Switch to detect-only" })).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    expect(api.callsFor("/api/choke/device-mode")).toEqual([]);

    await page.getByRole("button", { name: "Switch to detect-only" }).click();
    const dialog = page.getByRole("dialog", { name: "Switch to detect-only" });
    await dialog.getByLabel("Reason").fill("");
    await dialog.getByRole("button", { name: "Switch to detect-only" }).click();
    await expect(dialog.getByText("A reason is required for the audit log.")).toBeVisible();

    await dialog.getByLabel("Reason").fill("maintenance test");
    await dialog.getByRole("button", { name: "Switch to detect-only" }).click();

    await expect.poll(() => api.callsFor("/api/choke/device-mode").length).toBe(1);
    expect(api.callsFor("/api/choke/device-mode")[0]).toMatchObject({
      method: "POST",
      path: "/api/choke/device-mode",
      csrfToken: "mock-csrf",
      body: { enforcing: false, reason: "maintenance test" }
    });
    await expect(page.locator(".devices-toast")).toHaveText("mode -> detect-only");
    await expect(page.getByRole("button", { name: "Switch to enforcing" })).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("confirms and toggles the device kill-switch", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    const api = await installDevicesApi(page);

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await page.getByRole("button", { name: "Engage kill-switch" }).click();
    await expect(page.getByRole("dialog", { name: "Engage kill-switch" })).toBeVisible();
    await page.getByRole("button", { name: "Cancel" }).click();
    expect(api.callsFor("/api/choke/device-kill-switch")).toEqual([]);

    await page.getByRole("button", { name: "Engage kill-switch" }).click();
    await page
      .getByRole("dialog", { name: "Engage kill-switch" })
      .getByRole("button", { name: "Engage kill-switch" })
      .click();

    await expect.poll(() => api.callsFor("/api/choke/device-kill-switch").length).toBe(1);
    expect(api.callsFor("/api/choke/device-kill-switch")[0]).toMatchObject({
      method: "POST",
      path: "/api/choke/device-kill-switch",
      csrfToken: "mock-csrf",
      body: { on: true }
    });
    await expect(page.locator(".devices-toast")).toHaveText("kill-switch engaged");
    await expect(page.getByRole("button", { name: "Disengage kill-switch" })).toBeVisible();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });

  test("surfaces disabled device choke state and disables controls", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installDevicesApi(page, { deviceStateStatus: 503 });

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await expect(page.getByText("device choke disabled (start with -devchoke-iface)")).toBeVisible();
    await expect(page.getByText("Start the engine with a device choke interface")).toBeVisible();
    await expect(page.getByLabel("Device choke action")).toBeDisabled();
    await expect(page.getByPlaceholder("reason (required for audit)")).toBeDisabled();
    await expect(page.getByRole("button", { name: "Choke" })).toBeDisabled();
    await expect(page.getByRole("button", { name: "Thaw" })).toBeDisabled();
    await expect(page.getByLabel("Select all devices")).toBeDisabled();

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics, { allowOptionalDisabledApi503: true });
  });

  test("renders the empty device table state", async ({ page }) => {
    const diagnostics = attachBrowserDiagnostics(page);
    await installDevicesApi(page, {
      devices: [],
      state: {
        devices_seen: 0,
        devices_known: 0,
        tracked: 0,
        counts: { pristine: 0, throttled: 0, tarpit: 0, quarantined: 0, severed: 0 }
      }
    });

    await page.goto("/devices");
    await expect(page.getByRole("button", { name: "Refresh" })).toBeEnabled();

    await expect(page.getByText("No devices observed yet. Generate LAN traffic to populate the table.")).toBeVisible();
    await expect(page.getByLabel("Select all devices")).toBeDisabled();
    await expect(page.locator(".devices-count--pristine .devices-count-value")).toHaveText("0");

    expectNoCdnRequests(diagnostics.requestUrls);
    expectNoReleaseBlockingBrowserErrors(diagnostics);
  });
});

async function installDevicesApi(
  page: Page,
  options: {
    state?: JsonObject;
    devices?: JsonObject[];
    flows?: JsonObject[];
    deviceStateStatus?: number;
  } = {}
) {
  const calls: MockCall[] = [];
  const readCounts = new Map<string, number>();
  let state = mergeDeviceState(options.state);
  let devices = clone(options.devices ?? baseDevices);
  const flows = clone(options.flows ?? baseFlows);

  await page.addInitScript(() => {
    document.cookie = "csrf_token=mock-csrf; path=/";
  });

  await page.route("**/api/choke/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;

    if (request.method() !== "GET") {
      const body = parseJsonBody(request.postData());
      calls.push({
        method: request.method(),
        path,
        body,
        csrfToken: request.headers()["x-csrf-token"]
      });
      await fulfillJson(route, writeResponse(path, body));
      return;
    }

    readCounts.set(path, (readCounts.get(path) ?? 0) + 1);
    if (path === "/api/choke/device-state" && options.deviceStateStatus) {
      await route.fulfill({
        status: options.deviceStateStatus,
        contentType: "text/plain",
        body: "network device choke not enabled"
      });
      return;
    }

    switch (path) {
      case "/api/choke/device-state":
        await fulfillJson(route, state);
        return;
      case "/api/choke/devices":
        await fulfillJson(route, devices);
        return;
      case "/api/choke/device-flows":
        await fulfillJson(route, { mac: url.searchParams.get("mac"), flows });
        return;
      default:
        await fulfillJson(route, {});
    }
  });

  function writeResponse(path: string, body: JsonObject): JsonObject {
    switch (path) {
      case "/api/choke/device-jail":
        devices = devices.map((device) =>
          body.macs instanceof Array && body.macs.includes(device.mac) ? { ...device, state: body.action } : device
        );
        return {
          action: body.action,
          reason: body.reason,
          results: (body.macs as string[]).map((mac) => ({ mac, ok: true, state: body.action }))
        };
      case "/api/choke/device-thaw":
        devices = devices.map((device) =>
          body.macs instanceof Array && body.macs.includes(device.mac) ? { ...device, state: "pristine" } : device
        );
        return {
          results: (body.macs as string[]).map((mac) => ({ mac, ok: true, state: "pristine" }))
        };
      case "/api/choke/device-mode": {
        const enforcing = Boolean(body.enforcing);
        const previous = String(state.mode ?? "unknown");
        state = { ...state, enforcing, mode: enforcing ? "enforcing" : "detect-only" };
        return { mode: state.mode as string, previous };
      }
      case "/api/choke/device-kill-switch": {
        const engaged = Boolean(body.on);
        const previous = Boolean(state.kill_switched);
        state = {
          ...state,
          kill_switched: engaged,
          mode: engaged ? "kill-switched" : state.enforcing ? "enforcing" : "detect-only"
        };
        return { engaged, previous };
      }
      default:
        return { ok: true };
    }
  }

  return {
    calls,
    callsFor: (path: string) => calls.filter((call) => call.path === path),
    readCount: (path: string) => readCounts.get(path) ?? 0
  };
}

function mergeDeviceState(overrides?: JsonObject): JsonObject {
  return {
    ...clone(baseDeviceState),
    ...clone(overrides ?? {}),
    counts: {
      ...(baseDeviceState.counts as JsonObject),
      ...((overrides?.counts as JsonObject | undefined) ?? {})
    }
  };
}

function parseJsonBody(raw: string | null): JsonObject {
  if (!raw) return {};
  return JSON.parse(raw) as JsonObject;
}

async function fulfillJson(route: Route, value: unknown): Promise<void> {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(value)
  });
}

function clone<T>(value: T): T {
  return JSON.parse(JSON.stringify(value)) as T;
}
