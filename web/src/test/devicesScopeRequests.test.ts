import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

import { createDevicesApi, DevicesApiError } from "../features/devices/api";
import { setSelectedTenant } from "../lib/tenantScope";

/**
 * THE DEVICE PLANE IS AIMED BY THE SAME FUNNEL AS EVERYTHING ELSE.
 *
 * This client had a request path of its own: raw fetch, its own CSRF header,
 * its own 401 redirect — and no tenant. Every device request therefore left
 * without the `?tenant=` that names the customer the console is pointed at, so
 * a provider operator who had switched to customer B read B's device table and
 * jailed, thawed, kill-switched and re-moded devices belonging to whichever
 * customer the server resolves a tenant-less write to. Nothing about that
 * fails: the request is accepted, on the wrong LAN. It is the second
 * containment gateway, and the one whose targets are other people's phones,
 * cameras and PLCs.
 *
 * These tests drive the api client the console actually builds over a stubbed
 * fetch, so what is pinned is the URL that leaves the browser rather than a
 * helper someone may have remembered to call. The DEFAULT requester is used
 * throughout on purpose: DevicesRoute falls back to `createDevicesApi()` when
 * it is mounted without an api prop, so an unscoped default is one dropped prop
 * away from being the live path again.
 */

const MAC = "02:00:00:00:00:01";

interface Sent {
  url: string;
  method: string;
  body: unknown;
  csrf: string | null;
}

function recordRequests(body: unknown = { ok: true }): Sent[] {
  const sent: Sent[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL, init: RequestInit = {}) => {
      const headers = new Headers(init.headers);
      sent.push({
        url: String(input),
        method: (init.method ?? "GET").toUpperCase(),
        body: typeof init.body === "string" ? JSON.parse(init.body) : init.body,
        csrf: headers.get("X-CSRF-Token")
      });
      return new Response(JSON.stringify(body), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return sent;
}

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
  document.cookie = "csrf_token=test-csrf";
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("every device write names the customer the console is showing", () => {
  it("carries the selection on jail, thaw, kill-switch and mode", async () => {
    setSelectedTenant("globex");
    const sent = recordRequests({ results: [], engaged: true, mode: "enforcing" });
    const api = createDevicesApi();

    await api.jailDevices({ macs: [MAC], action: "quarantine", reason: "pinned by test" });
    await api.thawDevices({ macs: [MAC], reason: "pinned by test" });
    await api.setKillSwitch(true, "pinned by test");
    await api.setMode(true, "pinned by test");

    expect(
      sent.map((request) => request.url),
      "a device containment landed on the customer the server defaults to, not the one on screen"
    ).toEqual([
      "/api/choke/device-jail?tenant=globex",
      "/api/choke/device-thaw?tenant=globex",
      "/api/choke/device-kill-switch?tenant=globex",
      "/api/choke/device-mode?tenant=globex"
    ]);
    // The scope is on the URL and nowhere else, because that is where both
    // write planes read it from: the handlers never look in the body.
    for (const request of sent) {
      expect(request.method).toBe("POST");
      expect(request.body).not.toHaveProperty("tenant");
    }
  });

  it("keeps the CSRF header the old hand-rolled path was carrying", async () => {
    // The funnel sets it for any unsafe /api/ request. Losing it while moving
    // the client onto the funnel would trade an unaimed write for a refused
    // one, which the e2e csrf contract would catch far later than this.
    setSelectedTenant("globex");
    const sent = recordRequests({ results: [] });

    await createDevicesApi().jailDevices({ macs: [MAC], action: "sever", reason: "pinned by test" });

    expect(sent[0].csrf).toBe("test-csrf");
  });

  it("carries it on the reads as well, including one that already has a query", async () => {
    // Reads matter for the same reason: a table showing customer A's devices
    // is what the operator ticks the checkboxes on.
    setSelectedTenant("globex");
    const sent = recordRequests([]);
    const api = createDevicesApi();

    await api.fetchState();
    await api.fetchDevices();
    await api.fetchFlows(MAC);

    expect(sent.map((request) => request.url)).toEqual([
      "/api/choke/device-state?tenant=globex",
      "/api/choke/devices?tenant=globex",
      `/api/choke/device-flows?mac=${encodeURIComponent(MAC)}&tenant=globex`
    ]);
  });

  it("leaves the account-level whoami unscoped", async () => {
    // whoami reports the principal and the customer the SERVER resolves their
    // tenant-less requests to. Scoping it would ask the one endpoint that
    // answers that question to answer with the console's guess instead.
    setSelectedTenant("globex");
    const sent = recordRequests({ can_respond: true });

    await createDevicesApi().fetchWhoami?.();

    expect(sent.map((request) => request.url)).toEqual(["/api/whoami"]);
  });

  it("sends a tenant-bound operator exactly the requests it always did", async () => {
    // No selection — the single-tenant engine, which has no tenants, and every
    // tenant-bound operator on the control plane. A stray parameter here is a
    // scope claim from a console that never offered a switcher.
    const sent = recordRequests({ results: [] });
    const api = createDevicesApi();

    await api.fetchDevices();
    await api.jailDevices({ macs: [MAC], action: "throttle", reason: "pinned by test" });

    expect(sent.map((request) => request.url)).toEqual([
      "/api/choke/devices",
      "/api/choke/device-jail"
    ]);
  });

  it("aims at the customer selected when the request goes out, not when it was built", async () => {
    // There is always a gap between deciding to contain and sending: a confirm
    // modal, a typed reason. The funnel reads the selection as the request
    // leaves, so a switch inside that gap cannot leave the write pointed at the
    // customer the operator has already left.
    setSelectedTenant("acme-corp");
    const sent = recordRequests({ results: [] });
    const api = createDevicesApi();

    let confirmed: () => void = () => {};
    const operatorConfirmed = new Promise<void>((resolve) => {
      confirmed = resolve;
    });
    const pending = operatorConfirmed.then(() =>
      api.jailDevices({ macs: [MAC], action: "sever", reason: "pinned by test" })
    );

    setSelectedTenant("globex");
    confirmed();
    await pending;

    expect(sent[0].url).toBe("/api/choke/device-jail?tenant=globex");
  });
});

describe("the funnel's failures still reach the device console in its own terms", () => {
  it("keeps the server's sentence on a refusal instead of a bare status line", async () => {
    // The engine answers text/plain, and the funnel's ApiError falls back to
    // statusText for one — which would have turned the kill-switch's
    // explanation of a missing reason into "Bad Request" in the operator's
    // toast, about a field they were never shown.
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => new Response('"reason" is required to engage the device kill-switch', { status: 400 }))
    );

    const caught = await createDevicesApi()
      .setKillSwitch(true, "")
      .catch((error: unknown) => error);

    expect(caught).toBeInstanceOf(DevicesApiError);
    expect((caught as DevicesApiError).status).toBe(400);
    expect((caught as DevicesApiError).message).toContain("is required to engage the device kill-switch");
  });

  it("still reports a disabled data plane as a 503 the route can recognise", async () => {
    vi.stubGlobal("fetch", vi.fn(async () => new Response("device choke disabled", { status: 503 })));

    const caught = await createDevicesApi()
      .fetchState()
      .catch((error: unknown) => error);

    expect((caught as DevicesApiError).status).toBe(503);
  });
});
