import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchChoke, fetchDevices, fetchFleet, fetchTelemetry } from "../lib/console";

function jsonResponse(obj: unknown) {
  return {
    status: 200,
    ok: true,
    statusText: "OK",
    headers: { get: (h: string) => (h.toLowerCase() === "content-type" ? "application/json" : null) },
    json: async () => obj,
    text: async () => JSON.stringify(obj)
  };
}

describe("fetchTelemetry", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("reads the tenant-scoped telemetry endpoint and returns records", async () => {
    const spy = vi.fn(async (_input: RequestInfo | URL) =>
      jsonResponse({
        tenant: "adanian-internal",
        count: 1,
        records: [{ tenant: "adanian-internal", agent: "agent-x", kind: "process_exec", binary: "/usr/bin/ls", at: Date.now() * 1e6 }]
      })
    );
    vi.stubGlobal("fetch", spy);

    const res = await fetchTelemetry("adanian-internal", 50);
    expect(res.count).toBe(1);
    expect(res.records[0].binary).toBe("/usr/bin/ls");
    expect(String(spy.mock.calls[0][0])).toContain("/api/telemetry?tenant=adanian-internal&limit=50");
  });

  it("url-encodes the tenant id", async () => {
    const spy = vi.fn(async (_input: RequestInfo | URL) => jsonResponse({ tenant: "a b", count: 0, records: [] }));
    vi.stubGlobal("fetch", spy);
    await fetchTelemetry("a b");
    expect(String(spy.mock.calls[0][0])).toContain("tenant=a%20b");
  });

  it("fleet/choke/devices hit their tenant-scoped endpoints", async () => {
    const spy = vi.fn(async (_input: RequestInfo | URL) => jsonResponse({ count: 0, agents: [], chokes: [], devices: [] }));
    vi.stubGlobal("fetch", spy);
    await fetchFleet("acme-corp");
    await fetchChoke("acme-corp");
    await fetchDevices("acme-corp");
    const urls = spy.mock.calls.map((c) => String(c[0]));
    expect(urls[0]).toContain("/api/fleet?tenant=acme-corp");
    expect(urls[1]).toContain("/api/choke?tenant=acme-corp");
    expect(urls[2]).toContain("/api/devices?tenant=acme-corp");
  });
});
