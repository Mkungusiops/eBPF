import { beforeEach, describe, expect, it, vi } from "vitest";

import { fetchWhoami, tenantApi, TENANT_HEADER } from "../lib/console";
import {
  canAccessTenant,
  defaultTenant,
  nextActiveTenant,
  parseWhoami,
  type TenantIdentity
} from "../lib/tenantCore";
import { useTenantStore } from "../stores/tenant";

const analyst: TenantIdentity = { subject: "alice", tenants: ["tenant-a"], crossTenant: false };
const msoc: TenantIdentity = { subject: "msoc", tenants: [], crossTenant: true };

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

describe("tenantCore", () => {
  it("parses whoami and coerces null tenants to []", () => {
    expect(parseWhoami({ subject: "a", tenants: null, cross_tenant: false, can_respond: false })).toEqual({
      subject: "a",
      tenants: [],
      crossTenant: false,
      canRespond: false
    });
  });

  it("scopes a tenant-bound operator to their own tenant", () => {
    expect(canAccessTenant(analyst, "tenant-a")).toBe(true);
    expect(canAccessTenant(analyst, "tenant-b")).toBe(false);
  });

  it("lets a cross-tenant role reach any tenant", () => {
    expect(canAccessTenant(msoc, "tenant-x")).toBe(true);
  });

  it("nextActiveTenant refuses an unauthorized switch", () => {
    expect(nextActiveTenant(analyst, "tenant-a", "tenant-b")).toBe("tenant-a");
    expect(nextActiveTenant(analyst, "tenant-a", "tenant-a")).toBe("tenant-a");
    expect(nextActiveTenant(msoc, undefined, "tenant-z")).toBe("tenant-z");
  });

  it("defaultTenant picks the first authorized tenant", () => {
    expect(defaultTenant(analyst)).toBe("tenant-a");
    expect(defaultTenant(msoc)).toBeUndefined();
  });
});

describe("tenant store", () => {
  beforeEach(() => useTenantStore.getState().clear());

  it("defaults the active tenant on identity and guards switches", () => {
    useTenantStore.getState().setIdentity(analyst);
    expect(useTenantStore.getState().activeTenant).toBe("tenant-a");

    useTenantStore.getState().switchTenant("tenant-b"); // unauthorized
    expect(useTenantStore.getState().activeTenant).toBe("tenant-a"); // unchanged
  });
});

describe("console api client", () => {
  beforeEach(() => vi.restoreAllMocks());

  it("tenantApi stamps the active tenant and keeps same-origin credentials", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await tenantApi("/api/events", "tenant-a");

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    const headers = new Headers(init.headers);
    expect(headers.get(TENANT_HEADER)).toBe("tenant-a");
    expect(init.credentials).toBe("same-origin");
  });

  it("tenantApi omits the header when no tenant is active", async () => {
    const fetchMock = vi.fn(async () => jsonResponse({ ok: true }));
    vi.stubGlobal("fetch", fetchMock);

    await tenantApi("/api/events", undefined);

    const [, init] = fetchMock.mock.calls[0] as unknown as [string, RequestInit];
    expect(new Headers(init.headers).has(TENANT_HEADER)).toBe(false);
  });

  it("fetchWhoami maps the BFF response to a TenantIdentity", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ subject: "alice", tenants: ["tenant-a"], cross_tenant: false }))
    );
    expect(await fetchWhoami()).toEqual({ subject: "alice", tenants: ["tenant-a"], crossTenant: false, canRespond: false });
  });
});
