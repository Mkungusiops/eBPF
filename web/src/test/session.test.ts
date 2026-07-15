import { describe, expect, it, vi } from "vitest";

import { ApiError } from "../lib/api";
import { loadSession } from "../lib/session";
import type { TenantIdentity } from "../lib/tenantCore";

const identity: TenantIdentity = { subject: "alice", tenants: ["tenant-a"], crossTenant: false };

describe("loadSession", () => {
  it("authenticated: applies the identity to the store", async () => {
    const setIdentity = vi.fn();
    const redirect = vi.fn();
    const status = await loadSession({ whoami: async () => identity, setIdentity, redirect });
    expect(status).toBe("authenticated");
    expect(setIdentity).toHaveBeenCalledWith(identity);
    expect(redirect).not.toHaveBeenCalled();
  });

  it("401: hands off to the BFF login", async () => {
    const redirect = vi.fn();
    const status = await loadSession({
      whoami: async () => {
        throw new ApiError("unauthorized", 401, null);
      },
      setIdentity: vi.fn(),
      redirect
    });
    expect(status).toBe("redirecting");
    expect(redirect).toHaveBeenCalledWith("/auth/login");
  });

  it("other error: surfaces an error status without redirecting", async () => {
    const redirect = vi.fn();
    const status = await loadSession({
      whoami: async () => {
        throw new ApiError("boom", 500, null);
      },
      setIdentity: vi.fn(),
      redirect
    });
    expect(status).toBe("error");
    expect(redirect).not.toHaveBeenCalled();
  });
});
