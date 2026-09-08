import { afterEach, describe, expect, it } from "vitest";
import { noteScopeFromResponse, useTenantScope } from "../lib/tenantScope";
import { renderHook } from "@testing-library/react";

/**
 * A CUSTOMER NAME THAT IS NOT A NAME.
 *
 * `noteScopeFromResponse` is the one place whoami's `viewing_tenant` enters the
 * console, and every reader of what it stores RENDERS that value as a
 * customer's name: app/TenantScopeBanner prints it in bold, and the fleet
 * surface's own caption prints it above an estate-wide kill-switch.
 *
 * The guard used to be plain truthiness, and "   " is truthy. A control plane
 * answering whitespace — a half-populated row, a trimmed-to-nothing display
 * name — therefore produced a caption reading "Tenant" followed by three
 * spaces: a surface claiming to name whose telemetry is on screen, naming
 * nobody, in exactly the place an operator checks before firing containment.
 *
 * Answering whitespace is answering nothing, so the store keeps what it had.
 */

afterEach(() => {
  // The store deliberately cannot un-say a server tenant, so each case here
  // runs against whatever the previous one left. Both cases below assert that
  // whitespace does NOT become the stored name, which is order-independent.
});

describe("whoami's viewing_tenant is a name or it is nothing", () => {
  it("does not adopt a whitespace-only tenant as the customer on screen", () => {
    noteScopeFromResponse("/api/whoami", { viewing_tenant: "   ", cross_tenant: false });
    const { result } = renderHook(() => useTenantScope());
    expect(
      result.current.serverTenant,
      "a control plane answering whitespace was rendered as a customer's name"
    ).not.toBe("   ");
    expect(result.current.serverTenant?.trim() === "" ? "blank" : "named").not.toBe("blank");
  });

  it("adopts a real name, and stores it without surrounding whitespace", () => {
    noteScopeFromResponse("/api/whoami", { viewing_tenant: "  globex  ", cross_tenant: false });
    const { result } = renderHook(() => useTenantScope());
    expect(result.current.serverTenant, "the stored customer carried the server's padding").toBe("globex");
  });
});
