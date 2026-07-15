import { fireEvent, render, screen } from "@testing-library/react";
import { beforeEach, describe, expect, it } from "vitest";

import { TenantSwitcher } from "../components/TenantSwitcher";
import { useTenantStore } from "../stores/tenant";

describe("TenantSwitcher", () => {
  beforeEach(() => useTenantStore.getState().clear());

  it("renders nothing before an identity is loaded", () => {
    const { container } = render(<TenantSwitcher />);
    expect(container.firstChild).toBeNull();
  });

  it("offers only authorized tenants and updates the store on switch", () => {
    useTenantStore.getState().setIdentity({
      subject: "alice",
      tenants: ["tenant-a", "tenant-b"],
      crossTenant: false
    });
    render(<TenantSwitcher />);

    expect(screen.getByText("alice")).toBeTruthy();
    const select = screen.getByLabelText("Active tenant") as HTMLSelectElement;
    expect(select.value).toBe("tenant-a"); // defaulted to first authorized tenant
    expect(select.querySelectorAll("option")).toHaveLength(2);

    fireEvent.change(select, { target: { value: "tenant-b" } });
    expect(useTenantStore.getState().activeTenant).toBe("tenant-b");
  });

  it("shows a single, non-switchable tenant without a dropdown", () => {
    useTenantStore.getState().setIdentity({ subject: "bob", tenants: ["tenant-a"], crossTenant: false });
    render(<TenantSwitcher />);
    expect(screen.queryByLabelText("Active tenant")).toBeNull();
    expect(screen.getByText("tenant-a")).toBeTruthy();
  });

  it("badges a cross-tenant MSOC operator", () => {
    useTenantStore.getState().setIdentity({ subject: "msoc", tenants: [], crossTenant: true });
    render(<TenantSwitcher />);
    expect(screen.getByText("MSOC")).toBeTruthy();
  });
});
