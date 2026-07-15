import { render, screen, waitFor } from "@testing-library/react";
import { beforeEach, describe, expect, it, vi } from "vitest";

import { ConsoleShell } from "../app/ConsoleShell";
import { useTenantStore } from "../stores/tenant";

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

describe("ConsoleShell", () => {
  beforeEach(() => {
    useTenantStore.getState().clear();
    vi.restoreAllMocks();
  });

  it("bootstraps the session then renders the switcher + children", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ subject: "alice", tenants: ["tenant-a"], cross_tenant: false }))
    );

    render(
      <ConsoleShell>
        <div>panel-content</div>
      </ConsoleShell>
    );

    // The whoami resolves → the shell shows the brand, the switcher, and children.
    await waitFor(() => expect(screen.getByText("alice")).toBeTruthy());
    expect(screen.getByText("eBPF-SOC")).toBeTruthy();
    expect(screen.getByText("panel-content")).toBeTruthy();
    // The tenant store was populated from the session.
    expect(useTenantStore.getState().activeTenant).toBe("tenant-a");
  });

  it("does not render children before a session is established", () => {
    // A never-resolving fetch keeps it in the loading state.
    vi.stubGlobal("fetch", vi.fn(() => new Promise(() => {})));
    render(
      <ConsoleShell>
        <div>panel-content</div>
      </ConsoleShell>
    );
    expect(screen.queryByText("panel-content")).toBeNull();
    expect(screen.getByText("Loading…")).toBeTruthy();
  });
});

describe("ConsoleShell sign-out", () => {
  beforeEach(() => {
    useTenantStore.getState().clear();
    vi.restoreAllMocks();
  });

  it("renders a Sign out link pointing at the BFF logout (a navigation, not a fetch)", async () => {
    vi.stubGlobal(
      "fetch",
      vi.fn(async () => jsonResponse({ subject: "msoc", tenants: ["adanian-internal"], cross_tenant: true }))
    );

    render(
      <ConsoleShell>
        <div>panel</div>
      </ConsoleShell>
    );
    await waitFor(() => expect(screen.getByText("msoc")).toBeTruthy());

    // It must be a link: the browser has to follow the BFF's redirect to the
    // IdP's end-session endpoint. A fetch would end only the local session and
    // leave the SSO cookie intact, making the next "login" silent.
    const link = screen.getByRole("link", { name: /sign out/i });
    expect(link.getAttribute("href")).toBe("/auth/logout");
  });
});
