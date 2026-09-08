import { act, render, screen } from "@testing-library/react";
import { afterEach, describe, expect, it } from "vitest";

import { TenantScopeBanner } from "../app/TenantScopeBanner";
import { FleetScopeCaption } from "../features/fleet/FleetScopeCaption";
import { beginTenantHydration, noteScopeFromResponse, setSelectedTenant } from "../lib/tenantScope";

/**
 * THE FLEET SURFACE MUST NAME ITS CUSTOMER, AND MUST NOT NAME A DIFFERENT ONE
 * FROM THE SHELL.
 *
 * WHAT MOVED. These claims were pinned on FleetTopbar, the fleet console's own
 * top bar. The fleet view is a surface inside the SOC console now and the
 * topbar was deleted in the move — but the caption went with it, and nothing
 * replaced it: the surface is mounted full screen over an opaque backdrop that
 * covers the SOC route's own scope banner, and the shell banner on that entry
 * is TenantScopeBanner in "dashboard" mode, which renders nothing unless the
 * scope is unconfirmed. So a provider pointed at customer B opened the fleet
 * surface, read customer B's hosts and armed an estate-wide kill-switch with no
 * customer named anywhere on the page. The subject is FleetScopeCaption now;
 * the claims are the ones the topbar carried, over the same states, and the
 * wording is the shell banner's ("Provider view", not the topbar's "Provider
 * account") because one vocabulary for one question is the point.
 *
 * THE DEFECT THEY WERE WRITTEN FOR, which still stands: the caption must come
 * from lib/tenantScope, the store the shell banner and lib/api.ts read, and NOT
 * from whoami's `viewing_tenant` — that field is what the control plane
 * resolves a TENANT-LESS request to, whoami is unscoped by design, so it keeps
 * reporting the account's default customer however the console is pointed while
 * the fleet reads and the fleet WRITES beside it carry `?tenant=` for the
 * selection. Two captions is worse than one: the operator has no way to tell
 * which of them the rail is aimed by.
 *
 * ORDER MATTERS IN THIS FILE. `noteScopeFromResponse` is how a whoami answer
 * reaches the store, and it can never unsay a server tenant — a later answer
 * can only replace one non-empty name with another. So the two states that need
 * NO server tenant are asserted first, and nothing before them may record one.
 */

afterEach(() => {
  setSelectedTenant(null);
  window.localStorage.clear();
});

/** What lib/api.ts hands the store when a whoami answer comes back. */
function whoamiSaid(body: Record<string, unknown>) {
  noteScopeFromResponse("/api/whoami", body);
}

describe("the fleet surface captions the customer it is actually pointed at", () => {
  it("leaves the single-tenant engine's product label alone", () => {
    // FIRST, deliberately: no whoami has answered, so the store knows of no
    // tenant and no provider account. Inventing a customer for an engine that
    // has exactly one estate would be the same class of untrue reading in the
    // other direction.
    render(<FleetScopeCaption />);
    expect(screen.getByText("eBPF Threat Gateway · Tier 1")).toBeTruthy();
  });

  it("treats a blank tenant string as no tenant, not as a nameless one", () => {
    // SECOND, and before any real tenant is recorded. Both the store and the
    // caption trim now (lib/tenantScope's noteScopeFromResponse, and the
    // caption's own defensive trim), so this asserts the OUTCOME rather than
    // which of the two produced it — either one regressing renders "Tenant"
    // followed by three spaces.
    whoamiSaid({ user: "operator", viewing_tenant: "   " });
    render(<FleetScopeCaption />);
    expect(screen.queryByText(/^Tenant\s*$/), "a whitespace tenant rendered as 'Tenant '").toBeNull();
    expect(screen.getByText("eBPF Threat Gateway · Tier 1")).toBeTruthy();
  });

  it("leaves a tenant-bound operator's caption exactly as it was", () => {
    // No switcher, no selection, one customer. The shell banner says nothing at
    // all for this account, so if the surface does not name the customer,
    // nothing on screen does.
    whoamiSaid({ user: "operator", viewing_tenant: "acme-corp", cross_tenant: false });
    render(<FleetScopeCaption />);

    expect(screen.getByText("Tenant acme-corp")).toBeTruthy();
    expect(screen.queryByText(/Provider view/)).toBeNull();
  });

  it("names the server's resolution when nobody has been selected", () => {
    whoamiSaid({ user: "msoc-admin", viewing_tenant: "acme-corp", cross_tenant: true });
    render(<FleetScopeCaption />);

    const line = screen.getByText(/Provider view/);
    expect(line.textContent).toMatch(/acme-corp/);
    expect(line.textContent, "a provider was not told these panels are one customer's").toMatch(/only/i);
  });

  it("names the SELECTED customer, not the server's default, when one is chosen", () => {
    // whoami keeps saying the account's default; the funnel is naming the
    // selection on every fleet request.
    whoamiSaid({ user: "msoc-admin", viewing_tenant: "acme-corp", cross_tenant: true });
    setSelectedTenant("beta-industries");
    render(<FleetScopeCaption />);

    const line = screen.getByText(/Provider view/);
    expect(line.textContent).toMatch(/beta-industries/);
    expect(
      line.textContent,
      "the surface named the server's default over another customer's hosts"
    ).not.toMatch(/acme-corp/);
    expect(line.textContent, "a provider was not told these panels are one customer's").toMatch(/only/i);
  });

  it("agrees with the shell banner the console mounts", () => {
    whoamiSaid({ user: "msoc-admin", viewing_tenant: "acme-corp", cross_tenant: true });
    setSelectedTenant("beta-industries");
    render(
      <>
        <TenantScopeBanner mode="shell" />
        <FleetScopeCaption />
      </>
    );

    // Every customer named anywhere on the page is the same customer.
    expect(screen.getAllByText(/beta-industries/).length).toBeGreaterThanOrEqual(2);
    expect(screen.queryByText(/acme-corp/), "the two captions disagreed about the customer").toBeNull();
  });

  it("says it is still confirming rather than naming a customer it is not reading", async () => {
    // Hydration holds the fleet's own reads (lib/api.ts), so the rows below are
    // not the default customer's and are not the remembered one's yet either.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("beta-industries"));
    whoamiSaid({ user: "msoc-admin", viewing_tenant: "acme-corp", cross_tenant: true });
    let release = () => {};
    const held = new Promise<boolean>((resolve) => {
      release = () => resolve(true);
    });
    const hydration = beginTenantHydration(() => held, true);

    render(<FleetScopeCaption />);
    const line = screen.getByText(/Provider view/);
    expect(line.textContent).toMatch(/confirming/i);
    expect(line.textContent).toMatch(/beta-industries/);
    expect(line.textContent, "named a customer whose rows are not being fetched").not.toMatch(/acme-corp/);

    // The settle re-renders the mounted caption, so it is the test's update.
    await act(async () => {
      release();
      await hydration;
    });
  });

  it("names the refusal when the console could not confirm the customer", async () => {
    // The sixth state, and the one the deleted topbar had to be corrected for:
    // lib/api.ts refuses every write while the scope is unconfirmed, so a
    // caption that went on naming the server's default here would assert a
    // scope at the exact moment the surface has none and will not act on one.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("beta-industries"));
    await beginTenantHydration(async () => false, true);

    render(<FleetScopeCaption />);
    // Nothing settles after this render; the state under test is already set.
    const line = screen.getByText(/unconfirmed/i);
    expect(line.textContent, "the rail refuses every write and the caption did not say so").toMatch(
      /refused/i
    );
    expect(line.textContent, "asserted a customer while the console could not confirm one").not.toMatch(
      /acme-corp/
    );
  });
});
