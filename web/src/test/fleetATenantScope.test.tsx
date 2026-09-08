import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FleetScopeCaption } from "../features/fleet/FleetScopeCaption";
import { noteScopeFromResponse } from "../lib/tenantScope";

/**
 * WHOSE FLEET IS THIS?
 *
 * The fleet view answered "Choke Fleet Console — eBPF Threat Gateway · Tier 1":
 * a product label, scoping nothing. Meanwhile the control plane resolves every
 * request to exactly ONE customer — a provider account included, which belongs
 * to no tenant of its own and reaches customers by name — and publishes that
 * answer as `viewing_tenant`, with `cross_tenant` saying which kind of
 * principal is asking.
 *
 * So an MSOC operator carrying several customers could read a page that named
 * none of them, and fire an estate-wide kill-switch from it. Every host in the
 * table and every write from the rail belongs to one customer; the surface says
 * which.
 *
 * The single-tenant engine has no tenant to name and sends neither field. Its
 * brand line is left exactly as it was, because inventing a tenant for it would
 * be the same class of untrue reading in the other direction.
 *
 * WHAT MOVED, AND WHAT DID NOT. The subject was FleetTopbar, plus the fleet
 * feature's own `readWhoami`, which parsed those two fields. The fleet view is
 * a surface inside the SOC console now: the topbar is deleted, and the fields
 * reach the console through lib/api.ts, which hands every whoami answer it
 * carries to `noteScopeFromResponse` — one whoami for the whole shell instead
 * of one per console. So the claims are asserted where they now live: the
 * store's reading of the server's answer, and the caption the fleet surface
 * renders from it. `readWhoami`'s own claims are kept, including the trim,
 * which the store does NOT do — FleetScopeCaption does it instead.
 *
 * ORDER MATTERS IN THIS FILE. The store can never unsay a server tenant (a
 * later whoami can only replace one non-empty name with another) and never
 * unsays `cross_tenant` when a field is absent. Every state that needs a store
 * which has not yet been told something is therefore asserted before the test
 * that tells it.
 */

describe("the fleet surface is qualified by the customer it scopes", () => {
  it("claims no provider view and no customer when the server sent neither", () => {
    // FIRST, on a store nothing has spoken to yet — which is the only place
    // "the field was absent" can be told apart from "it was absent this time".
    const virgin = render(<FleetScopeCaption />);
    expect(screen.getByText("eBPF Threat Gateway · Tier 1")).toBeTruthy();
    expect(screen.queryByText(/Provider view/)).toBeNull();
    // Unmounted before the second render: two captions in one document would
    // make every getByText below ambiguous.
    virgin.unmount();

    // Absent and null are both a server with no cross-tenant principal to
    // describe: the single-tenant engine, or an older control plane. Inferring
    // one would caption a console that has exactly one customer as a provider
    // view.
    noteScopeFromResponse("/api/whoami", { user: "operator", host: "engine-host", cross_tenant: null });
    render(<FleetScopeCaption />);
    expect(screen.getByText("eBPF Threat Gateway · Tier 1")).toBeTruthy();
    expect(screen.queryByText(/Provider view/), "a nameless server was captioned as a provider").toBeNull();
  });

  it("treats a blank tenant string as no tenant, not as a nameless one", () => {
    // SECOND, before any real customer is recorded. The store trims this now
    // and so does the caption, so what is pinned here is that a whitespace
    // answer never becomes a customer's name — not which layer stopped it.
    noteScopeFromResponse("/api/whoami", { user: "operator", viewing_tenant: "   " });
    render(<FleetScopeCaption />);
    expect(screen.queryByText(/^Tenant\s*$/), "a whitespace tenant rendered as 'Tenant '").toBeNull();
    expect(screen.getByText("eBPF Threat Gateway · Tier 1")).toBeTruthy();
  });

  it("does not name a customer the server declined to resolve", () => {
    // cross_tenant with no viewing_tenant: the console knows the kind of
    // principal and not the scope. Naming a customer here would be a guess.
    noteScopeFromResponse("/api/whoami", { user: "msoc-admin", cross_tenant: true });
    render(<FleetScopeCaption />);

    expect(screen.getByText(/has not named the customer/)).toBeTruthy();
  });

  it("names the customer a tenant-bound operator is looking at", () => {
    noteScopeFromResponse("/api/whoami", {
      user: "operator",
      viewing_tenant: "acme-corp",
      cross_tenant: false
    });
    render(<FleetScopeCaption />);

    expect(screen.getByText("Tenant acme-corp")).toBeTruthy();
    expect(
      screen.queryByText("eBPF Threat Gateway · Tier 1"),
      "an unqualified product label still stands over one customer's hosts"
    ).toBeNull();
  });

  it("says a provider account is seeing one customer, not the estate", () => {
    noteScopeFromResponse("/api/whoami", {
      user: "msoc-admin",
      host: "all tenants",
      can_respond: true,
      viewing_tenant: "acme-corp",
      cross_tenant: true
    });
    render(<FleetScopeCaption />);

    const line = screen.getByText(/Provider view/);
    expect(line.textContent).toMatch(/acme-corp/);
    expect(
      line.textContent,
      "a cross-tenant account was not told that these panels are one customer's"
    ).toMatch(/only/i);
  });
});
