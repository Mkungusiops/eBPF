import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * THE CUSTOMER ROSTER IS READ ONCE PER PAGE LOAD.
 *
 * Two things want the same list: the shell's boot driver, which confirms the
 * customer this browser remembers before any scoped request is released
 * (app/tenantHydration.ts), and the dashboard's switcher, which offers it. They
 * used to ask separately, so opening the console read /api/tenants twice.
 *
 * That is not a wasted request. The control plane AUDITS every read of
 * /api/tenants against the account, so the second one writes a second row into
 * a customer's access trail for a page an operator opened once — a log that
 * says the provider looked twice when they looked once. An access trail that
 * over-reports is the same class of untruth as a dashboard that does.
 *
 * The hook therefore consumes what the driver already fetched, and asks only
 * when there was no driver read to consume (a console with no remembered
 * customer) or when that read did not answer.
 */

vi.mock("../lib/stream", () => ({
  useStream: () => ({
    state: "live" as const,
    retries: 0,
    messageCount: 0,
    lastMessageAt: Date.now(),
    lastEventAt: Date.now(),
    frames: [],
    latestBatch: [],
    batchId: 0,
    reconnect: () => {}
  })
}));

// D3 owns the graph's DOM and has nothing to do with the roster.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

const PROVIDER_WHOAMI = {
  user: "msoc@provider",
  host: "all tenants",
  role: "cross-tenant-responder",
  cross_tenant: true,
  tenants: [],
  viewing_tenant: "acme-corp",
  can_respond: true
};

const ROSTER = {
  count: 2,
  source: "tenants table: every customer this control plane has enrolled",
  tenants: [
    { tenant_id: "acme-corp", agents: 2, agents_fresh: 2 },
    { tenant_id: "globex", display_name: "Globex", agents: 1, agents_fresh: 0 }
  ]
};

function stubEstate(): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      paths.push(path);
      const json = (body: unknown) =>
        new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
      if (path.startsWith("/api/tenants")) return json(ROSTER);
      if (path.startsWith("/api/whoami")) return json(PROVIDER_WHOAMI);
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) return json({});
      return json([]);
    })
  );
  return paths;
}

/** Every roster read this page load made, however it was spelt. */
function rosterReads(paths: string[]): string[] {
  return paths.filter((path) => path.startsWith("/api/tenants"));
}

beforeEach(() => {
  vi.resetModules();
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
  window.localStorage.clear();
});

describe("the customer roster is read once per page load", () => {
  it("serves the switcher from the boot driver's read instead of asking again", async () => {
    // A remembered customer is what makes the driver run at all: with no claim
    // to confirm, startTenantScopeHydration does nothing by design.
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("globex"));
    const paths = stubEstate();

    const { startTenantScopeHydration } = await import("../app/tenantHydration");
    const { SocRoute } = await import("../features/soc/SocRoute");
    const { recordResponseAuthority } = await import("../features/soc/api");
    recordResponseAuthority(true);

    await startTenantScopeHydration();
    expect(rosterReads(paths), "the boot driver did not confirm the remembered customer").toHaveLength(1);

    render(<SocRoute />);
    // The switcher only exists once whoami has said this account is
    // cross-tenant, so waiting for it is what proves the roster was WANTED
    // here — without it this test would pass against a dashboard that never
    // asked because it never rendered a switcher at all.
    await waitFor(() => {
      const select = document.querySelector(".soc-tenant-switcher select");
      expect(select, "the provider was offered no customer switcher").not.toBeNull();
      expect(select!.querySelectorAll("option").length, "the switcher rendered an empty list").toBeGreaterThan(1);
    });

    expect(
      rosterReads(paths),
      "the roster was read twice for one page load — two audited rows in a customer's access trail"
    ).toEqual(["/api/tenants"]);
  });

  it("still asks when there was no boot read to consume", async () => {
    // No remembered customer: the driver returns without reading anything, so
    // the switcher has nothing to inherit and must fetch the list itself.
    const paths = stubEstate();

    const { startTenantScopeHydration } = await import("../app/tenantHydration");
    const { SocRoute } = await import("../features/soc/SocRoute");
    await startTenantScopeHydration();
    expect(rosterReads(paths), "a console with no remembered customer confirmed one anyway").toEqual([]);

    render(<SocRoute />);
    await waitFor(() => {
      expect(rosterReads(paths), "the switcher never read the roster it offers").toEqual(["/api/tenants"]);
    });
  });
});
