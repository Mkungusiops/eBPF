import { render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";

/**
 * THE CONSOLE MUST NOT PRESENT ONE CUSTOMER AS THE WHOLE ESTATE.
 *
 * Pinned twice against the live estate — `msoc.probe.spec.ts` for the
 * cross-tenant admin and `personas.probe.spec.ts` for the cross-tenant
 * responder. Both measure the same thing: sign in as a principal that belongs
 * to no tenant, read `.soc-host-pill`, and find one real customer's name there,
 * identical to what that customer's own analyst sees. The responder's version
 * is the sharper one — they act, and the containment they fire is aimed by a
 * console that silently chose the tenant for them.
 *
 * The server half is fixed elsewhere: a cross-tenant principal's `tenants`
 * scope is now genuinely empty, and whoami publishes `viewing_tenant`, the one
 * tenant the server resolves this session's tenant-less reads to. This file
 * pins the console half, and it deliberately pins BOTH directions:
 *
 *   • the estate identity is never a customer's name, AND
 *   • the customer whose data is actually on screen is named.
 *
 * The second is not decoration. A pill reading "all tenants" over one
 * customer's alerts, posture and containment history would satisfy the probe
 * and be a worse claim than the defect it replaced.
 *
 * These render the real route over a stubbed `fetch`, so the whole path is
 * exercised: the wire document, normalizeWhoami, the snapshot, the top bar.
 * Mocking the snapshot instead would let the normaliser drop the fields and
 * still pass, which is exactly how the first sweep stopped one layer short.
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

// D3 owns the graph's DOM and has nothing to do with the top bar; rendering it
// in jsdom only buys flakiness.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

const TENANT = "acme-corp";

function jsonResponse(body: unknown): Response {
  return new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
}

/** Serve one whoami document and empty everything else. */
function stubEstate(whoami: Record<string, unknown>): void {
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      if (path.startsWith("/api/whoami")) return jsonResponse(whoami);
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) return jsonResponse({});
      return jsonResponse([]);
    })
  );
}

async function renderRouteAndReadPill(): Promise<HTMLElement> {
  const { SocRoute } = await import("../features/soc/SocRoute");
  render(<SocRoute />);
  // Until the first whoami lands the pill renders the empty identity,
  // "localhost" — reading it that early passes vacuously, which is the trap the
  // probe docblocks call out by name.
  await waitFor(() => {
    const pill = document.querySelector(".soc-host-pill");
    expect(pill, "the top bar never rendered a host pill").not.toBeNull();
    expect(pill!.textContent, "whoami never landed").not.toContain("localhost");
  });
  return document.querySelector(".soc-host-pill") as HTMLElement;
}

beforeEach(() => {
  window.localStorage.clear();
});

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("a cross-tenant console names the provider, not one customer", () => {
  it("does not render a tenant name as the estate identity", async () => {
    // What the reworked control plane sends: no tenant list at all, an estate
    // label, and the tenant the reads actually resolve to.
    stubEstate({
      user: "msoc@provider",
      host: "all tenants",
      role: "msoc-admin",
      cross_tenant: true,
      tenants: [],
      viewing_tenant: TENANT,
      can_respond: true
    });
    const pill = await renderRouteAndReadPill();

    // The probe's own measurement: the pill text is not a customer's name.
    expect(pill.textContent?.trim()).not.toBe(TENANT);
    // And the estate half of it — the part that answers "whose console is
    // this?" — is not the customer either, with or without the caption beside
    // it.
    const estate = pill.querySelector("span")?.textContent?.trim();
    expect(estate, "the estate identity is one customer's name").not.toBe(TENANT);
  });

  it("names the customer whose data is actually on screen", async () => {
    stubEstate({
      user: "msoc@provider",
      host: "all tenants",
      role: "cross-tenant-responder",
      cross_tenant: true,
      tenants: [],
      viewing_tenant: TENANT,
      can_respond: true
    });
    const pill = await renderRouteAndReadPill();

    // Without this the console has only swapped one false statement for
    // another: an estate-wide label over a single customer's numbers.
    expect(pill.textContent, "the pill claims the estate without saying which tenant is displayed").toContain(TENANT);

    const banner = document.querySelector(".soc-scope-banner");
    expect(banner, "no scope caption for a provider session").not.toBeNull();
    expect(banner!.textContent).toContain(TENANT);
  });

  it("refuses an estate label that is simply the tenant being displayed", async () => {
    // A control plane that has not been updated still publishes scope[0] as
    // `host`. The console must not depend on the server having been fixed: an
    // estate identity that equals the tenant captioned underneath it is not an
    // estate identity.
    stubEstate({
      user: "msoc@provider",
      host: TENANT,
      role: "msoc-admin",
      cross_tenant: true,
      tenants: [],
      viewing_tenant: TENANT
    });
    const { SocRoute } = await import("../features/soc/SocRoute");
    render(<SocRoute />);
    await waitFor(() => {
      expect(document.querySelector(".soc-scope-banner"), "whoami never landed").not.toBeNull();
    });
    const estate = document.querySelector(".soc-host-pill span")?.textContent?.trim();
    expect(estate, "an out-of-date server's customer name was displayed as the estate").not.toBe(TENANT);
  });
});

describe("a tenant-bound console is left exactly as it was", () => {
  it("shows the operator's own tenant as the estate, with no provider caption", async () => {
    stubEstate({
      user: "analyst@acme",
      host: TENANT,
      role: "tenant-analyst",
      cross_tenant: false,
      tenants: [TENANT],
      viewing_tenant: TENANT,
      can_respond: true
    });
    const pill = await renderRouteAndReadPill();

    // For an operator who belongs to this tenant, its name IS the estate: the
    // fix must not caption a single-customer console with provider language.
    expect(pill.textContent?.trim()).toBe(TENANT);
    expect(document.querySelector(".soc-scope-banner"), "a tenant-bound operator was told they are the provider").toBeNull();
  });
});
