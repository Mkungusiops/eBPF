import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { jailSocAlert, normalizeAlert, recordResponseAuthority, setSelectedTenant } from "../features/soc/api";
// Imported at module scope, not inside the helper: the route pulls in the whole
// SOC feature, and paying that on the first test's clock is what made this file
// time out when the suite runs its files in parallel. vi.mock is hoisted above
// this, so the stubs below still apply.
import { SocRoute } from "../features/soc/SocRoute";

/**
 * THE CUSTOMER SWITCHER.
 *
 * A provider account could see WHICH customer it was looking at and could not
 * change it: /api/whoami deliberately refuses to enumerate the provider's
 * customer roster (an MSSP's customer list is itself confidential), and the
 * console named a tenant on no request it made. Both halves now exist —
 * GET /api/tenants serves the roster to a cross-tenant principal and to nobody
 * else, and every read and write endpoint honours `?tenant=`.
 *
 * What this file pins is the pairing of the two, in both directions:
 *
 *   • a tenant-bound operator is offered nothing and ASKS for nothing — they
 *     hold exactly one tenant, and the endpoint 404s them anyway, so a request
 *     here would put a permanent refusal in the network log of a console that
 *     is working perfectly;
 *   • a provider's selection re-scopes the reads AND the containment. A
 *     switcher that moved the dashboard but left the kill-switch aimed at the
 *     previously-resolved customer is the worst defect this console could
 *     ship, and is the failure the cross-tenant responder persona probe exists
 *     to measure;
 *   • a refusal from /api/tenants degrades to the console that was there
 *     before it;
 *   • a persisted customer that is no longer offered scopes NOTHING. A read
 *     for a customer this account can no longer reach answers 404, which this
 *     console renders as an empty dashboard — indistinguishable from a quiet
 *     customer.
 *
 * These render the real route over a stubbed `fetch`, like msocIdentityScope,
 * so the whole path is exercised: the wire documents, the normaliser, the
 * snapshot, the top bar and the request builder underneath them.
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

// D3 owns the graph's DOM and has nothing to do with the top bar.
vi.mock("../features/soc/CorrelationGraph", () => ({ CorrelationGraph: () => null }));

const DEFAULT_TENANT = "acme-corp";
const OTHER_TENANT = "globex";

const PROVIDER_WHOAMI = {
  user: "msoc@provider",
  host: "all tenants",
  role: "cross-tenant-responder",
  cross_tenant: true,
  tenants: [],
  viewing_tenant: DEFAULT_TENANT,
  can_respond: true
};

const ANALYST_WHOAMI = {
  user: "analyst@acme",
  host: DEFAULT_TENANT,
  role: "tenant-analyst",
  cross_tenant: false,
  tenants: [DEFAULT_TENANT],
  viewing_tenant: DEFAULT_TENANT,
  can_respond: true
};

const ROSTER = {
  count: 2,
  source: "tenants table: every customer this control plane has enrolled",
  tenants: [
    { tenant_id: DEFAULT_TENANT, agents: 2, agents_fresh: 2 },
    { tenant_id: OTHER_TENANT, display_name: "Globex", agents: 1, agents_fresh: 0 }
  ]
};

interface Estate {
  paths: string[];
}

/** Serve one whoami, one roster answer, and empty everything else. */
function stubEstate(whoami: Record<string, unknown>, roster: { status: number; body?: unknown }): Estate {
  const estate: Estate = { paths: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      estate.paths.push(path);
      const json = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      if (path.startsWith("/api/tenants")) {
        return roster.status === 200 ? json(roster.body) : json({ error: "not found" }, roster.status);
      }
      if (path.startsWith("/api/whoami")) return json(whoami);
      if (path.startsWith("/api/version") || path.startsWith("/api/health")) return json({});
      if (path.startsWith("/api/choke/jail")) return json({ ok: true });
      return json([]);
    })
  );
  return estate;
}

/** Render the route and wait for the FIRST REAL whoami to land. */
async function renderRoute(): Promise<void> {
  render(<SocRoute />);
  // Until whoami answers the pill renders EMPTY_WHOAMI.host — "localhost" —
  // and every assertion below would pass vacuously against it.
  await waitFor(() => {
    const pill = document.querySelector(".soc-host-pill");
    expect(pill, "the top bar never rendered a host pill").not.toBeNull();
    expect(pill!.textContent, "whoami never landed").not.toContain("localhost");
  });
}

function switcher(): HTMLSelectElement | null {
  return document.querySelector(".soc-tenant-switcher select");
}

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
  // Containment is withheld until the server has answered what this account may
  // do; without this the write assertions could pass by sending nothing at all.
  recordResponseAuthority(true);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("a tenant-bound operator is offered no switcher and asks for no roster", () => {
  it("renders no customer control and never reads /api/tenants", async () => {
    const estate = stubEstate(ANALYST_WHOAMI, { status: 200, body: ROSTER });
    await renderRoute();
    // renderRoute has already waited for a render carrying the REAL whoami, so
    // the effect that reads the roster would have run in that same commit.
    // One macrotask turn is enough for its request to be recorded — and not a
    // wait on some other element appearing, which is a timeout under load
    // rather than an answer about the request.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(switcher(), "a single-customer operator was offered a customer switcher").toBeNull();
    expect(
      estate.paths.filter((path) => path.startsWith("/api/tenants")),
      "the console asked for the provider's customer roster on a tenant-bound session"
    ).toEqual([]);
  });
});

describe("a provider chooses which customer the console is showing", () => {
  it("lists the customers the roster offered", async () => {
    stubEstate(PROVIDER_WHOAMI, { status: 200, body: ROSTER });
    await renderRoute();

    const select = await waitFor(() => {
      const found = switcher();
      expect(found, "a cross-tenant account was given no way to change customer").not.toBeNull();
      return found!;
    });
    expect([...select.options].map((option) => option.value)).toEqual([DEFAULT_TENANT, OTHER_TENANT]);
    // Before any choice, the control shows the customer the SERVER resolved
    // this session to — the one whose rows are already on screen.
    expect(select.value).toBe(DEFAULT_TENANT);
  });

  it("re-scopes the reads, the caption and the containment together", async () => {
    const estate = stubEstate(PROVIDER_WHOAMI, { status: 200, body: ROSTER });
    await renderRoute();
    const select = await waitFor(() => {
      const found = switcher();
      expect(found).not.toBeNull();
      return found!;
    });

    fireEvent.change(select, { target: { value: OTHER_TENANT } });

    // THE READS.
    await waitFor(() => {
      expect(
        estate.paths.some((path) => path.startsWith("/api/alerts") && path.includes(`tenant=${OTHER_TENANT}`)),
        "the dashboard kept reading the customer the operator switched away from"
      ).toBe(true);
    });

    // THE CAPTION. The banner and the pill must name the customer now on
    // screen, and must still not present a customer as the whole estate.
    await waitFor(() => {
      expect(document.querySelector(".soc-scope-banner")?.textContent).toContain(OTHER_TENANT);
    });
    const pill = document.querySelector(".soc-host-pill")!;
    expect(pill.textContent).toContain(OTHER_TENANT);
    expect(pill.querySelector("span")?.textContent?.trim()).not.toBe(OTHER_TENANT);

    // THE WRITE. jailSocAlert is the single point every containment surface in
    // this feature fires through, so scoping it is what makes "the dashboard
    // and the kill-switch cannot be aimed at different customers" true of the
    // request rather than of one button.
    await jailSocAlert({
      alert: normalizeAlert({ exec_id: "YWJj", severity: "critical", title: "t", timestamp: new Date().toISOString() }),
      action: "sever",
      reason: "pinned by test",
      descendants: false
    });
    expect(
      estate.paths,
      "containment was fired at the customer the console had switched away from"
    ).toContain(`/api/choke/jail?tenant=${OTHER_TENANT}`);
  });

  it("keeps the previous customer's rows out of the new customer's dashboard", async () => {
    // The polled snapshot is MERGED into what is on screen, so the buffer must
    // be emptied by the switch itself — otherwise the customer being left
    // keeps contributing alerts to the customer being opened, where they are
    // selectable and containable.
    const estate = stubEstate(PROVIDER_WHOAMI, { status: 200, body: ROSTER });
    vi.stubGlobal(
      "fetch",
      vi.fn(async (input: RequestInfo | URL) => {
        const path = String(input);
        estate.paths.push(path);
        const json = (body: unknown) =>
          new Response(JSON.stringify(body), { status: 200, headers: { "content-type": "application/json" } });
        if (path.startsWith("/api/tenants")) return json(ROSTER);
        if (path.startsWith("/api/whoami")) return json(PROVIDER_WHOAMI);
        if (path.startsWith("/api/version")) return json({});
        if (path.startsWith("/api/alerts")) {
          const title = path.includes(`tenant=${OTHER_TENANT}`) ? "globex beacon" : "acme ransomware stager";
          return json([
            { severity: "critical", title, exec_id: `e-${title}`, timestamp: new Date().toISOString() }
          ]);
        }
        return json([]);
      })
    );

    await renderRoute();
    // The queue and the timeline both render the title, so this counts rows
    // rather than expecting a single node.
    await waitFor(() => expect(screen.queryAllByText(/acme ransomware stager/).length).toBeGreaterThan(0));
    const select = await waitFor(() => {
      const found = switcher();
      expect(found).not.toBeNull();
      return found!;
    });

    fireEvent.change(select, { target: { value: OTHER_TENANT } });

    // Waiting for the NEW customer's row rather than for the old one to
    // vanish: the buffer is empty for an instant during any refresh, so an
    // absence measured before the switch had loaded would pass on a console
    // that merges the two.
    await waitFor(() => expect(screen.queryAllByText(/globex beacon/).length).toBeGreaterThan(0));
    expect(
      screen.queryAllByText(/acme ransomware stager/),
      "one customer's alert stayed on screen under another customer's name"
    ).toEqual([]);
  });
});

describe("a refused roster leaves the console exactly as it was", () => {
  it("renders no switcher and keeps the dashboard working", async () => {
    // 404 is the documented refusal — never 403, so a refusal cannot confirm
    // that a roster exists — and a server too old to serve /api/tenants answers
    // the same way. Neither is an outage.
    const estate = stubEstate(PROVIDER_WHOAMI, { status: 404 });
    await renderRoute();
    await waitFor(() => {
      expect(estate.paths.some((path) => path.startsWith("/api/tenants"))).toBe(true);
    });

    expect(switcher(), "a refused roster still rendered a switcher").toBeNull();
    // The provider console it degrades to is the one that shipped before the
    // switcher: the estate identity, and the customer it resolves to.
    const pill = document.querySelector(".soc-host-pill")!;
    expect(pill.textContent).toContain(DEFAULT_TENANT);
    expect(document.querySelector(".soc-scope-banner")?.textContent).toContain(DEFAULT_TENANT);
    // And nothing is scoped by a roster that was never offered.
    expect(estate.paths.filter((path) => path.includes("tenant="))).toEqual([]);
  });
});

describe("a persisted customer that is no longer offered scopes nothing", () => {
  it("forgets it, reads the server's own default, and says so", async () => {
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify("offboarded-corp"));
    const estate = stubEstate(PROVIDER_WHOAMI, { status: 200, body: ROSTER });
    await renderRoute();
    const select = await waitFor(() => {
      const found = switcher();
      expect(found).not.toBeNull();
      return found!;
    });

    expect(
      estate.paths.filter((path) => path.includes("offboarded-corp")),
      "the console read a customer this account was no longer offered"
    ).toEqual([]);
    // The control names the customer actually on screen, not the stale choice.
    expect(select.value).toBe(DEFAULT_TENANT);
    expect(document.querySelector(".soc-scope-banner")?.textContent).toContain(DEFAULT_TENANT);
    expect(
      window.localStorage.getItem("soc.selectedTenant"),
      "the unreachable customer was left in storage to be adopted by a later read"
    ).toBeNull();
  });

  it("re-adopts one the roster still offers", async () => {
    window.localStorage.setItem("soc.selectedTenant", JSON.stringify(OTHER_TENANT));
    const estate = stubEstate(PROVIDER_WHOAMI, { status: 200, body: ROSTER });
    await renderRoute();

    await waitFor(() => {
      expect(
        estate.paths.some((path) => path.startsWith("/api/alerts") && path.includes(`tenant=${OTHER_TENANT}`)),
        "an operator's saved customer was not restored"
      ).toBe(true);
    });
    expect(switcher()!.value).toBe(OTHER_TENANT);
  });
});
