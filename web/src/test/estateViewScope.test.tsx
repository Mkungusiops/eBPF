import { fireEvent, render, waitFor } from "@testing-library/react";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { setSelectedTenant } from "../features/soc/api";
// Imported at module scope for the reason tenantScopeSwitcher gives: the route
// pulls in the whole SOC feature, and paying that on the first test's clock is
// what made that file time out when the suite runs its files in parallel.
import { SocRoute } from "../features/soc/SocRoute";

/**
 * WHO GETS THE ESTATE VIEW, AND WHEN IT GOES AWAY.
 *
 * The estate summary is cross-tenant by construction: it reads every customer
 * this account may reach and audits each read against that customer. Two rules
 * about WHO asks and WHEN, and both are about the request as much as the
 * rendering:
 *
 *   • A TENANT-BOUND OPERATOR NEVER REACHES IT AND NEVER ISSUES IT. The control
 *     plane refuses them with 404 (never 403, so a refusal cannot confirm that
 *     an estate view exists to be denied) — so a console that asked anyway
 *     would put a permanent refusal in the network log of a console that is
 *     working perfectly, and would be one server bug away from painting a
 *     provider's whole book of business for one customer's analyst.
 *   • THE SWITCHER GOVERNS WHICH CONSOLE THIS IS. With no customer selected the
 *     provider sees the estate; the moment they select one, the console is that
 *     customer's and the estate section goes — leaving it up would put an
 *     estate-wide figure directly above one customer's panels, which is the
 *     scope confusion the whole feature exists to remove, in the other
 *     direction.
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

// D3 owns the graph's DOM and has nothing to do with the estate section.
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
  source: "tenants table",
  tenants: [
    { tenant_id: DEFAULT_TENANT, agents: 2, agents_fresh: 2 },
    { tenant_id: OTHER_TENANT, display_name: "Globex", agents: 1, agents_fresh: 1 }
  ]
};

const SUMMARY = {
  window_min: 30,
  tenants_total: 2,
  tenants_read: 2,
  tenants_unread: 0,
  totals: {
    alerts: 17,
    alerts_by_severity: { critical: 2, high: 5, medium: 10 },
    alerts_exact: true,
    decisions: 4,
    decisions_by_action: { sever: 1, quarantine: 3 },
    contained_processes: 2,
    severed_processes: 1,
    agents: 5,
    agents_fresh: 4,
    dropped_records: 0
  },
  posture: {
    worst_score: 61,
    worst_tenant: DEFAULT_TENANT,
    concern_threshold: 45,
    tenants_at_or_above_concern: 1,
    tenants_below_concern: 1,
    tenants_unscored: 0
  },
  top_technique: { technique: "T1059", count: 6, by_tenant: { [DEFAULT_TENANT]: 5, [OTHER_TENANT]: 1 } },
  tenants: [
    { tenant: DEFAULT_TENANT, status: "read", alerts: 12, decisions: 3, contained_processes: 2, severed_processes: 1, agents: 3, agents_fresh: 2, posture: 61, alerts_exact: true },
    { tenant: OTHER_TENANT, status: "read", alerts: 5, decisions: 1, contained_processes: 0, severed_processes: 0, agents: 2, agents_fresh: 2, posture: 12, alerts_exact: true }
  ],
  bounds: { max_tenants: 25, budget_exceeded: false }
};

function stubEstate(whoami: Record<string, unknown>): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      paths.push(path);
      const json = (body: unknown, status = 200) =>
        new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
      if (path.startsWith("/api/estate/summary")) return json(SUMMARY);
      if (path.startsWith("/api/tenants")) return json(ROSTER);
      if (path.startsWith("/api/whoami")) return json(whoami);
      if (path.startsWith("/api/version")) return json({});
      return json([]);
    })
  );
  return paths;
}

/** Render the route and wait for the FIRST REAL whoami to land. */
async function renderRoute(): Promise<void> {
  render(<SocRoute />);
  await waitFor(() => {
    const pill = document.querySelector(".soc-host-pill");
    expect(pill, "the top bar never rendered a host pill").not.toBeNull();
    expect(pill!.textContent, "whoami never landed").not.toContain("localhost");
  });
}

function estateReads(paths: string[]): string[] {
  return paths.filter((path) => path.startsWith("/api/estate/summary"));
}

/**
 * The estate section THAT CARRIES FIGURES, not merely an element with the
 * estate's class.
 *
 * EstateView renders `.soc-estate` in three states — `is-loading` while the
 * read is in flight, `is-error` when it failed, and the populated section — so
 * waiting on `.soc-estate` alone resolves against the loading skeleton and the
 * assertions that follow then read an empty shell. That is a real failure
 * under CPU load and a pass on an idle machine, which is the worst shape a
 * test can have: it reports the machine's speed, not the console's behaviour.
 */
function populatedEstate(): HTMLElement | null {
  return document.querySelector<HTMLElement>(".soc-estate:not(.is-loading):not(.is-error)");
}

/** What the estate section is showing, for a failure message worth reading. */
function estateState(): string {
  const section = document.querySelector(".soc-estate");
  if (!section) return "no estate section at all";
  if (section.classList.contains("is-loading")) return "still reading every customer's window";
  if (section.classList.contains("is-error")) return `an error: ${section.textContent?.trim().slice(0, 120)}`;
  return "populated";
}

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
});

afterEach(() => {
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("a tenant-bound operator never reaches the estate view", () => {
  it("renders no estate section and never asks for the estate summary", async () => {
    const paths = stubEstate(ANALYST_WHOAMI);
    await renderRoute();
    // renderRoute has already waited for a render carrying the REAL whoami, so
    // the effect that would issue the read has run in that same commit. One
    // macrotask turn is enough for its request to be recorded — and not a wait
    // on some element appearing, which is a timeout under load rather than an
    // answer about the request.
    await new Promise((resolve) => setTimeout(resolve, 0));

    expect(document.querySelector(".soc-estate"), "a single-customer operator was shown the whole estate").toBeNull();
    expect(
      estateReads(paths),
      "a tenant-bound console asked the control plane for every customer's summary"
    ).toEqual([]);
  });
});

describe("the switcher governs whether the console shows the estate or one customer", () => {
  it("shows the estate to a provider who has selected no customer", async () => {
    const paths = stubEstate(PROVIDER_WHOAMI);
    await renderRoute();

    const section = await waitFor(() => {
      const found = populatedEstate();
      expect(found, `a provider with no customer selected saw no estate — ${estateState()}`).not.toBeNull();
      return found!;
    });
    expect(estateReads(paths).length).toBeGreaterThan(0);
    // The estate figure, and the customer it belongs to, together — the same
    // rule the per-customer scope banner underneath enforces one level down.
    expect(section.textContent).toContain("17");
    expect(section.querySelector(`.soc-estate-table tr[data-tenant="${OTHER_TENANT}"]`)).not.toBeNull();
  });

  it("leaves the estate view the moment a customer is selected", async () => {
    const paths = stubEstate(PROVIDER_WHOAMI);
    await renderRoute();
    // Wait for the FIGURES, not the skeleton: the point of this test is that a
    // real estate view goes away on selection, and a skeleton disappearing
    // would satisfy the assertion below without ever proving that.
    await waitFor(() => expect(populatedEstate(), `the estate never populated — ${estateState()}`).not.toBeNull());

    const select = await waitFor(() => {
      const found = document.querySelector<HTMLSelectElement>(".soc-tenant-switcher select");
      expect(found, "a cross-tenant account was given no way to change customer").not.toBeNull();
      return found!;
    });
    const before = estateReads(paths).length;
    fireEvent.change(select, { target: { value: OTHER_TENANT } });

    await waitFor(() => {
      expect(
        document.querySelector(".soc-estate"),
        "an estate-wide summary stayed on screen above one customer's panels"
      ).toBeNull();
    });
    // The panels are now that customer's — the console changed scope, it did not
    // merely hide a section.
    await waitFor(() => {
      expect(paths.some((path) => path.startsWith("/api/alerts") && path.includes(`tenant=${OTHER_TENANT}`))).toBe(true);
    });
    expect(
      estateReads(paths).length,
      "the console kept reading every customer's summary after it was pointed at one"
    ).toBe(before);
  });
});
