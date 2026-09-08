import { act, cleanup, render, renderHook, screen, waitFor } from "@testing-library/react";
import userEvent from "@testing-library/user-event";
import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { IntelligenceBody } from "../features/soc/IntelligenceBody";
import { enrichmentSummaryText, useEnrichmentSummary } from "../features/common/enrichmentSummary";
import { setSelectedTenant } from "../lib/tenantScope";

/**
 * THE PANEL UNDER THE BANNER MUST BE THE CUSTOMER ON THE BANNER.
 *
 * The SOC route captions itself "Every panel below is <customer>'s data only",
 * and the switcher makes that true by naming the selection on every request the
 * funnel sends. Behaviour & Intel and the assistant's enrichment strip did not
 * go through the funnel: they raw-fetched /api/baseline* and /api/intel*, so
 * those requests named no customer at all while their answers were rendered —
 * and vouched for — under that sentence. A read-scoped screen with an unscoped
 * panel inside it is worse than an unscoped screen, because the banner is the
 * reason the operator believes the panel.
 *
 * These tests drive the REAL panel and the REAL hook over a stubbed fetch, so
 * what is pinned is the URL that actually leaves the console. They pin the
 * console's half only: whether the control plane HONOURS `?tenant=` on the
 * enrichment routes is a server test, and today its handlers resolve those five
 * endpoints from the session instead (internal/controlplane/enrichment.go).
 */

const BASELINE = {
  enabled: true,
  scope: "tenant",
  anomalies_total: 3,
  status: {
    ready: true,
    observations: 9000,
    need_observations: 500,
    span_seconds: 172_800,
    need_span_seconds: 1800,
    half_life_hours: 336,
    facets: []
  }
};

const INTEL = {
  status: {
    loaded: true,
    indicators: 414,
    ips: 414,
    cidrs: 0,
    domains: 0,
    hashes: 0,
    allowlisted: 0,
    sources: []
  },
  refresh: { enabled: false, feeds: 0 },
  matches_total: 0
};

function anomalyOn(binary: string) {
  return {
    findings: [
      {
        at: new Date().toISOString(),
        kind: "anomaly",
        exec_id: "e1",
        pid: 42,
        binary,
        points: 20,
        reasons: ["never seen on this host"]
      }
    ]
  };
}

/**
 * Serves every enrichment endpoint by PATHNAME, ignoring the query string, so a
 * scoped run and an unscoped run get byte-identical bodies. The only thing that
 * may differ between them is the URL — which is exactly what is asserted.
 *
 * `hold()` parks answers instead of sending them, which is how the moment
 * BETWEEN a switch and its answer is put under test. That moment is the whole
 * risk: it is where a panel keeps rendering the customer just left.
 */
function serve(bodies: () => Record<string, unknown>) {
  const paths: string[] = [];
  const parked: (() => void)[] = [];
  let held = false;

  function answer(url: string): Response {
    const body = bodies()[url.split("?")[0]];
    if (body === undefined) return new Response("{}", { status: 503 });
    return new Response(JSON.stringify(body), { status: 200 });
  }

  vi.stubGlobal(
    "fetch",
    vi.fn((input: RequestInfo | URL) => {
      const url = String(input);
      paths.push(url);
      if (!held) return Promise.resolve(answer(url));
      return new Promise<Response>((resolve) => parked.push(() => resolve(answer(url))));
    })
  );

  return {
    paths,
    hold: () => {
      held = true;
    },
    release: async () => {
      held = false;
      const queued = [...parked];
      parked.length = 0;
      await act(async () => {
        for (const send of queued) send();
      });
    }
  };
}

const READY_ESTATE: Record<string, unknown> = {
  "/api/baseline": BASELINE,
  "/api/intel": INTEL,
  "/api/baseline/anomalies": anomalyOn("/usr/bin/curl"),
  "/api/intel/matches": { findings: [] }
};

beforeEach(() => {
  window.localStorage.clear();
  setSelectedTenant(null);
});

afterEach(() => {
  // Unmounted BEFORE the selection is cleared. The shared cleanup in
  // test-setup.ts runs after this hook, so clearing first would push a tenant
  // change through useSelectedTenant into a still-mounted panel outside act()
  // — a re-read fired by teardown, and a warning that belongs to no test.
  cleanup();
  vi.unstubAllGlobals();
  setSelectedTenant(null);
  window.localStorage.clear();
});

describe("the Behaviour & Intel panel reads the customer the console is pointed at", () => {
  it("names the selected customer on all four of its reads", async () => {
    setSelectedTenant("globex");
    const { paths } = serve(() => READY_ESTATE);

    render(<IntelligenceBody open />);
    await screen.findByText(/414 indicators/);

    expect(
      [...paths].sort(),
      "the panel read the account's default customer's baseline and threat-intel under a banner naming globex"
    ).toEqual(
      [
        "/api/baseline?top=8&tenant=globex",
        "/api/baseline/anomalies?limit=100&tenant=globex",
        "/api/intel?tenant=globex",
        "/api/intel/matches?limit=100&tenant=globex"
      ].sort()
    );
  });

  it("names it on the indicator lookup too", async () => {
    setSelectedTenant("globex");
    const { paths } = serve(() => ({ ...READY_ESTATE, "/api/intel/lookup": { matched: false } }));

    render(<IntelligenceBody open />);
    await screen.findByText(/414 indicators/);

    await userEvent.type(screen.getByLabelText("Indicator to check"), "198.51.100.7");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));

    await waitFor(() =>
      expect(
        paths.some((path) => path.startsWith("/api/intel/lookup")),
        "the lookup never reached the server"
      ).toBe(true)
    );
    expect(
      paths.filter((path) => path.startsWith("/api/intel/lookup")),
      "an indicator checked against the wrong customer's deployment answers about a set the operator is not looking at"
    ).toEqual(["/api/intel/lookup?q=198.51.100.7&tenant=globex"]);
  });

  it("leaves a tenant-bound operator's URLs exactly as they were", async () => {
    // No selection is the single-tenant engine and every tenant-bound operator
    // on the control plane. They have no switcher, and their requests must go
    // out byte for byte as they always did — a `tenant=` they never asked for
    // is a scope claim on a server that may not read one.
    const { paths } = serve(() => READY_ESTATE);

    render(<IntelligenceBody open />);
    await screen.findByText(/414 indicators/);

    expect([...paths].sort()).toEqual(
      [
        "/api/baseline?top=8",
        "/api/baseline/anomalies?limit=100",
        "/api/intel",
        "/api/intel/matches?limit=100"
      ].sort()
    );
  });

  it("re-reads on a switch, and shows no finding it can no longer attribute", async () => {
    setSelectedTenant("acme-corp");
    let estate = READY_ESTATE;
    const server = serve(() => estate);

    render(<IntelligenceBody open />);
    await screen.findByText("/usr/bin/curl");

    // The customer changes, and globex's reads are held in flight. THIS is the
    // moment that matters: acme-corp's anomaly is still the only thing this
    // panel has been told, and the banner above it now says globex. It must
    // not be rendered, and the reads for the new customer must already be out
    // — waiting for the 20s refresh would leave one customer's evidence
    // readable as another's for twenty seconds.
    server.hold();
    estate = { ...READY_ESTATE, "/api/baseline/anomalies": anomalyOn("/usr/bin/wget") };
    await act(async () => {
      setSelectedTenant("globex");
    });

    expect(
      screen.queryByText("/usr/bin/curl"),
      "the customer just left's anomaly is still on screen under the new customer's name"
    ).toBeNull();
    expect(
      server.paths,
      "the switch fired no read, so the panel would have shown the previous customer until the 20s refresh"
    ).toContain("/api/baseline/anomalies?limit=100&tenant=globex");

    await server.release();
    await screen.findByText("/usr/bin/wget");
  });

  it("drops a lookup answered after the customer changed", async () => {
    setSelectedTenant("acme-corp");
    const server = serve(() => ({
      ...READY_ESTATE,
      "/api/intel/lookup": {
        matched: true,
        match: {
          value: "198.51.100.7",
          kind: "ip",
          source: "abuse-c2",
          category: "cobalt-strike",
          confidence: "high",
          observed: "198.51.100.7",
          points: 30
        }
      }
    }));

    render(<IntelligenceBody open />);
    await screen.findByText("/usr/bin/curl");

    // The lookup has its OWN request, which no switch aborts — the panel's
    // polls are torn down by their effect, this one is not. So its answer can
    // arrive after the operator has moved on, and printing it then would put a
    // verdict obtained under one customer beside another customer's name.
    server.hold();
    await userEvent.type(screen.getByLabelText("Indicator to check"), "198.51.100.7");
    await userEvent.click(screen.getByRole("button", { name: "Check" }));
    await act(async () => {
      setSelectedTenant("globex");
    });
    await server.release();

    await screen.findByText("/usr/bin/curl");
    expect(
      screen.queryByText(/MATCH — 198\.51\.100\.7/),
      "a verdict asked for under the previous customer was printed under the new one"
    ).toBeNull();
  });
});

describe("the assistant's enrichment strip reads the same customer", () => {
  it("names the selected customer on both status reads", async () => {
    setSelectedTenant("globex");
    const { paths } = serve(() => READY_ESTATE);

    const { result } = renderHook(() => useEnrichmentSummary(true));
    await waitFor(() => expect(result.current.indicators).toBe(414));

    expect(
      [...paths].sort(),
      "the strip vouched for the default customer's detector beside the selected customer's name"
    ).toEqual(["/api/baseline?top=1&tenant=globex", "/api/intel?tenant=globex"].sort());
  });

  it("leaves a tenant-bound operator's URLs exactly as they were", async () => {
    const { paths } = serve(() => READY_ESTATE);

    const { result } = renderHook(() => useEnrichmentSummary(true));
    await waitFor(() => expect(result.current.indicators).toBe(414));

    expect([...paths].sort()).toEqual(["/api/baseline?top=1", "/api/intel"].sort());
  });

  it("forgets what it knew when the customer changes", async () => {
    setSelectedTenant("acme-corp");
    let estate = READY_ESTATE;
    const server = serve(() => estate);

    const { result } = renderHook(() => useEnrichmentSummary(true));
    await waitFor(() => expect(enrichmentSummaryText(result.current)).toMatch(/Baseline ready · 414 indicators/));

    // "Baseline ready · 414 indicators" is the analyst's evidence that an empty
    // findings list is a finding. Said about the customer they just left, it is
    // not weaker evidence — it is false evidence. So while the new customer's
    // read is in flight the strip knows nothing and says nothing (the sidebar
    // renders its neutral label for this).
    server.hold();
    estate = { "/api/intel": { ...INTEL, status: { ...INTEL.status, loaded: false, indicators: 0 } } };
    await act(async () => {
      setSelectedTenant("globex");
    });

    expect(
      enrichmentSummaryText(result.current),
      "the strip went on vouching for the previous customer's detector"
    ).toBe("");
    expect(server.paths).toContain("/api/intel?tenant=globex");

    await server.release();
    await waitFor(() =>
      expect(enrichmentSummaryText(result.current)).toBe("no threat-intel indicators loaded")
    );
  });
});
