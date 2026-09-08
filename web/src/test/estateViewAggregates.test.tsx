import { fireEvent, render, screen, waitFor } from "@testing-library/react";
import { afterEach, describe, expect, it, vi } from "vitest";
import { EstateView } from "../features/soc/EstateView";

/**
 * THE ESTATE-WIDE VIEW.
 *
 * A provider's console could say which single customer it was resolved to and
 * nothing about the other twenty-four. GET /api/estate/summary answers across
 * them, under one rule — every total ships with the parts it was folded from,
 * and a customer whose read FAILED is not a zero.
 *
 * What this file pins is that the SCREEN keeps that rule, because the ways to
 * lose it are all quiet ones:
 *
 *   • an additive tile that is not the sum, or a posture that is an AVERAGE.
 *     A mean over customers hides one on fire behind nine quiet ones, which is
 *     precisely the situation an MSSP console exists to surface — so posture is
 *     the worst customer's score, named, with the count above the concern
 *     threshold beside it;
 *   • an aggregate with no per-customer breakdown. A number a provider cannot
 *     ask "which customer produced this?" about is the same defect as a console
 *     presenting one customer as the estate, one level up;
 *   • a customer that could not be read rendered as 0, or dropped from the
 *     list. Both read as a calm estate, and this codebase has shipped that
 *     class of false all-clear repeatedly;
 *   • a total whose published parts do not add up to it, trusted in silence.
 *
 * These render the real component over a stubbed `fetch`, so the wire document,
 * the normaliser, the fold and the markup are all exercised.
 */

const ACME = {
  tenant: "acme-corp",
  status: "read",
  alerts: 12,
  alerts_by_severity: { critical: 2, high: 4, medium: 6, low: 0, info: 0 },
  alerts_exact: true,
  decisions: 3,
  decisions_by_action: { sever: 1, quarantine: 2, tarpit: 0, throttle: 0 },
  contained_processes: 2,
  severed_processes: 1,
  agents: 3,
  agents_fresh: 2,
  dropped_records: 4,
  posture: 61,
  weighted_alerts_per_hour: 312.5,
  techniques: { "T1059": 5, "T1078": 2 },
  techniques_sampled: false,
  alerts_without_technique: 5
};

const GLOBEX = {
  tenant: "globex",
  status: "read",
  alerts: 5,
  alerts_by_severity: { critical: 0, high: 1, medium: 4, low: 0, info: 0 },
  alerts_exact: true,
  decisions: 1,
  decisions_by_action: { sever: 0, quarantine: 1, tarpit: 0, throttle: 0 },
  contained_processes: 0,
  severed_processes: 0,
  agents: 2,
  agents_fresh: 2,
  dropped_records: 0,
  posture: 12,
  weighted_alerts_per_hour: 7,
  techniques: { "T1059": 1 },
  techniques_sampled: false,
  alerts_without_technique: 0
};

const INITECH_UNREAD = {
  tenant: "initech",
  status: "unread",
  unread_reason: "alerts could not be read: dial tcp 10.0.4.9:5432: i/o timeout"
};

/** Two customers, both read: the totals are exactly the sum of the parts. */
const HEALTHY = {
  window_min: 60,
  tenants_total: 2,
  tenants_read: 2,
  tenants_unread: 0,
  totals: {
    alerts: 17,
    alerts_by_severity: { critical: 2, high: 5, medium: 10, low: 0, info: 0 },
    alerts_exact: true,
    decisions: 4,
    decisions_by_action: { sever: 1, quarantine: 3, tarpit: 0, throttle: 0 },
    contained_processes: 2,
    severed_processes: 1,
    agents: 5,
    agents_fresh: 4,
    dropped_records: 4
  },
  posture: {
    direction: "higher is worse",
    worst_score: 61,
    worst_tenant: "acme-corp",
    concern_threshold: 45,
    tenants_at_or_above_concern: 1,
    tenants_below_concern: 1,
    tenants_unscored: 0,
    scale: "every tenant scored against the same fixed half-scale",
    note: "the worst tenant's score, never an average"
  },
  top_technique: { technique: "T1059", count: 6, by_tenant: { "acme-corp": 5, globex: 1 }, sampled: false, alerts_without_technique: 5 },
  roster_source: "tenants table",
  tenants: [ACME, GLOBEX],
  bounds: { max_tenants: 25, budget_exceeded: false }
};

/** The same estate with a third customer nobody could read. */
const PARTIAL = {
  ...HEALTHY,
  tenants_total: 3,
  tenants_read: 2,
  tenants_unread: 1,
  totals: { ...HEALTHY.totals, alerts_exact: false },
  posture: { ...HEALTHY.posture, tenants_unscored: 1 },
  tenants: [ACME, GLOBEX, INITECH_UNREAD]
};

function stubEstate(body: unknown, status = 200): string[] {
  const paths: string[] = [];
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      paths.push(String(input));
      return new Response(JSON.stringify(body), { status, headers: { "content-type": "application/json" } });
    })
  );
  return paths;
}

async function renderEstate(body: unknown, status = 200): Promise<string[]> {
  const paths = stubEstate(body, status);
  render(<EstateView enabled rangeMin={60} />);
  // The section paints a loading state first; every assertion below is about
  // the answered one, so waiting on the posture readout rather than on the
  // section keeps them from passing against the placeholder.
  await waitFor(() => {
    expect(document.querySelector(".soc-estate-posture"), "the estate summary never rendered").not.toBeNull();
  });
  return paths;
}

function tileValue(metric: string): string {
  const node = document.querySelector(`.soc-estate-tile[data-metric="${metric}"] .soc-estate-tile-value`);
  expect(node, `no estate tile for ${metric}`).not.toBeNull();
  return node!.textContent!.trim();
}

/** Open one tile's per-customer decomposition and read it back. */
function breakdown(metric: string): Array<{ tenant: string; value: string; text: string }> {
  const tile = document.querySelector(`.soc-estate-tile[data-metric="${metric}"]`)!;
  const toggle = tile.querySelector("button")!;
  if (toggle.getAttribute("aria-expanded") !== "true") fireEvent.click(toggle);
  return [...tile.querySelectorAll(".soc-estate-breakdown li")].map((li) => ({
    tenant: li.querySelector(".soc-estate-breakdown-tenant")?.textContent?.trim() || "",
    // The contribution itself, read apart from the row's prose: an unread
    // customer's REASON can legitimately contain digits (a port, an address),
    // and matching on the whole row would let a real "0" hide behind one.
    value: li.querySelector("strong")?.textContent?.trim() || "",
    text: li.textContent || ""
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("the estate sums what is additive and refuses to average what is not", () => {
  it("renders the estate totals, not one customer's numbers", async () => {
    await renderEstate(HEALTHY);

    // 12 + 5, 3 + 1, 2 + 0, 1 + 0, 3 + 2, 4 + 0 — every one of these would also
    // be satisfied by a view that rendered the FIRST customer if the fixtures
    // were symmetric, so no tile below is allowed to equal acme's own figure.
    expect(tileValue("alerts")).toBe("17");
    expect(tileValue("decisions")).toBe("4");
    expect(tileValue("contained")).toBe("2");
    expect(tileValue("severed")).toBe("1");
    expect(tileValue("agents")).toBe("5");
    expect(tileValue("dropped")).toBe("4");
  });

  it("reports posture as the WORST customer's score, named, and never a mean", async () => {
    await renderEstate(HEALTHY);

    const score = document.querySelector(".soc-estate-posture-score strong")!.textContent!.trim();
    // The mean of 61 and 12 is 36.5. A view that averaged would print 36 or 37
    // here and read as a calm estate while acme burns.
    expect(score, "the estate posture is not the worst customer's score").toBe("61");
    expect(["36", "37", "36.5"], "posture was rendered as an average across customers").not.toContain(score);

    const posture = document.querySelector(".soc-estate-posture")!.textContent!;
    expect(posture, "the worst customer is not named beside their score").toContain("acme-corp");
    expect(posture, "nothing on screen says this is not an average").toMatch(/not an estate average/i);
    // Both sides of the threshold, so "how many customers need attention" is
    // answered without the reader subtracting and getting the direction wrong.
    expect(posture).toMatch(/1 at or above the concern threshold \(45\)/);
    expect(posture).toMatch(/1 below it/);
  });

  it("shows no telemetry-throughput figure, and says it is absent rather than zero", async () => {
    await renderEstate(HEALTHY);
    // The store has no windowed count-by-kind primitive, so the endpoint omits
    // the figure. An empty tile here would be read as "zero events".
    expect(document.querySelector('.soc-estate-tile[data-metric="throughput"]')).toBeNull();
    expect(document.querySelector('.soc-estate-tile[data-metric="eps"]')).toBeNull();
    expect(document.querySelector(".soc-estate-absent")!.textContent).toMatch(/absent rather than zero/i);
  });
});

describe("every estate number can be broken down per customer, on screen", () => {
  it("gives each tile the parts it was folded from", async () => {
    await renderEstate(HEALTHY);

    const expected: Record<string, Record<string, string>> = {
      alerts: { "acme-corp": "12", globex: "5" },
      decisions: { "acme-corp": "3", globex: "1" },
      contained: { "acme-corp": "2", globex: "0" },
      severed: { "acme-corp": "1", globex: "0" },
      agents: { "acme-corp": "3", globex: "2" },
      dropped: { "acme-corp": "4", globex: "0" }
    };
    for (const [metric, parts] of Object.entries(expected)) {
      const rows = breakdown(metric);
      expect(
        rows.map((row) => row.tenant).sort(),
        `the ${metric} tile does not name which customer contributed what`
      ).toEqual(["acme-corp", "globex"]);
      for (const row of rows) {
        expect(row.text, `${metric} for ${row.tenant} is missing its contribution`).toContain(parts[row.tenant]);
      }
    }
  });

  it("puts every customer's contribution in a table that needs no click", async () => {
    await renderEstate(HEALTHY);
    const acme = document.querySelector('.soc-estate-table tr[data-tenant="acme-corp"]')!;
    expect(acme.textContent).toContain("12");
    expect(acme.textContent).toContain("61");
    expect(document.querySelector('.soc-estate-table tr[data-tenant="globex"]')!.textContent).toContain("5");
  });

  it("names the customers behind the top technique instead of asserting a campaign", async () => {
    await renderEstate(HEALTHY);
    const block = document.querySelector(".soc-estate-technique")!;
    expect(block.textContent).toContain("T1059");
    // 5 of the 6 are one customer's. Without the split, one noisy customer is
    // indistinguishable from an estate-wide campaign.
    const split = [...block.querySelectorAll(".soc-estate-breakdown li")].map((li) => li.textContent || "");
    expect(split.some((row) => row.includes("acme-corp") && row.includes("5"))).toBe(true);
    expect(split.some((row) => row.includes("globex") && row.includes("1"))).toBe(true);
    // And the alerts that carried no technique at all are disclosed, so "top
    // technique" is never read as covering every alert.
    expect(block.textContent).toMatch(/5 alert\(s\) carried no technique/);
  });

  it("says so when the published parts do not add up to the published total", async () => {
    // Should be impossible — the endpoint folds its totals out of exactly these
    // rows — which is why it is surfaced rather than trusted: an operator who
    // cannot check a total is back to believing a number on faith.
    await renderEstate({ ...HEALTHY, totals: { ...HEALTHY.totals, alerts: 99 } });
    const tile = document.querySelector('.soc-estate-tile[data-metric="alerts"]')!;
    expect(tile.querySelector(".soc-estate-mismatch"), "a total that its own parts contradict was rendered in silence").not.toBeNull();
    expect(tile.textContent).toContain("17");
  });
});

describe("a customer that could not be read is unread, not zero", () => {
  it("names it, gives the reason, and keeps it out of every total", async () => {
    await renderEstate(PARTIAL);

    // 1. Called out ABOVE the totals: a figure missing a customer must be read
    //    as short before it is read at all.
    const alarm = document.querySelector(".soc-estate-alarm.is-unread")!;
    expect(alarm, "a customer whose read failed was dropped silently").not.toBeNull();
    expect(alarm.textContent).toContain("initech");
    expect(alarm.textContent).toContain("i/o timeout");

    // 2. Its table row is one sentence, not a row of zeroes. A zeroed row is
    //    indistinguishable from a quiet customer, and that is the reading an
    //    operator would act on.
    const row = document.querySelector('.soc-estate-table tr[data-tenant="initech"]')!;
    expect(row.getAttribute("data-status")).toBe("unread");
    expect(row.textContent).toMatch(/not read/i);
    expect(row.querySelectorAll("td").length, "an unread customer was given a row of numbers").toBe(1);

    // 3. In a tile's decomposition it appears with NO number at all.
    const parts = breakdown("alerts");
    const initech = parts.find((part) => part.tenant === "initech");
    expect(initech, "an unread customer vanished from the breakdown").toBeDefined();
    expect(initech!.value).toMatch(/not read/i);
    expect(initech!.value, "an unread customer was rendered as a zero contribution").not.toBe("0");
    expect(initech!.text, "the reason the customer could not be read is missing").toContain("i/o timeout");

    // 4. And the totals themselves are marked as floors, because they are short
    //    by whatever the unread customer holds.
    expect(tileValue("alerts")).toBe("≥ 17");

    // 5. An unscored customer is NOT counted as "below concern": their posture
    //    is unknown, and folding unknown into fine is the same false all-clear.
    const posture = document.querySelector(".soc-estate-posture")!.textContent!;
    expect(posture).toMatch(/1 below it/);
    expect(posture).toMatch(/1 unscored/);
  });

  it("puts unread customers last, whatever order the server sent them in", async () => {
    // The table's caption tells the operator what the row order MEANS, and an
    // unread customer sorted among the quiet ones is how an outage reads as a
    // good night — so the console orders the rows itself rather than inheriting
    // whatever the server happened to send.
    await renderEstate({ ...PARTIAL, tenants: [INITECH_UNREAD, GLOBEX, ACME] });
    const order = [...document.querySelectorAll(".soc-estate-table tbody tr")].map((row) =>
      row.getAttribute("data-tenant")
    );
    expect(order, "an unread customer was left sitting among the customers that were read").toEqual([
      "acme-corp",
      "globex",
      "initech"
    ]);
  });

  it("refuses to show an estate at all when no customer could be read", async () => {
    await renderEstate({
      ...PARTIAL,
      tenants_read: 0,
      tenants_unread: 1,
      tenants_total: 1,
      totals: { ...HEALTHY.totals, alerts: 0, decisions: 0, contained_processes: 0, severed_processes: 0, agents: 0, agents_fresh: 0, dropped_records: 0 },
      posture: { ...HEALTHY.posture, worst_score: 0, worst_tenant: "", tenants_at_or_above_concern: 0, tenants_below_concern: 0, tenants_unscored: 1 },
      tenants: [INITECH_UNREAD]
    });

    // A grid of zeroes over an estate nobody could measure is the single most
    // believable false all-clear this view could print.
    expect(document.querySelectorAll(".soc-estate-tile").length, "zeroed tiles were rendered for an unmeasured estate").toBe(0);
    expect(document.querySelector(".soc-estate-posture")!.textContent).toMatch(/unmeasured estate, not a calm one/i);
    expect(screen.getAllByText(/i\/o timeout/).length, "the unreadable customer was not named").toBeGreaterThan(0);
  });

  it("shows the failure, and no figures, when the whole read fails", async () => {
    stubEstate({ error: "control plane unavailable" }, 503);
    render(<EstateView enabled rangeMin={60} />);
    await waitFor(() => {
      expect(document.querySelector(".soc-estate.is-error"), "a failed estate read rendered no failure").not.toBeNull();
    });
    expect(document.querySelectorAll(".soc-estate-tile").length).toBe(0);
    expect(document.querySelector(".soc-estate-posture")).toBeNull();
  });

  it("renders nothing at all when the server does not offer the endpoint", async () => {
    // 404 is the documented refusal (never 403, so a refusal cannot confirm the
    // view exists) and it is also what an older control plane answers. Neither
    // is an outage: the console degrades to the per-customer view it had.
    const paths = stubEstate({ error: "not found" }, 404);
    const { container } = render(<EstateView enabled rangeMin={60} />);
    await waitFor(() => expect(paths.length).toBeGreaterThan(0));
    await waitFor(() => expect(container.querySelector(".soc-estate")).toBeNull());
  });
});

describe("the estate is read only when it is being shown", () => {
  it("issues no request while disabled", async () => {
    const paths = stubEstate(HEALTHY);
    const { container } = render(<EstateView enabled={false} rangeMin={60} />);
    await new Promise((resolve) => setTimeout(resolve, 0));
    expect(paths, "the estate summary was read for a console that is not showing it").toEqual([]);
    expect(container.querySelector(".soc-estate")).toBeNull();
  });

  it("asks for the window the console is showing", async () => {
    const paths = stubEstate(HEALTHY);
    render(<EstateView enabled rangeMin={1440} />);
    await waitFor(() => expect(paths.length).toBeGreaterThan(0));
    expect(paths[0]).toBe("/api/estate/summary?window_min=1440");
  });
});
