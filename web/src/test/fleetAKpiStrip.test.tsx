import { render, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { FleetKpiStrip } from "../features/fleet/FleetKpiStrip";
import { EMPTY_KPIS, ladderReading } from "../features/fleet/fleetLogic";
import type { FleetKpis } from "../features/fleet/types";

/**
 * WHAT THE STRIP IS ALLOWED TO CLAIM.
 *
 * Three readings on it were untrue on the live single-agent tenant:
 *
 *  A3 "5 fleet devices" sat under "FLEET SIZE 1". Two denominators in one
 *     tile — hosts and network devices — with nothing saying which was which,
 *     so the tile read as a fleet of five that had lost four.
 *  A4 AUDIT CHAIN rendered "—" over "not maintained on these hosts", forever:
 *     the multi-tenant plane chains nothing centrally, so the tile was
 *     structurally incapable of ever saying anything. A permanent blank in a
 *     KPI slot reads as a gap in coverage, not as a check that does not run
 *     here.
 *  A6 DRIFT and the majority-ladder reading are COMPARATIVE. Over one host
 *     they compare a host with itself, can only ever read zero, and that zero
 *     is read as "the fleet is aligned" — a reassurance nothing measured.
 *
 * The rule these tests pin: a tile either says what its number counts, or it is
 * not rendered; and when a comparative tile is withheld the strip says why,
 * because a missing tile an operator cannot explain sends them looking for a
 * fault.
 */

function kpis(overrides: Partial<FleetKpis>): FleetKpis {
  return { ...EMPTY_KPIS, ...overrides };
}

/** The live single-agent tenant: one host, five devices seen on it, no chain. */
const FLEET_OF_ONE = kpis({
  total: 1,
  healthy: 1,
  enforcing: 1,
  killed: 0,
  killUnknown: 1,
  tracked: 3,
  auditUnsupported: 1,
  deviceHosts: 1,
  devices: 5
});

const TWO_HOSTS = kpis({
  total: 2,
  healthy: 2,
  enforcing: 2,
  drift: 1,
  auditOk: 2,
  auditTotal: 40,
  deviceHosts: 2,
  devices: 5
});

describe("the fleet KPI strip says what each number counts", () => {
  it("names both denominators in the fleet-size tile", () => {
    render(<FleetKpiStrip kpis={FLEET_OF_ONE} />);

    // The value counts hosts; the devices are named as devices, and as seen ON
    // those hosts rather than as members of the fleet.
    expect(screen.getByText(/^host · 5 network devices seen on 1$/)).toBeTruthy();
    expect(
      screen.queryByText(/5 fleet devices/),
      "the tile still calls network devices 'fleet devices' under a host count"
    ).toBeNull();
  });

  it("says no inventory was reported rather than counting zero devices", () => {
    render(<FleetKpiStrip kpis={kpis({ total: 2, healthy: 2 })} />);
    expect(screen.getByText(/hosts · no device inventory reported/)).toBeTruthy();
  });

  it("does not render an audit tile on a deployment that chains nothing centrally", () => {
    render(<FleetKpiStrip kpis={FLEET_OF_ONE} />);

    expect(
      screen.queryByText("Audit chain"),
      "a tile that can never report a fact was rendered as a permanent blank"
    ).toBeNull();
    expect(screen.queryByText("not maintained on these hosts")).toBeNull();
  });

  it("renders the audit tile, over the hosts that actually chain, when some do", () => {
    render(<FleetKpiStrip kpis={kpis({ total: 3, healthy: 3, auditOk: 2, auditUnsupported: 1 })} />);

    expect(screen.getByText("Audit chain")).toBeTruthy();
    // Denominator is the chaining hosts, not every reachable one: dividing by
    // reachable counted a host that maintains no chain as a missing one.
    expect(screen.getByText("2/2")).toBeTruthy();
    expect(screen.getByText(/all intact · 1 not maintained here/)).toBeTruthy();
  });

  it("withholds the comparative tiles on a fleet of one, and says it is one host", () => {
    render(<FleetKpiStrip kpis={FLEET_OF_ONE} />);

    expect(
      screen.queryByText("Drift"),
      "drift was reported over a single host, where it can only ever read zero"
    ).toBeNull();
    expect(screen.queryByText("fleet aligned")).toBeNull();
    expect(screen.getByText(/one host, so there is nothing to compare/)).toBeTruthy();
  });

  it("withholds them again when only one of several configured hosts answered", () => {
    render(<FleetKpiStrip kpis={kpis({ total: 3, healthy: 1 })} />);
    expect(screen.queryByText("Drift")).toBeNull();
    expect(screen.getByText(/Only 1 of 3 configured hosts reported/)).toBeTruthy();
  });

  it("restores the comparative tiles as soon as two hosts have reported", () => {
    render(<FleetKpiStrip kpis={TWO_HOSTS} />);

    expect(screen.getByText("Drift")).toBeTruthy();
    expect(
      screen.queryByText(/nothing to compare/),
      "the strip apologised for a comparison it had just made"
    ).toBeNull();
  });

  it("counts hosts that did not report a kill-switch instead of folding them into zero", () => {
    render(<FleetKpiStrip kpis={FLEET_OF_ONE} />);
    expect(screen.getByText("Kill-switched")).toBeTruthy();
    expect(screen.getByText(/1 host did not report/)).toBeTruthy();
  });
});

describe("the ladder reading beside the threshold inputs is qualified by its population", () => {
  const ladder = { throttle_at: 5, tarpit_at: 10, quarantine_at: 20, sever_at: 40 };

  it("does not call a single host's ladder a majority", () => {
    expect(ladderReading(1, ladder)).toBe("One host reporting · 5/10/20/40");
    expect(ladderReading(1, ladder)).not.toMatch(/majority/i);
  });

  it("names the population it was computed from when there is one", () => {
    expect(ladderReading(4, ladder)).toBe("Majority of 4 · 5/10/20/40");
  });

  it("says nothing was reported rather than printing an empty ladder", () => {
    expect(ladderReading(0, null)).toBe("No host reported a ladder");
    // A reachable host that sent no thresholds: the reading has no value to
    // show, and "Majority ?" was the old one.
    expect(ladderReading(2, null)).toBe("No host reported a ladder");
  });
});
