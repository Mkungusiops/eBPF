import { describe, expect, it } from "vitest";
import {
  deriveFleet,
  detectDrift,
  majority,
  summarizeFanout,
  thresholdKey,
  validateThresholds
} from "../../features/fleet/fleetLogic";
import type { ChokeState, FleetPeer, HostResult } from "../../features/fleet/types";

const peers: FleetPeer[] = [
  { name: "alpha", url: "http://alpha" },
  { name: "beta", url: "http://beta" },
  { name: "gamma", url: "http://gamma" }
];

const thresholds = {
  throttle_at: 10,
  tarpit_at: 30,
  quarantine_at: 60,
  sever_at: 100
};

function state(name: string, data: Partial<ChokeState>): HostResult<ChokeState> {
  return {
    name,
    ok: true,
    data: {
      mode: "enforcing",
      kill_switched: false,
      tracked: 0,
      counts: {},
      thresholds,
      audit: { ok: true, total: 1 },
      ...data
    }
  };
}

describe("fleet logic", () => {
  it("finds majority values in insertion order", () => {
    expect(majority(["enforcing", "detect-only", "enforcing"])).toBe("enforcing");
    expect(majority<string>([])).toBeNull();
  });

  it("serializes and validates thresholds", () => {
    expect(thresholdKey(thresholds)).toBe("10/30/60/100");
    expect(validateThresholds(thresholds)).toBeNull();
    expect(validateThresholds({ throttle_at: 10, tarpit_at: 8, quarantine_at: 60, sever_at: 100 })).toContain(
      "strictly ascending"
    );
  });

  it("detects drift against reachable ok hosts only", () => {
    const drift = detectDrift([
      state("alpha", {}),
      state("beta", {}),
      state("gamma", { mode: "detect-only", kill_switched: true })
    ]);

    expect(drift.mode).toBe("enforcing");
    expect(drift.kill).toBe("off");
    expect(drift.thresholds).toBe("10/30/60/100");
  });

  it("derives KPIs and row drift", () => {
    const derived = deriveFleet(
      peers,
      [
        state("alpha", { tracked: 4, counts: { quarantined: 1, tarpit: 2, throttled: 3 } }),
        state("beta", { tracked: 2 }),
        state("gamma", { mode: "detect-only", audit: { ok: false, total: 9 } })
      ],
      [{ name: "alpha", ok: true, data: [{ mac: "aa:bb", state: "throttled" }] }]
    );

    expect(derived.kpis.total).toBe(3);
    expect(derived.kpis.healthy).toBe(3);
    expect(derived.kpis.enforcing).toBe(2);
    expect(derived.kpis.drift).toBe(1);
    expect(derived.kpis.auditOk).toBe(2);
    expect(derived.kpis.devices).toBe(1);
    expect(derived.rows.find((row) => row.peer.name === "gamma")?.driftMode).toBe(true);
  });

  it("summarizes partial fan-out failures", () => {
    const summary = summarizeFanout("Thresholds", [
      { name: "alpha", ok: true },
      { name: "beta", ok: false, status: 503, error: "gateway disabled" }
    ]);

    expect(summary.ok).toBe(false);
    expect(summary.title).toBe("Thresholds: partial");
    expect(summary.body).toContain("beta");
  });
});
