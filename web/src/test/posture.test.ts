import { describe, expect, it } from "vitest";
import { computePosture } from "../features/common/ContainmentCommand";

/**
 * A broken audit chain is an incident. An audit chain that cannot be verified
 * on this deployment is a capability gap. Conflating them either invents a
 * breach or hides one.
 *
 * The fleet control plane does not hash-chain decisions centrally, so it
 * reports supported=false. Before this distinction existed it reported
 * ok=true — a green "intact · 0 rows" for a check that never ran.
 */
describe("computePosture — audit chain", () => {
  const base = { mode: "detect-only" as const, activeThreats: 0, contained: 100 };

  it("does not penalise a deployment that cannot verify centrally", () => {
    const verified = computePosture({ ...base, auditOk: true, auditSupported: true });
    const unverifiable = computePosture({ ...base, auditOk: false, auditSupported: false });
    expect(unverifiable).toBe(verified);
  });

  it("still penalises a chain that is genuinely BROKEN", () => {
    const intact = computePosture({ ...base, auditOk: true, auditSupported: true });
    const broken = computePosture({ ...base, auditOk: false, auditSupported: true });
    expect(broken).toBeLessThan(intact);
    expect(intact - broken).toBe(30);
  });

  it("treats an absent supported flag as verifiable (single-host engine)", () => {
    // The engine does chain centrally and sends no `supported` key at all.
    const broken = computePosture({ ...base, auditOk: false });
    const intact = computePosture({ ...base, auditOk: true });
    expect(intact - broken).toBe(30);
  });

  it("stays within 0..100", () => {
    const worst = computePosture({
      mode: "detect-only", activeThreats: 100, contained: 0,
      auditOk: false, auditSupported: true, killSwitched: true
    });
    expect(worst).toBeGreaterThanOrEqual(0);
    expect(worst).toBeLessThanOrEqual(100);
  });
});
