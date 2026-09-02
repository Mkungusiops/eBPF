import { describe, expect, it } from "vitest";
import { computePosture } from "../features/common/ContainmentCommand";
import {
  RISK_HALF_SCALE_PER_HOUR,
  RISK_MIN_HALF_SCALE,
  estateHalfScale,
  estateTypicalRate,
  riskScoreAgainst,
  riskScoreFromRate,
  weightedHourlyRates
} from "../features/soc/risk";

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
    const intact = computePosture({ ...base, auditOk: true, auditSupported: true })!;
    const broken = computePosture({ ...base, auditOk: false, auditSupported: true })!;
    expect(broken).toBeLessThan(intact);
    expect(intact - broken).toBe(30);
  });

  it("treats an absent supported flag as verifiable (single-host engine)", () => {
    // The engine does chain centrally and sends no `supported` key at all.
    const broken = computePosture({ ...base, auditOk: false })!;
    const intact = computePosture({ ...base, auditOk: true })!;
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

/**
 * Baseline-relative scaling: the fix for a dial with no dynamic range.
 *
 * A fixed 200/hr half-scale meant a genuinely busy estate sat near the top of
 * the curve permanently and the gauge distinguished nothing — the clamp defect
 * one layer out. The curve had headroom; the estate was already past the part
 * of it where movement is visible.
 */
describe("estate-relative posture", () => {
  it("gives a busy estate room to get worse", () => {
    // An estate whose normal is 400 weighted/hr — twice the old fixed scale.
    const busy = new Array(48).fill(400);
    const half = estateHalfScale(estateTypicalRate(busy));

    const normal = riskScoreAgainst(400, half);
    const doubled = riskScoreAgainst(800, half);
    const quadrupled = riskScoreAgainst(1600, half);

    // Under the old fixed scale these were 67, 80 and 89 — compressed into the
    // top third, which is what "pinned" meant.
    expect(normal).toBeLessThan(40);
    expect(doubled - normal).toBeGreaterThan(10);
    expect(quadrupled - doubled).toBeGreaterThan(10);
  });

  it("does not let a quiet estate read catastrophe on one alert", () => {
    const quiet = new Array(48).fill(0);
    const half = estateHalfScale(estateTypicalRate(quiet));
    // The floor is what stops a near-zero baseline collapsing the scale.
    expect(half).toBe(RISK_MIN_HALF_SCALE);
    expect(riskScoreAgainst(8, half)).toBeLessThan(45);
  });

  it("uses the median so one bad night does not raise the estate's own normal", () => {
    // 47 quiet hours and one severe spike.
    const history = [...new Array(47).fill(10), 5000];
    expect(estateTypicalRate(history)).toBe(10);
  });

  it("reports unknown rather than zero when history is too thin", () => {
    // Fewer than a day of buckets cannot describe a daily rhythm, and a dial
    // rescaled from four hours of a weekend would be confidently wrong.
    expect(estateTypicalRate([1, 2, 3])).toBeNull();
    // Unknown must fall back to the fixed scale, never to a collapsed one.
    expect(estateHalfScale(null)).toBe(RISK_HALF_SCALE_PER_HOUR);
  });

  it("converts buckets to an hourly rate rather than counting them raw", () => {
    // Four 15-minute buckets each holding one critical is 8 weighted per
    // quarter-hour, which is 32/hr — not 8.
    const rates = weightedHourlyRates([{ critical: 1, high: 0, medium: 0 }], 15);
    expect(rates[0]).toBe(32);
  });

  it("keeps the curve asymptotic at any scale", () => {
    for (const half of [RISK_MIN_HALF_SCALE, 200, 5000]) {
      expect(riskScoreAgainst(1e9, half)).toBeLessThanOrEqual(100);
      expect(riskScoreAgainst(0, half)).toBe(0);
    }
  });
});

/**
 * Regression: riskScoreFromRate must stay single-argument.
 *
 * It briefly took an optional half-scale, which broke every point-free
 * `.map(riskScoreFromRate)` — Array.map passes (element, index, array), so the
 * index became the half-scale and three of four windows were scored against 1,
 * 2 and 3.
 */
describe("riskScoreFromRate arity", () => {
  it("ignores the extra arguments Array.map supplies", () => {
    const rates = [2424, 2498, 3046, 2697];
    const viaMap = rates.map(riskScoreFromRate);
    const viaExplicit = rates.map((r) => riskScoreFromRate(r));
    expect(viaMap).toEqual(viaExplicit);
  });
});

/**
 * The posture LABEL must never contradict the severity tiles beside it.
 *
 * Observed live: the dial read "Critical 86/100" while the CRITICAL and HIGH
 * tiles on the same row both read 0. The number was right — 288 weighted
 * alerts/hr against a 7-day median of 10 — but "Critical" is read as "critical
 * alerts are happening", and two readings of one estate contradicting each
 * other on one screen is how a console loses an operator.
 */
function label(score: number, counts: { critical: number; high: number }): string {
  const ceiling = counts.critical > 0 ? 3 : counts.high > 0 ? 2 : 1;
  const raw = score >= 80 ? 3 : score >= 45 ? 2 : score >= 18 ? 1 : 0;
  const band = Math.min(raw, ceiling);
  return band >= 3 ? "critical" : band >= 2 ? "high" : band >= 1 ? "elevated" : "low";
}

describe("posture label vs the severity tiles", () => {
  it("does not say critical when nothing critical is open", () => {
    // The exact live reading: score 86, zero critical, zero high.
    expect(label(86, { critical: 0, high: 0 })).toBe("elevated");
  });

  it("says critical when something critical actually is", () => {
    expect(label(86, { critical: 3, high: 1 })).toBe("critical");
  });

  it("caps at high when only high-severity alerts are open", () => {
    expect(label(95, { critical: 0, high: 4 })).toBe("high");
  });

  it("never inflates a quiet estate", () => {
    expect(label(5, { critical: 9, high: 9 })).toBe("low");
  });
});

// A subject that cannot count threats has no posture, and must not be given a
// flattering one. The device plane is exactly that case: nothing scores a
// device, so activeThreats was hardcoded to 0 — and with zero uncontained the
// coverage term below evaluates to a perfect 1, pinning the dial at maximum
// regardless of what the estate was doing.
describe("posture is null when it cannot be computed", () => {
  const base = { mode: "detect-only" as const, activeThreats: 0, contained: 100, auditOk: true };

  it("still scores the measurable terms when the threat count is unknown", () => {
    // Returning null threw away what the subject DOES know — armed or not,
    // plane attached or not, kill-switch engaged or not — and rendered a blank
    // dial that reads as broken. The coverage term drops out; the rest stays.
    const p = computePosture({ ...base, activeThreats: null });
    expect(typeof p).toBe("number");
    expect(p).toBeGreaterThan(0);
  });

  it("does not let an unknown threat count inflate the score above a measured zero", () => {
    // The original bug in one line: unknown must not be BETTER than measured.
    const unknown = computePosture({ ...base, activeThreats: null })!;
    const measuredZero = computePosture({ ...base, activeThreats: 0 })!;
    expect(unknown).toBeLessThanOrEqual(measuredZero);
  });

  it("is labelled as excluding coverage rather than presented as complete", () => {
    // The honesty now lives in the LABEL (posture*) and the tooltip, not in a
    // null. A number with a stated omission beats both a fabricated 100 and an
    // empty ring — this asserts the number exists so the label has something
    // to qualify.
    expect(computePosture({ ...base, activeThreats: null })).not.toBeNull();
  });

  it("a measured zero still scores, because it was measured", () => {
    expect(computePosture({ ...base, activeThreats: 0 })).toBeGreaterThan(0);
  });
});
