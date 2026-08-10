import { describe, expect, it } from "vitest";
import { RISK_HALF_SCALE_PER_HOUR, riskScoreFromRate } from "../features/soc/SocRoute";

/**
 * Posture is a RATE, not a cumulative count.
 *
 * The old score was `critical*8 + high*3 + medium` clamped to 100. Two defects,
 * both observed live:
 *
 *  1. It measured the WINDOW SELECTOR. The single-tenant engine, at one instant,
 *     read 0 / 3 / 31 / 100 as the range widened 5m → 30m → 60m → 24h. Nothing
 *     about the host changed.
 *  2. It saturated at THIRTEEN criticals (13*8 = 104), so the control plane sat
 *     at "Critical 100/100" on every window and the dial distinguished nothing.
 */

const weighted = (crit: number, high: number, med: number) => crit * 8 + high * 3 + med;
const rate = (crit: number, high: number, med: number, windowMin: number) =>
  (weighted(crit, high, med) * 60) / windowMin;

describe("posture score", () => {
  it("gives the same answer for a steady estate at every window", () => {
    // The live control-plane figures: the raw counts differ ~340x between the
    // 5m and 24h views, but they describe one estate at one rate.
    const views = [
      rate(18, 14, 16, 5),
      rate(107, 90, 123, 30),
      rate(273, 197, 271, 60),
      rate(5530, 4685, 6446, 1440)
    ].map(riskScoreFromRate);

    const spread = Math.max(...views) - Math.min(...views);
    expect(spread).toBeLessThanOrEqual(5); // was 0 spread only because all four were CLAMPED to 100
    // ...and it must not be the degenerate "everything is 100" agreement.
    expect(Math.max(...views)).toBeLessThan(100);
  });

  it("no longer saturates at thirteen criticals", () => {
    // The old clamp: 13*8 = 104 -> min(100,104) = 100, on any window.
    const thirteenCriticalsInAnHour = riskScoreFromRate(rate(13, 0, 0, 60));
    expect(thirteenCriticalsInAnHour).toBeLessThan(50);
    // And a tenfold worse estate must still be visibly worse.
    expect(riskScoreFromRate(rate(130, 0, 0, 60))).toBeGreaterThan(thirteenCriticalsInAnHour + 20);
  });

  it("always leaves headroom, so worse is always visible", () => {
    let previous = 0;
    for (const perHour of [10, 100, 1_000, 10_000, 100_000]) {
      const score = riskScoreFromRate(perHour);
      expect(score).toBeGreaterThan(previous); // strictly monotonic — never pegs
      expect(score).toBeLessThanOrEqual(100);
      previous = score;
    }
  });

  it("reads 50 at half-scale, 0 at silence", () => {
    expect(riskScoreFromRate(RISK_HALF_SCALE_PER_HOUR)).toBe(50);
    expect(riskScoreFromRate(0)).toBe(0);
    expect(riskScoreFromRate(-1)).toBe(0);
    expect(riskScoreFromRate(Number.NaN)).toBe(0);
  });

  it("a quiet host reads low on a long window", () => {
    // The engine's 30m view: one high alert. Under the old count-based score a
    // wider window would drag the same host toward 'critical' on volume alone.
    expect(riskScoreFromRate(rate(0, 1, 0, 30))).toBeLessThan(18); // 'low' band
  });
});
