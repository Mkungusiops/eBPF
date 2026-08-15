// The posture dial's maths.
//
// Kept apart from the surfaces that draw it because the curve — not the
// drawing — is what was wrong in production, and it is the part with tests.

/**
 * Half-scale rate: the weighted alerts/hour at which posture reads 50.
 *
 * Weighted means critical*8 + high*3 + medium, so 200/hr is roughly 25 criticals
 * an hour sustained — a genuinely bad day, not a busy one.
 */
export const RISK_HALF_SCALE_PER_HOUR = 200;

/**
 * Map a weighted alert RATE onto the 0..100 dial.
 *
 * Soft knee (`r / (r + k)`) rather than a hard `min(100, …)` clamp. The clamp
 * was the reason the gauge read "Critical 100/100" on every window of every
 * busy tenant: once past the ceiling, a tenfold worsening looked identical to
 * scraping over the line. This curve is asymptotic, so it never quite reaches
 * 100 and there is always headroom for "worse" to be visible — which is the
 * whole job of a posture dial.
 */
export function riskScoreFromRate(perHour: number): number {
  if (!Number.isFinite(perHour) || perHour <= 0) return 0;
  return Math.round((100 * perHour) / (perHour + RISK_HALF_SCALE_PER_HOUR));
}
