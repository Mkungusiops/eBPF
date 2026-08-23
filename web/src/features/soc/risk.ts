// The posture dial's maths.
//
// Kept apart from the surfaces that draw it because the curve — not the
// drawing — is what was wrong in production, and it is the part with tests.

/**
 * Fallback half-scale: the weighted alerts/hour at which posture reads 50 when
 * this estate's own typical rate is not yet known.
 *
 * Weighted means critical*8 + high*3 + medium, so 200/hr is roughly 25 criticals
 * an hour sustained — a genuinely bad day, not a busy one.
 *
 * A FALLBACK now, not the rule. See estateHalfScale.
 */
export const RISK_HALF_SCALE_PER_HOUR = 200;

/**
 * The floor under an adaptive half-scale.
 *
 * Without it, a genuinely quiet estate has a typical rate near zero, so the
 * half-scale collapses and a single medium alert reads as catastrophe. 20
 * weighted/hr is roughly two or three criticals an hour — meaningfully above
 * nothing, and far below the fixed 200 that made every quiet estate read 0.
 */
export const RISK_MIN_HALF_SCALE = 20;

/**
 * How many times its own typical rate an estate must reach to read 50.
 *
 * Three, not one. At a multiplier of one the dial sits at 50 whenever the
 * estate is behaving exactly normally, which is alarming and useless. At three,
 * normal reads about 25 and there is room above it for "busier than usual" to
 * be visible before anything is actually wrong.
 */
export const RISK_BASELINE_MULTIPLE = 3;

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
  return riskScoreAgainst(perHour, RISK_HALF_SCALE_PER_HOUR);
}

/**
 * The same curve, scored against an explicit half-scale.
 *
 * A SEPARATE FUNCTION rather than an optional second parameter on
 * riskScoreFromRate, and that is not a style preference — the optional
 * parameter shipped for about ten minutes and broke `views.map(riskScoreFromRate)`,
 * because Array.map passes (element, INDEX, array) and the index silently
 * became the half-scale. Three of four windows were then scored against a
 * half-scale of 1, 2 and 3.
 *
 * An existing test caught it. The next one might not, so the shape that made it
 * possible is gone: a single-argument function cannot be handed an index it
 * will mistake for configuration.
 */
export function riskScoreAgainst(perHour: number, halfScale: number): number {
  if (!Number.isFinite(perHour) || perHour <= 0) return 0;
  const k = Number.isFinite(halfScale) && halfScale > 0 ? halfScale : RISK_HALF_SCALE_PER_HOUR;
  return Math.round((100 * perHour) / (perHour + k));
}

/**
 * The estate's own typical weighted alert rate, per hour.
 *
 * MEDIAN, not mean. An estate's alert history is a quiet floor with occasional
 * spikes, and the mean is dragged upwards by exactly the incidents the dial is
 * supposed to make visible — an estate that had one bad night last week would
 * quietly raise its own "normal" and stop reporting the next one.
 *
 * Returns null when there is not enough history to say. Null is not zero: it
 * means "unknown", and the caller falls back to the fixed scale and tells the
 * operator it is doing so.
 */
export function estateTypicalRate(hourlyWeightedRates: number[]): number | null {
  const usable = hourlyWeightedRates.filter((r) => Number.isFinite(r) && r >= 0);
  // Fewer than a day of buckets cannot describe a daily rhythm, and a dial
  // rescaled from four hours of a weekend would be confidently wrong.
  if (usable.length < 24) return null;
  const sorted = [...usable].sort((a, b) => a - b);
  const mid = Math.floor(sorted.length / 2);
  return sorted.length % 2 === 0 ? (sorted[mid - 1] + sorted[mid]) / 2 : sorted[mid];
}

/**
 * The half-scale to use for this estate, given its own typical rate.
 *
 * This is the fix for a dial that pinned. A fixed 200/hr means a genuinely busy
 * estate sits at the top of the scale permanently and the gauge distinguishes
 * nothing — the same defect the clamp had, one layer out: the curve had
 * headroom, but the estate was already past the part of it where movement is
 * visible.
 *
 * Scaling to the estate's own normal restores dynamic range everywhere: a quiet
 * estate that gets busy moves, and a busy estate that gets worse also moves.
 *
 * THE TRADE, STATED PLAINLY: an estate with a chronically terrible baseline now
 * reads "normal" while being chronically terrible. That is the classic failure
 * of every baseline-relative metric, and it is not solved here — it is
 * DISCLOSED. The caller must show the absolute rate and the baseline it is
 * being measured against beside the dial, so "52/100" is never the only number
 * on screen. See ExecutiveBand.
 */
export function estateHalfScale(typicalRate: number | null): number {
  if (typicalRate === null || !Number.isFinite(typicalRate)) return RISK_HALF_SCALE_PER_HOUR;
  return Math.max(RISK_MIN_HALF_SCALE, typicalRate * RISK_BASELINE_MULTIPLE);
}

/** One timeline bucket reduced to the weighted rate it represents. */
export interface WeightedBucket {
  critical: number;
  high: number;
  medium: number;
}

/**
 * Convert timeline buckets into per-hour weighted rates.
 *
 * `bucketMinutes` matters: buckets are a slice of the window, not an hour, so
 * counting them directly would report a 7-day estate's rate as if each bucket
 * were sixty minutes. That is the same window-dependence the rate change fixed
 * for the dial itself, and it would reappear here unnoticed.
 */
export function weightedHourlyRates(buckets: WeightedBucket[], bucketMinutes: number): number[] {
  if (!Number.isFinite(bucketMinutes) || bucketMinutes <= 0) return [];
  return buckets.map((b) => ((b.critical * 8 + b.high * 3 + b.medium) * 60) / bucketMinutes);
}
