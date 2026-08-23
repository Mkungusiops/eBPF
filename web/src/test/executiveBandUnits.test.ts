import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { estateHalfScale, riskScoreAgainst } from "../features/soc/risk";

/**
 * Three numbers on the executive band were measured wrong on the live engine
 * (engine.adanianlabs.io, 2026-08-21) and are pinned here.
 *
 * These are source-level assertions because the defects were all WIRING — the
 * right value existed somewhere in the model and the wrong one was handed to
 * the band. A rendering test would pass with either.
 */
const socRoute = readFileSync("src/features/soc/SocRoute.tsx", "utf8");
const windowModel = readFileSync("src/features/soc/useSocWindowModel.ts", "utf8");

describe("the posture delta is in the dial's own units", () => {
  /**
   * The band rendered "100/100" with "-9252 vs prior 5m" directly beneath it:
   * a difference of weighted alerts per HOUR printed under a 0..100 gauge. The
   * dial had not moved; the number below it claimed a five-figure fall.
   */
  it("hands the band a difference of SCORES, not of rates", () => {
    expect(socRoute).toContain("riskDelta={Math.round(model.riskScore - model.previousRiskScore)}");
    expect(socRoute).not.toContain("model.riskPerHour - model.previousRiskPerHour");
  });

  it("scores the prior window on the same half-scale as the current one", () => {
    expect(windowModel).toContain("riskScoreAgainst(previousRiskPerHour, riskHalfScale)");
  });

  it("keeps a score delta inside the gauge's range whatever the rates are", () => {
    // The rates that produced -9252: 7548/hr now against ~16800/hr before, on a
    // quiet estate's half-scale. A score delta can never leave [-100, 100].
    const half = estateHalfScale(60);
    const delta = riskScoreAgainst(7548, half) - riskScoreAgainst(16800, half);
    expect(delta).toBeGreaterThanOrEqual(-100);
    expect(delta).toBeLessThanOrEqual(100);
  });
});

describe("the band's counts come from the same population as the tiles beside them", () => {
  /**
   * "Needs containment" counted the capped browser buffer while the CRITICAL
   * and HIGH tiles two inches away counted the server's window totals — 52
   * against 88, same screen, same five minutes.
   */
  it("bases open containment on the server counts", () => {
    expect(windowModel).toContain("critical: Math.max(0, counts.critical - ackedCritical)");
    expect(windowModel).toContain("high: Math.max(0, counts.high - ackedHigh)");
  });

  it("takes the alert total from the server when it is available", () => {
    expect(socRoute).toContain("totalAlerts={model.serverStats ? model.serverStats.total : model.rangeAlerts.length}");
  });
});

describe("the response count is not a fetch limit", () => {
  /**
   * "Response actions" counted a 200-row page filtered to the window. Those 200
   * rows spanned seven minutes on the live engine, so every window at least
   * that long reported exactly 200 — MAX_BUFFERED_DECISIONS rendered as a
   * measurement.
   */
  it("prefers the server-side window count", () => {
    expect(socRoute).toContain("model.decisionStats ? model.decisionStats.total : model.rangeDecisions.length");
  });

  it("marks the fallback as a floor rather than printing it as a total", () => {
    expect(socRoute).toContain("containmentActionsAreFloor={!model.decisionStats");
    expect(socRoute).toContain("model.rangeDecisions.length >= MAX_BUFFERED_DECISIONS");
    const band = readFileSync("src/features/soc/ExecutiveBand.tsx", "utf8");
    expect(band).toContain("containmentActionsAreFloor ? `≥${containmentActions}` : containmentActions");
  });
});
