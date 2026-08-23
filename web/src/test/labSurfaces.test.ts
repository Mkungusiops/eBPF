import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { normalizeVersion } from "../features/soc/api";

/**
 * The three demo surfaces are gated because two of them are actively
 * dangerous on a customer estate:
 *
 *  - Attack Sim executes a script AS ROOT on the host the engine is defending,
 *    behind a single shared admin credential (so it is unattributable), and on
 *    the control plane it writes FABRICATED alerts into the tenant's real
 *    telemetry table where alert-stats, MITRE coverage and every export count
 *    them as genuine findings.
 *  - Honeypots on the control plane reports decoy hits from Go constants that
 *    no host produced.
 *  - The Rule Simulator tunes a severity ladder no endpoint can persist.
 */
const sidebar = readFileSync("src/features/soc/Sidebar.tsx", "utf8");

describe("lab surfaces are hidden unless the server says this is a lab", () => {
  it("gates Attack Sim, Honeypots and Rule Simulator on labMode", () => {
    for (const label of ["Attack Sim", "Honeypots", "Rule Simulator"]) {
      const idx = sidebar.indexOf(`label="${label}"`);
      expect(idx, `${label} must still exist in the nav source`).toBeGreaterThan(-1);
      // The nav entry must sit inside a labMode conditional.
      const preceding = sidebar.slice(Math.max(0, idx - 400), idx);
      expect(preceding, `${label} must be gated on labMode`).toContain("labMode ?");
    }
  });

  it("leaves the surfaces an analyst always needs ungated", () => {
    for (const label of ["Watchlist", "Time Machine", "Policies", "Fleet", "Reports"]) {
      const idx = sidebar.indexOf(`label="${label}"`);
      expect(idx, `${label} must still be in the nav`).toBeGreaterThan(-1);
    }
  });
});

describe("labMode defaults to off", () => {
  it("treats a server that does not report the field as production", () => {
    // An older control plane or engine has no lab_mode key. Defaulting to true
    // would offer a nav entry whose endpoint answers 404 — or worse, offer the
    // attack runner on a customer box.
    expect(normalizeVersion({ sha: "abc" }).labMode).toBe(false);
    expect(normalizeVersion({}).labMode).toBe(false);
  });

  it("honours an explicit lab_mode", () => {
    expect(normalizeVersion({ sha: "abc", lab_mode: true }).labMode).toBe(true);
    expect(normalizeVersion({ sha: "abc", lab_mode: false }).labMode).toBe(false);
  });
});

describe("a gated endpoint is not an outage", () => {
  it("does not route a 404 on the lab endpoints into the error strip", () => {
    // Routing it there would light the notices strip and the executive band's
    // "telemetry feed down" path over two panels the operator is deliberately
    // not given — an invented outage.
    const api = readFileSync("src/features/soc/api.ts", "utf8");
    expect(api).toContain('OPTIONAL_ENDPOINTS = new Set(["attacks", "honeypots"])');
    expect(api).toContain("OPTIONAL_ENDPOINTS.has(key) && result.status === 404");
  });
});
