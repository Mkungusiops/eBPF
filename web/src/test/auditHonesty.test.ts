import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";

/**
 * The audit chain has THREE states, and every surface must render all three.
 *
 * The single-tenant engine hash-chains its decisions and answers
 * {ok: true, total: N}. The multi-tenant control plane does NOT chain centrally
 * — each agent chains its own — and answers {ok: false, supported: false}.
 *
 * Collapsing that to a boolean produces a false statement in one direction or
 * the other: "verified" for a check that never ran, or "BROKEN" for a
 * capability the deployment simply does not have. Both were live on
 * console.adanianlabs.io, one of them in a downloadable report rendered in
 * alarm-red, telling an enterprise its tamper-evidence had failed.
 */
const choke = readFileSync("src/features/choke/ChokeRoute.tsx", "utf8");
const command = readFileSync("src/features/common/ContainmentCommand.tsx", "utf8");

describe("the audit chain is never reported as a boolean", () => {
  it("no surface renders a verdict without first consulting supported", () => {
    // Asserting the ABSENCE of the two-state form is wrong: the correct
    // three-state ternary legitimately ends in `auditOk ? "Intact" : "Broken"`.
    // What matters is that a supported check comes FIRST in the same
    // expression. So for every verdict rendered, look back for that guard.
    const flat = choke.replace(/\s+/g, " ");
    const verdicts = [...flat.matchAll(/"Intact"|"BROKEN"|"broken" : "verified"/g)];
    expect(verdicts.length, "expected to find the audit verdict renders").toBeGreaterThanOrEqual(3);
    for (const v of verdicts) {
      const lookback = flat.slice(Math.max(0, v.index! - 200), v.index!);
      expect(
        lookback,
        `an audit verdict at offset ${v.index} renders without checking supported: ...${lookback.slice(-90)}`,
      ).toMatch(/[Ss]upported === false/);
    }
  });

  it("every audit readout has an unsupported branch", () => {
    // One per surface: the assurance pill, the exported report tile, and the
    // audit popover.
    const unsupported = [...choke.matchAll(/auditSupported === false|audit\?\.supported === false/g)];
    expect(unsupported.length, "expected all three audit surfaces to branch on supported").toBeGreaterThanOrEqual(3);
  });

  it("the shared header already did this and still does", () => {
    expect(command).toMatch(/auditSupported === false \? "not verified here"/);
  });

  it("an unsupported chain is not scored as a failure", () => {
    // computePosture must not dock points for a capability gap, or the fleet
    // console scores permanently below the identical single-host one.
    expect(command).toMatch(/auditSupported !== false && !m\.auditOk/);
  });
});
