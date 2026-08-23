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

// THE FILES THE ORIGINAL TEST DID NOT READ — which is exactly where the drift
// happened. On 2026-08-22 the Choke Gateway footer read "chain broken @ ?",
// the System Health tile read "broken" and the assurance banner read
// "CHAIN BROKEN", all on a control plane that simply does not maintain a
// central chain. Two surfaces had the three-state fix; these three did not,
// and nothing failed.
const commandView = readFileSync("src/features/choke/CommandView.tsx", "utf8");
const sections = readFileSync("src/features/choke/sections.tsx", "utf8");
const assurance = readFileSync("src/features/choke/AssuranceView.tsx", "utf8");

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


describe("no surface collapses the chain verdict to a boolean", () => {
  // The bare two-state test. Any surface deciding "broken" straight off
  // `audit.ok === false` will fire on every multi-tenant deployment, because
  // that is also what an unverifiable chain answers.
  const surfaces: Array<[string, string]> = [
    ["CommandView.tsx", commandView],
    ["sections.tsx", sections],
    ["AssuranceView.tsx", assurance],
    ["ChokeRoute.tsx", choke]
  ];

  it("never tests audit.ok === false without consulting supported", () => {
    for (const [name, src] of surfaces) {
      const flat = src.replace(/\s+/g, " ");
      for (const m of flat.matchAll(/audit\?\.ok === false|audit\.ok === false/g)) {
        const lookback = flat.slice(Math.max(0, m.index! - 240), m.index!);
        expect(
          // Either form of consulting `supported` is correct: `=== false` to
          // branch to the unverifiable copy, or `!== false &&` to guard a
          // broken-only readout. What must never appear is a bare ok check.
          /[Ss]upported (===|!==) false|auditVerdict/.test(lookback),
          `${name}: a raw ok===false verdict at ${m.index} — this renders "broken" for an unverifiable chain: ...${lookback.slice(-100)}`
        ).toBe(true);
      }
    }
  });

  it("routes the choke surfaces through the shared verdict helper", () => {
    // A shared helper is what stops the next surface drifting: the fix was
    // applied to two files and missed on three, twice.
    for (const [name, src] of [["CommandView.tsx", commandView], ["sections.tsx", sections]] as Array<[string, string]>) {
      expect(src, `${name} must use auditVerdict`).toContain("auditVerdict");
    }
    expect(assurance, "AssuranceView must branch on auditSupported").toContain("auditSupported === false");
  });

  it("the downloadable report does not assert intact for an unchecked chain", () => {
    expect(choke).toContain('status: commandMetrics.auditSupported === false ? "not-verified-here"');
    expect(choke).toContain("intact: commandMetrics.auditSupported === false ? null");
  });
});
