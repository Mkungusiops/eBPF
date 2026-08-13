import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { decisionOutcome } from "../features/soc/api";

/**
 * An exported report must not invent an outcome.
 *
 * Measured on the live engine: a decision row carries `outcome` (free text) and
 * NO boolean `ok`. The export computed `ok: d.ok !== false`, so `undefined`
 * became `true` — every decision in the JSON report and the CSV was stamped
 * successful, including rows whose outcome literally read
 * "skipped: system-critical chain (auto-only; manual override allowed)".
 *
 * That is a false statement about whether containment happened, in the
 * artefact most likely to be handed to an auditor.
 */
describe("decisionOutcome reports what the engine said", () => {
  it("carries the engine's own words through", () => {
    expect(decisionOutcome({ outcome: "ok" })).toBe("ok");
    expect(decisionOutcome({ outcome: "skipped: system-critical chain (auto-only; manual override allowed)" }))
      .toBe("skipped: system-critical chain (auto-only; manual override allowed)");
  });

  it("never turns an absent outcome into success", () => {
    expect(decisionOutcome({})).toBe("unknown");
    expect(decisionOutcome({ outcome: "" })).toBe("unknown");
    expect(decisionOutcome({ outcome: "   " })).toBe("unknown");
  });

  it("honours an explicit boolean when a backend does send one", () => {
    expect(decisionOutcome({ ok: true })).toBe("ok");
    expect(decisionOutcome({ ok: false })).toBe("failed");
    // Explicit beats derived.
    expect(decisionOutcome({ ok: false, outcome: "ok" })).toBe("failed");
  });

  it("a skipped decision never reads as ok", () => {
    for (const outcome of ["skipped: system-critical chain", "skipped: dry-run", "error: cgroup write failed"]) {
      expect(decisionOutcome({ outcome })).not.toBe("ok");
    }
  });
});

describe("the export carries outcome, not a manufactured boolean", () => {
  // Comments quote the old code on purpose, to explain why it was wrong. Match
  // against CODE only, or the explanation trips the assertion.
  const soc = readFileSync("src/features/soc/SocRoute.tsx", "utf8")
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join("\n");

  it("the fabricated ok column is gone from both exports", () => {
    expect(soc, "the JSON report still synthesises ok").not.toMatch(/ok: d\.ok !== false/);
    expect(soc, "the CSV still has a manufactured ok column").not.toMatch(/"reason", "ok", "timestamp"/);
  });

  it("both exports emit the real outcome", () => {
    expect(soc).toMatch(/outcome: decisionOutcome\(d\)/);
    expect(soc).toMatch(/"reason", "outcome", "timestamp"/);
  });
});
