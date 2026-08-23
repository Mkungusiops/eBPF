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
// NOTE: this asserts on SOURCE TEXT, which makes it brittle to refactoring —
// it broke when the code moved out of SocRoute.tsx into focused modules. The
// invariant it guards is real, so it now reads every file the SOC route is
// composed from rather than one path. A behavioural test would be better still.
  const soc = ["SocRoute", "CorrelationGraph", "exportStudio", "panels"]
    .map((f) => readFileSync(`src/features/soc/${f}.tsx`, "utf8"))
    .join("\n")
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

// The PDF is the artefact most likely to reach an auditor, and it dropped the
// one column that says whether the action actually took effect. A decision
// whose outcome is "skipped: system-critical chain" rendered as
// "sever / contained" — an assertion of containment that never happened.
//
// This file previously asserted only on the CSV header, which is exactly how
// the two exporters drifted apart, so the check is now on both.
describe("the exported PDF carries the outcome, not just the intent", () => {
  const src = readFileSync("src/features/soc/exportStudio.tsx", "utf8");

  it("names Outcome in the decisions table head", () => {
    expect(src).toMatch(/head:\s*\[\[\s*"Action",\s*"State",\s*"Target",\s*"Reason",\s*"Outcome",\s*"Time"\s*\]\]/);
  });

  it("emits the outcome field in the row body", () => {
    expect(src).toMatch(/d\.reason,\s*d\.outcome,\s*d\.timestamp/);
  });

  it("carries no stale ok:true placeholder", () => {
    // A fossil of a removed field; it made the empty-state row claim success.
    expect(src).not.toMatch(/no decisions logged[^)]*ok:\s*true/);
  });
});
