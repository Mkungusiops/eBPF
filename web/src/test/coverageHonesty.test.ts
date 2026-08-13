import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { buildMitreCoverageModel } from "../features/soc/panels";
import type { SocAlert, SocPolicy } from "../features/soc/types";

/**
 * "0% ATT&CK coverage" must never be printed for an estate whose coverage
 * cannot be measured.
 *
 * Coverage is derived from policies carrying a technique tag. A fleet can run
 * policies this build has never heard of — the control plane maps by name
 * lookup and returns empty strings rather than guessing a technique — and then
 * nothing maps, `covered` is empty, and the percentage computes to 0.
 *
 * Zero is a definitive claim that the estate detects nothing. On a report handed
 * to a customer that is the difference between "we cannot tell you" and "you are
 * completely exposed" — and it is reachable on day one of a new deployment with
 * custom policy names.
 */
const policy = (name: string, mitre?: string): SocPolicy =>
  ({ name, mitre, description: "", tactic: "" }) as unknown as SocPolicy;

const noAlerts: SocAlert[] = [];

describe("coverage is only reported when it can be computed", () => {
  it("policies with no ATT&CK mapping make coverage unmeasurable", () => {
    const model = buildMitreCoverageModel([], noAlerts, [policy("custom-rule-a"), policy("custom-rule-b")]);
    expect(model.mappingAvailable, "unmapped policies must not read as measurable").toBe(false);
    // The raw number is still 0 — what must not happen is PRINTING it.
    expect(model.coveragePct).toBe(0);
  });

  it("a mapped policy makes coverage measurable", () => {
    const model = buildMitreCoverageModel([], noAlerts, [policy("sensitive-file-access", "T1003 OS Credential Dumping")]);
    expect(model.mappingAvailable).toBe(true);
  });

  it("an estate with no policies at all is not an unmapped estate", () => {
    // Nothing configured yet is a different statement from "configured, but we
    // cannot map any of it". Zero policies leaves coverage measurable-at-zero.
    expect(buildMitreCoverageModel([], noAlerts, []).mappingAvailable).toBe(true);
  });
});

describe("every coverage render consults measurability", () => {
  const soc = readFileSync("src/features/soc/SocRoute.tsx", "utf8")
    .split("\n")
    .filter((line) => !/^\s*(\/\/|\*|\/\*)/.test(line))
    .join("\n");
  const panels = readFileSync("src/features/soc/panels.tsx", "utf8");

  it("no export prints a bare coverage percentage", () => {
    expect(soc, "an export still interpolates coveragePct directly").not.toMatch(
      /\$\{model\.summary\.coveragePct\}%/,
    );
    expect(soc).toMatch(/function coverageLabel/);
  });

  it("the MITRE panel shows n/a rather than 0% when nothing is mapped", () => {
    expect(panels).toMatch(/mappingAvailable \? `\$\{model\.coveragePct\}%` : "n\/a"/);
    expect(panels).toMatch(/no ATT&CK mapping published/);
  });
});
