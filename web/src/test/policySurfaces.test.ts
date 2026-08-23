import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { normalizePolicy } from "../features/soc/api";

/**
 * Three defects on the policy surfaces, all of the same family: a console
 * asserting more than its data supports.
 */
const panels = readFileSync("src/features/soc/panels.tsx", "utf8");

describe("the policy card does not claim a policy is loaded without evidence", () => {
  it("no longer falls back to the literal string 'loaded'", () => {
    // handlePolicyStats on the control plane returns {name, posts} and nothing
    // else, so stat.status is ALWAYS undefined there. The old fallback made
    // every policy on every fleet deployment claim to be loaded — including
    // one no agent has.
    expect(panels).not.toContain('stat?.status || "loaded"');
  });

  it("prefers real kernel evidence and says unknown when there is none", () => {
    expect(panels).toContain("policy.loadedAgents ? `loaded on ${policy.loadedAgents}` : \"unknown\"");
  });

  it("carries loaded_agents and kernel_mode off the wire", () => {
    const p = normalizePolicy({ name: "x", loaded_agents: 3, kernel_mode: "monitor" });
    expect(p.loadedAgents).toBe(3);
    expect(p.kernelMode).toBe("monitor");
    // Absent must stay absent, never default to a number that reads as evidence.
    expect(normalizePolicy({ name: "x" }).loadedAgents).toBeUndefined();
  });
});

describe("the impossible alerts-per-policy column is gone", () => {
  it("does not render an alerts count on the policy card", () => {
    // An alert has no policy field: a live row is {description, event_ids,
    // exec_id, id, score, severity, timestamp, title}. Alerts are built from a
    // cumulative chain score, not one policy (see internal/mitre/mitre.go), so
    // the count was 0 for every policy forever — including one with 2,142
    // kernel posts, which reads as "this detection never fires".
    expect(panels).not.toContain("alerts <b");
    expect(panels).not.toContain("alerts: alertCount");
  });
});

describe("the Policy Workbench is removed, not relabelled", () => {
  it("leaves no workbench surface behind", () => {
    for (const f of [
      "src/features/choke/CommandView.tsx",
      "src/features/choke/ChokeRoute.tsx",
      "src/features/choke/api.ts"
    ]) {
      const src = readFileSync(f, "utf8");
      expect(src, `${f} still references the workbench`).not.toMatch(/usePolicyWorkbench|previewPolicy\(|policyYaml/);
    }
  });

  it("keeps the fleet-wide knob that actually reaches hosts", () => {
    // Thresholds dispatch over the signed, acknowledged command channel. That
    // is the response control an operator really has; the DSL was not one.
    expect(readFileSync("src/features/choke/CommandView.tsx", "utf8")).toContain("ThresholdPanel");
  });
});

/**
 * SHIPPED AND WRONG, caught in a screenshot: the Detections panel announced
 * "4 expected detections not loaded on any host" on a host running all four.
 *
 * The single-tenant engine's /api/policies did not send loaded_agents at all,
 * so every policy normalised to 0 and the panel read absence-of-data as
 * absence-of-coverage — then styled it as an alarm. A console that invents a
 * coverage gap is worse than the count it replaced.
 */
const detections = readFileSync("src/features/soc/DetectionsBody.tsx", "utf8");

describe("Detections separates unknown from not-loaded", () => {
  it("only alarms when the server actually said a policy is absent", () => {
    expect(detections).toContain("p.expected && p.kernelStateKnown && (p.loadedAgents ?? 0) === 0");
  });

  it("renders a third state rather than defaulting to not-loaded", () => {
    expect(detections).toContain('"load state unknown"');
    expect(detections).toContain("!p.kernelStateKnown");
  });

  it("distinguishes absent from zero at the normaliser", () => {
    // Absent field => could not ask. Present-and-zero => asked, answer none.
    expect(normalizePolicy({ name: "x" }).kernelStateKnown).toBe(false);
    expect(normalizePolicy({ name: "x", loaded_agents: 0 }).kernelStateKnown).toBe(true);
    expect(normalizePolicy({ name: "x", loaded_agents: 2 }).loadedAgents).toBe(2);
  });
});

describe("a removed policy is not a coverage gap", () => {
  it("only expected policies can be missing", () => {
    // The control plane's list unions kernel state with names merely seen in
    // recent telemetry, so a policy that fired once and was then deliberately
    // removed lingers at zero. That is history, not a hole.
    expect(normalizePolicy({ name: "console-push-probe", loaded_agents: 0 }).expected).toBe(false);
    expect(normalizePolicy({ name: "sensitive-file-access", loaded_agents: 1, expected: true }).expected).toBe(true);
  });
});

describe("the panel explains itself to someone who did not build it", () => {
  it("says what a detection is and what each state means", () => {
    for (const phrase of ["loaded into each host's kernel", "NOT LOADED", "load state unknown", "monitor records"]) {
      expect(detections, `missing operator guidance: ${phrase}`).toContain(phrase);
    }
  });
});
