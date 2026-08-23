import { readFileSync } from "node:fs";
import { describe, expect, it } from "vitest";
import { normalizeAlert } from "../features/soc/api";

/**
 * Containing a process from an alert — the primary triage-to-contain path —
 * returned 400 on BOTH deployments.
 *
 * A live alert is {description, event_ids, exec_id, id, score, severity,
 * timestamp, title}: no pid, no binary. normalizeAlert falls back
 * `process = … || execId`, so the request carried {pids: [], binary: "<base64
 * exec_id>"} and no exec_id at all. The control plane does not decode `binary`;
 * the engine matches it against p.Exe/p.Comm where base64 matches nothing.
 */
const api = readFileSync("src/features/soc/api.ts", "utf8");
const drill = readFileSync("src/features/soc/DrillPanel.tsx", "utf8");

describe("containment from an alert names a target the backends accept", () => {
  it("sends exec_id, which is the only id an alert reliably carries", () => {
    expect(api).toContain("exec_id: alert.execId");
  });

  it("never sends the exec_id echoed back as a binary name", () => {
    // normalizeAlert's fallback makes alert.process === alert.execId whenever
    // the server sends no process name — which is always, on both backends.
    expect(api).toContain("alert.process === alert.execId ? undefined : alert.process");
  });

  it("still has the fallback that caused it, so this test stays meaningful", () => {
    const a = normalizeAlert({ exec_id: "YWJj", severity: "high", title: "t", description: "d" });
    expect(a.process, "the fallback is intentional; the request builder must compensate").toBe("YWJj");
  });
});

describe("the target guard is not defeated by that same fallback", () => {
  it("does not treat an echoed exec_id as a process name", () => {
    expect(drill).toContain("alert.process !== alert.execId");
    expect(drill).not.toContain("const canTarget = Boolean(alert.pid || alert.process);");
  });

  it("accepts exec_id as a valid target", () => {
    expect(drill).toContain("Boolean(alert.execId || alert.pid || hasRealProcessName)");
  });
});
