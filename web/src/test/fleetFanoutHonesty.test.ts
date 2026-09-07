/**
 * What a fleet write is allowed to CLAIM about its own reach.
 *
 * Two defects met here. The control plane answers these four routes with
 * `{ok, applied, total, detail}` and no `hosts` key, and the console read
 * `result.hosts ?? []` off it — so every multi-tenant fleet write, including one
 * that reached every agent in the tenant, was summarised from an empty list.
 * summarizeFanout then derived success from `failed === 0`, which an empty list
 * satisfies, so the operator was shown a green "applied" over "0/0 hosts
 * succeeded": a write that reached nobody and one that reached everybody looked
 * identical.
 *
 * The rule these pin is that only a stated, non-zero, fully-applied coverage may
 * be toned as success. Everything else — no coverage stated, zero coverage, or
 * partial — is a failure the operator must go and check.
 */
import { describe, expect, it } from "vitest";

import { readFanout, summarizeFanout } from "../features/fleet/fleetLogic";

function summarize(label: string, envelope: unknown) {
  return summarizeFanout(label, readFanout(envelope));
}

describe("fleet fan-out honesty", () => {
  it("does not report a fan-out that reached no hosts as applied", () => {
    // The engine's shape, genuinely empty: the write was issued and no peer
    // took it. The old rule (failed === 0) called this a success.
    const summary = summarize("Preset default", { hosts: [] });

    expect(summary.ok, "a write that touched no host was toned as a success").toBe(false);
    expect(summary.title).toBe("Preset default: no hosts");
    expect(summary.body).toMatch(/reached no hosts/i);
    expect(summary.body).not.toMatch(/applied/i);
  });

  it("reports the coverage a control-plane envelope stated, rather than 0/0", () => {
    // The control plane's documented 200 for /api/fleet/preset — no `hosts` key
    // in it at all. Both agents took the write; the console used to print 0/0.
    const summary = summarize("Preset default", {
      ok: true,
      preset: "default",
      applied: 2,
      total: 2,
      detail: ""
    });

    expect(summary.ok).toBe(true);
    expect(summary.title).toBe("Preset default applied");
    expect(summary.body).toContain("2/2");
    expect(summary.body).not.toContain("0/0");
  });

  it("reads a control-plane envelope that carries the contract's hosts array", () => {
    // The shape the control plane sends now: per-agent acks alongside the
    // counts. `status` is the ack WORD, not an HTTP code, and the failing
    // agent's detail is what tells an operator to retry or investigate.
    const summary = summarize("Kill-switch ON", {
      ok: true,
      applied: 1,
      total: 2,
      detail: "1/2 agents applied",
      hosts: [
        { name: "agent-a", ok: true, status: "APPLIED" },
        { name: "agent-b", ok: false, status: "timeout", error: "no ack before deadline" }
      ]
    });

    expect(summary.ok).toBe(false);
    expect(summary.title).toBe("Kill-switch ON: partial");
    expect(summary.body).toContain("1/2");
    expect(summary.body).toContain("agent-b");
    expect(summary.body).toContain("no ack before deadline");
    expect(summary.body, "the agent that DID apply must not be listed as a failure").not.toContain("agent-a");
  });

  it("counts partial coverage the server only stated numerically", () => {
    // applied < total with no per-host list: the console can say how many, but
    // must not pretend to know which, and must not call it applied.
    const summary = summarize("Thaw", { ok: true, applied: 1, total: 3, detail: "" });

    expect(summary.ok).toBe(false);
    expect(summary.title).toBe("Thaw: partial");
    expect(summary.body).toContain("1/3");
    expect(summary.body).toMatch(/did not name the hosts that failed/i);
  });

  it("treats a response that states no coverage at all as unconfirmed, not applied", () => {
    // "The server said nothing about reach" and "the server said it reached
    // nobody" are different facts, and neither is a success.
    const summary = summarize("Thresholds", { ok: true });

    expect(summary.ok).toBe(false);
    expect(summary.title).toBe("Thresholds: coverage unknown");
    expect(summary.body).toMatch(/did not report which hosts/i);
  });

  it("keeps the engine's full-coverage fan-out a success", () => {
    const summary = summarize("Thresholds", {
      hosts: [
        { name: "alpha-edge", ok: true, status: 200 },
        { name: "bravo-edge", ok: true, status: 200 }
      ]
    });

    expect(summary.ok).toBe(true);
    expect(summary.title).toBe("Thresholds applied");
    expect(summary.body).toContain("2/2");
  });

  it("does not credit a host entry it could not read as a success", () => {
    // A row with no `ok` field is not a host that took the write. Defaulting
    // the other way would invent coverage out of a malformed response.
    const report = readFanout({ hosts: [{ name: "alpha" }, { name: "bravo", ok: true }] });

    expect(report.applied).toBe(1);
    expect(report.total).toBe(2);
    expect(summarizeFanout("Preset", report).ok).toBe(false);
  });

  it("survives a body that is not an envelope at all", () => {
    for (const body of [null, undefined, "accepted", 7, []]) {
      const summary = summarize("Preset", body);
      expect(summary.ok, `a ${JSON.stringify(body)} body was reported as a success`).toBe(false);
    }
  });
});
