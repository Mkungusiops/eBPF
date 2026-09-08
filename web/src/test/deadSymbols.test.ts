import { readFileSync } from "node:fs";
import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";

import { useChokePosture } from "../features/choke/useChokePosture";
import type { StreamInfo } from "../features/choke/constants";

/**
 * DEAD SYMBOLS ARE A HONESTY PROBLEM, NOT A TIDINESS ONE.
 *
 * Both residues below survived a deliberate replacement, not an accident, and
 * each one made the code lie about what the console offers:
 *
 *  - 30318a3 pointed the "kprobes" surface at SensorHealthBody and the
 *    "policies" surface at DetectionsBody. It left KprobeBody exported from
 *    features/soc/panels.tsx with no caller — a whole self-polling panel that
 *    reads, to anyone opening the file, like a surface someone forgot to mount.
 *    (Its sibling PoliciesBody is the same residue; see the note above it in
 *    panels.tsx for why it cannot be removed from this file alone yet.)
 *  - The same commit removed the policy workbench, taking with it the only
 *    reader of useChokePosture's `engineOnlyHint` — a tooltip string the hook
 *    kept publishing for a button that no longer exists.
 *
 * These are pinned because a deleted symbol is easy to re-add "for symmetry".
 */

describe("features/soc/panels.tsx does not carry the replaced kprobe board", () => {
  const panels = readFileSync("src/features/soc/panels.tsx", "utf8");

  it("exports no KprobeBody — the kprobes surface is served by SensorHealthBody", () => {
    expect(panels).not.toContain("export function KprobeBody");
    // SocModals.tsx mounts SensorHealthBody for openSurface === "kprobes"; the
    // surface is reachable, only this body is gone.
    const modals = readFileSync("src/features/soc/SocModals.tsx", "utf8");
    expect(modals).toContain("<SensorHealthBody");
    expect(modals).toContain('openSurface === "kprobes"');
  });

  it("drops the panel's private machinery with it", () => {
    for (const symbol of ["KPROBE_HISTORY", "kprobeRateFromHistory", "kprobeDeltaSeries", "KprobeBand"]) {
      expect(panels, `${symbol} outlived its only reader`).not.toContain(symbol);
    }
    // The 15s /api/policy-stats self-poll was that panel's alone. Nothing in
    // this file should reach the network on its own except the fleet probe.
    expect(panels).not.toContain("fetchPolicyStats");
    expect(panels).toContain("probeFleetHosts");
  });
});

describe("useChokePosture publishes nothing for the deleted policy workbench", () => {
  it("returns no engineOnlyHint", () => {
    const posture = renderHook(() =>
      useChokePosture({
        chokeState: null,
        circuits: [],
        approvals: [],
        whoami: null,
        hostPings: [],
        streamInfo: { state: "live", retries: 0, lastMessageAt: 0, totalMessages: 0, messagesByMinute: [] } as StreamInfo,
        loadState: { kind: "ready" },
        now: Date.now(),
        windowMin: 60,
        currentWindowDecisions: [],
      }),
    ).result.current;

    expect(Object.keys(posture)).not.toContain("engineOnlyHint");
    // isFleetConsole itself is NOT dead: commandItems.ts still uses it to drop
    // the engine-local forensic-snapshot entry on a fleet console.
    expect(posture).toHaveProperty("isFleetConsole");
    expect(readFileSync("src/features/choke/commandItems.ts", "utf8")).toContain("Download forensic snapshot");
  });
});
