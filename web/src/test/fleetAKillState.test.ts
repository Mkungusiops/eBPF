import { describe, expect, it } from "vitest";

import { deriveFleet, detectDrift, killStateOf } from "../features/fleet/fleetLogic";
import type { ChokeState, FleetPeer, HostResult } from "../features/fleet/types";

/**
 * THE KILL-SWITCH HAS THREE STATES AND THE CONSOLE USED TO PAINT TWO.
 *
 * `/api/fleet/state` on the multi-tenant control plane sends
 * `"kill_switched": null` for every host: no heartbeat field carries the
 * agent's switch, so the server is saying it could not read one. The console
 * read it as `data.kill_switched ? "on" : "off"`, which spent that null twice:
 *
 *   1. as a green "live" pill on a host whose enforcement state nobody knows,
 *      and
 *   2. as an "off" VOTE in the drift majority — so a fleet that reported
 *      nothing at all elected an "off" majority, agreed with itself, and
 *      certified "DRIFT 0" over a field the server had said it could not read.
 *
 * The second is the one that matters: a drift count is the console's claim that
 * it compared the fleet, and part of that zero was an artefact.
 *
 * The fix is EXCLUSION, not a different colour: an unknown is not evidence for
 * what the majority is, it is counted on its own (`killUnknown`), and it drifts
 * on nothing.
 */

const THRESHOLDS = { throttle_at: 10, tarpit_at: 30, quarantine_at: 60, sever_at: 100 };

const PEERS: FleetPeer[] = [
  { name: "engaged", url: "http://engaged" },
  { name: "live", url: "http://live" },
  { name: "silent", url: "http://silent" }
];

/** One reachable host, differing from its siblings only in the kill field. */
function host(name: string, killSwitched: boolean | null | undefined): HostResult<ChokeState> {
  return {
    name,
    ok: true,
    data: {
      mode: "enforcing",
      kill_switched: killSwitched,
      tracked: 1,
      counts: {},
      thresholds: THRESHOLDS,
      audit: { ok: true, total: 1 }
    }
  };
}

const REPORTED_THREE_WAYS = [host("engaged", true), host("live", false), host("silent", null)];

describe("a host that did not report its kill-switch is neither on nor off", () => {
  it("reads null and a missing field as unknown, and only a boolean as a state", () => {
    expect(killStateOf({ kill_switched: true })).toBe("on");
    expect(killStateOf({ kill_switched: false })).toBe("off");
    expect(killStateOf({ kill_switched: null })).toBe("unknown");
    expect(killStateOf({})).toBe("unknown");
    expect(killStateOf(undefined)).toBe("unknown");
  });

  it("counts the engaged host and the silent one separately", () => {
    const { kpis } = deriveFleet(PEERS, REPORTED_THREE_WAYS);

    expect(kpis.healthy).toBe(3);
    // Exactly one host SAID the switch is engaged. The silent host must not
    // inflate this...
    expect(kpis.killed).toBe(1);
    // ...nor disappear into the reassuring side of it.
    expect(kpis.killUnknown).toBe(1);
  });

  it("keeps the unknown host out of the majority vote", () => {
    // Two reported (on, off) and one silent. The silent host must not vote:
    // with it folded in as "off", "off" would win 2-1 rather than tie.
    const drift = detectDrift(REPORTED_THREE_WAYS);
    expect(drift.kill).not.toBeNull();
    expect(["on", "off"]).toContain(drift.kill);

    // The decisive case: NOBODY reported. There is no majority to be had, and
    // "off" here would be a fleet-wide enforcement claim invented by the
    // console out of three nulls.
    const noneReported = detectDrift([
      host("engaged", null),
      host("live", null),
      host("silent", null)
    ]);
    expect(noneReported.kill).toBeNull();
  });

  it("raises no drift on the host that reported nothing", () => {
    const { rows, kpis } = deriveFleet(PEERS, REPORTED_THREE_WAYS);
    const silent = rows.find((row) => row.peer.name === "silent");

    expect(silent?.killState).toBe("unknown");
    expect(silent?.driftKill, "a host was marked drifted on a field it never reported").toBe(false);

    // And the drift count only ever names hosts that disagree on something
    // they both stated. Here that is the one host whose kill-switch differs
    // from the reported majority — never the silent one.
    const drifted = rows.filter((row) => row.driftMode || row.driftKill || row.driftThresholds);
    expect(drifted.map((row) => row.peer.name)).not.toContain("silent");
    expect(kpis.drift).toBe(drifted.length);
  });

  it("does not certify a fleet nobody measured as aligned", () => {
    // Three hosts, none of which reported a kill-switch: identical in every
    // other field. The old fold made all three "off", agreeing with a majority
    // they had themselves elected, and DRIFT read 0 — the console's word that
    // it had compared something.
    const { kpis, drift } = deriveFleet(PEERS, [
      host("engaged", null),
      host("live", null),
      host("silent", null)
    ]);

    expect(drift.kill).toBeNull();
    expect(kpis.killed).toBe(0);
    expect(kpis.killUnknown, "three hosts reported nothing and the strip counted none of them").toBe(3);
    expect(kpis.drift).toBe(0);
  });
});
