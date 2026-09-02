import { describe, expect, it } from "vitest";
import { isConnectionEvent, peerFromEvent } from "../features/soc/telemetry";

/**
 * An IP in a command line is an INTENT; an IP the sensor reported from the
 * connection is an OBSERVATION. The fallback used to treat them the same, and
 * on the live estate that produced 1,614 peers from non-network events against
 * 55 from real connection events — twenty-nine invented for every one
 * recovered, drawn onto the correlation graph as observed traffic.
 */
const base = { execId: "e", process: "/usr/bin/bash", timestamp: "2026-08-24T12:00:00Z" };

describe("a peer must have actually been observed", () => {
  it("uses the sensor's reported destination when present", () => {
    expect(peerFromEvent({ ...base, destIp: "203.0.113.77", destPort: 443 } as never))
      .toBe("203.0.113.77:443");
  });

  it("does NOT invent a peer from nc arguments", () => {
    // Straight from the estate: the old attack simulator's command line. This
    // drew a Tor exit onto the graph as though it had been contacted.
    expect(peerFromEvent({ ...base, args: "-w1 185.220.101.1 4444" } as never)).toBeUndefined();
  });

  it("does NOT turn an ICMP ping target into a TCP peer", () => {
    expect(peerFromEvent({ ...base, args: "-c1 -W1 172.31.45.193" } as never)).toBeUndefined();
  });

  it("does NOT turn a shell variable assignment into a peer", () => {
    expect(peerFromEvent({ ...base, args: "-v gw=172.31.32.1 -v cp=172.31.45.193" } as never))
      .toBeUndefined();
  });

  it("still recovers the peer from a historical connection event", () => {
    // The sensor rendered daddr:dport into args long before there was a field
    // for it, so gating the fallback removes the need for any backfill.
    expect(peerFromEvent({ ...base, policyName: "outbound-connections", args: "172.31.32.1:22" } as never))
      .toBe("172.31.32.1:22");
  });

  it("treats an unrecognised policy as not-a-connection", () => {
    // Under-claiming on purpose: a new detection must not start inventing
    // peers before anyone decides whether its arguments mean one.
    expect(isConnectionEvent({ ...base, policyName: "some-new-detection" } as never)).toBe(false);
    expect(peerFromEvent({ ...base, policyName: "some-new-detection", args: "10.0.0.5:80" } as never))
      .toBeUndefined();
  });
});
