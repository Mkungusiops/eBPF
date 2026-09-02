import { describe, expect, it } from "vitest";
import { isDevicePeer, isLoopbackPeer, joinPeer, peerAddress, peerFromEvent } from "../features/soc/telemetry";
import type { SocEvent } from "../features/soc/types";

/**
 * Measured on the live engine, 2026-08-25, minutes after curl entered the
 * outbound-connections policy:
 *
 *   /usr/bin/curl | peer=::1:8090 | args=::1:8090
 *
 * That is a health check against the machine's own console. `peer.split(":")[0]`
 * returns the EMPTY STRING for it, which matches neither the loopback test nor
 * the RFC1918 test — so it fell through to "external peer" and was drawn on the
 * correlation graph as an outbound connection, in the panel whose entire job is
 * showing who talked to whom.
 */
const ev = (over: Partial<SocEvent>): SocEvent =>
  ({ eventType: "process_kprobe", timestamp: "2026-08-25T10:00:00Z", ...over }) as SocEvent;

describe("peerAddress", () => {
  it("strips the port from IPv4", () => {
    expect(peerAddress("10.0.0.5:443")).toBe("10.0.0.5");
    expect(peerAddress("10.0.0.5")).toBe("10.0.0.5");
  });

  it("unwraps a bracketed IPv6 endpoint", () => {
    expect(peerAddress("[::1]:8090")).toBe("::1");
    expect(peerAddress("[2001:db8::1]:443")).toBe("2001:db8::1");
  });

  it("keeps unbracketed IPv6 whole rather than guessing a port split", () => {
    // "::1:80" is a valid address on its own, so splitting is a guess. Keeping
    // it whole errs toward classifying it correctly below.
    expect(peerAddress("::1:8090")).toBe("::1:8090");
    expect(peerAddress("2001:db8::1")).toBe("2001:db8::1");
  });

  it("never returns the empty string for a real peer", () => {
    // The whole defect in one assertion.
    for (const p of ["::1:8090", "[::1]:8090", "2001:db8::1", "10.0.0.5:443"]) {
      expect(peerAddress(p)).not.toBe("");
    }
  });
});

describe("isLoopbackPeer", () => {
  it("recognises IPv4 loopback", () => {
    expect(isLoopbackPeer("127.0.0.1:8090")).toBe(true);
  });

  it("recognises IPv6 loopback in every form the sensor produces", () => {
    expect(isLoopbackPeer("[::1]:8090")).toBe(true);
    expect(isLoopbackPeer("::1:8090")).toBe(true); // the measured, unbracketed form
    expect(isLoopbackPeer("::1")).toBe(true);
    expect(isLoopbackPeer("[::ffff:127.0.0.1]:8090")).toBe(true); // dual-stack socket
  });

  it("does not swallow a real external peer", () => {
    expect(isLoopbackPeer("172.66.147.243:443")).toBe(false);
    expect(isLoopbackPeer("[2001:db8::1]:443")).toBe(false);
  });
});

describe("isDevicePeer", () => {
  it("still classifies RFC1918 addresses as devices", () => {
    expect(isDevicePeer("10.0.0.5:22")).toBe(true);
    expect(isDevicePeer("192.168.1.4:80")).toBe(true);
    expect(isDevicePeer("172.31.32.1:22")).toBe(true);
  });

  it("does not classify loopback or public addresses as devices", () => {
    expect(isDevicePeer("172.66.147.243:443")).toBe(false); // 172.66 is public
    expect(isDevicePeer("[::1]:8090")).toBe(false);
  });
});

describe("peerFromEvent", () => {
  it("brackets IPv6 so the result can be parsed back", () => {
    const peer = peerFromEvent(ev({ destIp: "::1", destPort: 8090 }));
    expect(peer).toBe("[::1]:8090");
    // The round trip is the point: what is produced must be classifiable.
    expect(isLoopbackPeer(peer!)).toBe(true);
  });

  it("leaves IPv4 unbracketed", () => {
    expect(peerFromEvent(ev({ destIp: "172.66.147.243", destPort: 443 }))).toBe("172.66.147.243:443");
  });
});

describe("joinPeer", () => {
  it("is the single place the bracketing rule lives", () => {
    expect(joinPeer("::1", 8090)).toBe("[::1]:8090");
    expect(joinPeer("10.0.0.5", 443)).toBe("10.0.0.5:443");
  });
});
