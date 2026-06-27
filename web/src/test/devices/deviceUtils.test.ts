import { describe, expect, it } from "vitest";

import {
  flagName,
  formatAgo,
  formatBucket,
  formatBytes,
  isBridgeMasterWarning,
  isDeviceStateName,
  macSlug,
  normalizeCounts,
  sortFlows,
  summarizeResults
} from "../../features/devices/utils";

describe("device utilities", () => {
  it("maps device bucket flags by most severe action", () => {
    expect(flagName(0)).toBe("none");
    expect(flagName(1)).toBe("throttle");
    expect(flagName(2)).toBe("tarpit");
    expect(flagName(4)).toBe("quarantine");
    expect(flagName(8)).toBe("sever");
    expect(flagName(1 | 8)).toBe("sever");
  });

  it("formats buckets and byte counts for the table", () => {
    expect(formatBucket(null)).toBe("-");
    expect(formatBucket({ flags: 1, rate_per_sec: 50 })).toBe("throttle 50/s");
    expect(formatBytes(42)).toBe("42 B");
    expect(formatBytes(2048)).toBe("2.0 KB");
    expect(formatBytes(3 * 1024 * 1024)).toBe("3.0 MB");
  });

  it("formats relative last-seen timestamps", () => {
    const now = new Date("2026-06-25T12:00:00Z").getTime();
    expect(formatAgo("2026-06-25T11:59:45Z", now)).toBe("15s");
    expect(formatAgo("2026-06-25T11:30:00Z", now)).toBe("30m");
    expect(formatAgo("2026-06-25T09:00:00Z", now)).toBe("3h");
    expect(formatAgo("2026-06-22T12:00:00Z", now)).toBe("3d");
    expect(formatAgo("not a date", now)).toBe("-");
  });

  it("normalizes counts and mac slugs", () => {
    expect(normalizeCounts({ pristine: 2, severed: 1 })).toEqual({
      pristine: 2,
      throttled: 0,
      tarpit: 0,
      quarantined: 0,
      severed: 1
    });
    expect(macSlug("aa:bb:cc:dd:ee:ff")).toBe("aa-bb-cc-dd-ee-ff");
    expect(isDeviceStateName("tarpit")).toBe(true);
    expect(isDeviceStateName("unknown")).toBe(false);
  });

  it("sorts flows busiest first", () => {
    expect(
      sortFlows([
        { dest_ip: "10.0.0.2", packets: 2, bytes: 900 },
        { dest_ip: "10.0.0.3", packets: 9, bytes: 50 },
        { dest_ip: "10.0.0.4", packets: 2, bytes: 1000 }
      ]).map((flow) => flow.dest_ip)
    ).toEqual(["10.0.0.3", "10.0.0.4", "10.0.0.2"]);
  });

  it("summarizes partial action results", () => {
    expect(summarizeResults([{ ok: true }, { ok: true }], "choked")).toBe("2/2 choked");
    expect(summarizeResults([{ ok: true }, { ok: false, error: "protected MAC" }], "choked")).toBe(
      "1/2 choked: protected MAC"
    );
  });

  it("detects bridge-master attach warnings", () => {
    expect(isBridgeMasterWarning({ links_attached: 1, frames_seen: 0 })).toBe(true);
    expect(isBridgeMasterWarning({ links_attached: 1, frames_seen: 10 })).toBe(false);
    expect(isBridgeMasterWarning({ links_attached: 0, frames_seen: 0 })).toBe(false);
  });
});
