import { describe, expect, it } from "vitest";

/**
 * Window coverage is reported PER FEED.
 *
 * The dashboard's severity counts, deltas and timeline are server-computed over
 * the whole range, while the row-level panels are bound by finite client
 * buffers (1000 alerts, 2000 events). Those two buffers run out at very
 * different distances — alerts are far rarer than events — so a single
 * worst-case number misdescribes whichever panel is not the limiting one.
 *
 * Observed on the live console: a 30m window whose alert queue held 319 of 320
 * alerts was labelled "the alert queue ... shows only the most recent 25m",
 * because the EVENT buffer was short. A truncation notice that fires when
 * nothing is truncated is one operators learn to dismiss.
 */

// The computation under test, extracted verbatim in shape from SocRoute's
// windowCoverage memo.
function coverage(opts: {
  windowMs: number;
  now: number;
  oldestAlert?: number;
  oldestEvent?: number;
  alertsTruncated: boolean;
  eventsTruncated: boolean;
}) {
  const windowStart = opts.now - opts.windowMs;
  const shortBy = (v?: number) => (v !== undefined && v > windowStart ? v - windowStart : 0);
  const eventsShortMs = opts.eventsTruncated ? shortBy(opts.oldestEvent) : 0;
  const alertsShortMs = opts.alertsTruncated ? shortBy(opts.oldestAlert) : 0;
  return {
    complete: Math.max(eventsShortMs, alertsShortMs) === 0,
    alerts: { short: alertsShortMs > 0, coveredMs: Math.max(0, opts.windowMs - alertsShortMs) },
    events: { short: eventsShortMs > 0, coveredMs: Math.max(0, opts.windowMs - eventsShortMs) }
  };
}

const MIN = 60_000;
const NOW = 1_700_000_000_000;

describe("window coverage", () => {
  it("does not claim the alert queue is short when only events are", () => {
    // The live 30m case: events reach 25m, alerts cover the whole window.
    const c = coverage({
      windowMs: 30 * MIN,
      now: NOW,
      oldestEvent: NOW - 25 * MIN,
      oldestAlert: NOW - 30 * MIN,
      eventsTruncated: true,
      alertsTruncated: false
    });
    expect(c.complete).toBe(false); // something IS short — the notice still shows
    expect(c.alerts.short).toBe(false); // ...but not the alert queue
    expect(c.events.short).toBe(true);
    expect(c.events.coveredMs).toBe(25 * MIN);
  });

  it("reports each feed's own reach when both are short", () => {
    // The live 24h case: alerts reach ~87m, events ~25m. One number for both
    // understated the alert queue by over an hour.
    const c = coverage({
      windowMs: 24 * 60 * MIN,
      now: NOW,
      oldestAlert: NOW - 87 * MIN,
      oldestEvent: NOW - 25 * MIN,
      alertsTruncated: true,
      eventsTruncated: true
    });
    expect(c.alerts.coveredMs).toBe(87 * MIN);
    expect(c.events.coveredMs).toBe(25 * MIN);
    expect(c.alerts.coveredMs).not.toBe(c.events.coveredMs);
  });

  it("is complete when neither buffer hit its cap", () => {
    const c = coverage({
      windowMs: 5 * MIN,
      now: NOW,
      alertsTruncated: false,
      eventsTruncated: false
    });
    expect(c.complete).toBe(true);
    expect(c.alerts.short).toBe(false);
    expect(c.events.short).toBe(false);
  });

  it("a full buffer that still spans the window is not short", () => {
    // Truncated only means "we hit the cap", not "we missed data". If the cap
    // was reached but the oldest row still predates the window, coverage is
    // complete and no notice should fire.
    const c = coverage({
      windowMs: 10 * MIN,
      now: NOW,
      oldestAlert: NOW - 40 * MIN,
      oldestEvent: NOW - 40 * MIN,
      alertsTruncated: true,
      eventsTruncated: true
    });
    expect(c.complete).toBe(true);
  });
});
