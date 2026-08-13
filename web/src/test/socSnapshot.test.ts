import { afterEach, describe, expect, it, vi } from "vitest";
import {
  MAX_BUFFERED_ALERTS,
  MAX_BUFFERED_DECISIONS,
  MAX_BUFFERED_EVENTS,
  fetchSocSnapshot
} from "../features/soc/api";

// Every dashboard number is derived from this snapshot, so what the snapshot
// asks for and what it admits it is missing decide whether those numbers are
// honest. Both defects guarded here shipped: a decision feed capped at one
// record, and a silently short event window.

interface Recorded {
  paths: string[];
}

function mockApi(handler: (path: string) => unknown): Recorded {
  const recorded: Recorded = { paths: [] };
  vi.stubGlobal(
    "fetch",
    vi.fn(async (input: RequestInfo | URL) => {
      const path = String(input);
      recorded.paths.push(path);
      return new Response(JSON.stringify(handler(path)), {
        status: 200,
        headers: { "content-type": "application/json" }
      });
    })
  );
  return recorded;
}

function alertsPage(count: number, oldestAgeMs: number) {
  // Newest-first, matching the server's ORDER BY at DESC.
  return Array.from({ length: count }, (_, index) => ({
    severity: "critical",
    title: `alert ${index}`,
    exec_id: `exec-${index}`,
    timestamp: new Date(Date.now() - (oldestAgeMs * index) / Math.max(1, count - 1)).toISOString()
  }));
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("fetchSocSnapshot", () => {
  it("does not cap the decision feed at a single record", async () => {
    // `/api/decisions?limit=1` made the "Response actions" tile structurally
    // incapable of reading above 1, so it reported "1 containment decision" for
    // a tenant that had run hundreds.
    const recorded = mockApi(() => []);
    await fetchSocSnapshot();

    const decisionsPath = recorded.paths.find((path) => path.includes("/api/decisions"));
    expect(decisionsPath).toBeDefined();
    expect(decisionsPath).not.toContain("limit=1&");
    expect(decisionsPath).toContain(`limit=${MAX_BUFFERED_DECISIONS}`);
    expect(MAX_BUFFERED_DECISIONS).toBeGreaterThan(1);
  });

  it("requests exactly the history the console can hold", async () => {
    // The fetch caps and the live-stream trim caps have to agree; if the fetch
    // asks for more than the stream keeps, the first frame after a poll throws
    // the surplus away.
    const recorded = mockApi(() => []);
    await fetchSocSnapshot();

    expect(recorded.paths.find((path) => path.includes("/api/alerts"))).toContain(`limit=${MAX_BUFFERED_ALERTS}`);
    expect(recorded.paths.find((path) => path.includes("/api/events"))).toContain(`limit=${MAX_BUFFERED_EVENTS}`);
  });

  it("reports truncation when a feed comes back full", async () => {
    mockApi((path) => {
      if (path.includes("/api/events")) return { events: alertsPage(MAX_BUFFERED_EVENTS, 60_000) };
      if (path.includes("/api/alerts")) return alertsPage(MAX_BUFFERED_ALERTS, 60_000);
      return [];
    });

    const read = await fetchSocSnapshot();

    expect(read.truncated.events).toBe(true);
    expect(read.truncated.alerts).toBe(true);
  });

  it("reports no truncation when a feed comes back short", async () => {
    mockApi((path) => {
      if (path.includes("/api/events")) return { events: alertsPage(12, 60_000) };
      if (path.includes("/api/alerts")) return alertsPage(5, 60_000);
      return [];
    });

    const read = await fetchSocSnapshot();

    expect(read.truncated.events).toBe(false);
    expect(read.truncated.alerts).toBe(false);
    expect(read.snapshot.alerts).toHaveLength(5);
  });
});
