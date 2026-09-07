import { describe, expect, it } from "vitest";
import { EMPTY_SOC_SNAPSHOT, normalizeAlert, normalizeEvent } from "../features/soc/api";
import { mergeSocSnapshot } from "../features/soc/hooks";
import { queueEmptyState } from "../features/soc/AlertQueue";
import { queueExclusions } from "../features/soc/analytics";
import type { SocAlert, SocEvent, SocSnapshot } from "../features/soc/types";

/**
 * What the snapshot poll is allowed to do to the buffer the stream fills.
 *
 * Two ways it was wrong in opposite directions: it de-duplicated on an id that
 * the control plane does not supply (so one event became many), and it could
 * only ever ADD (so a record the server had stopped returning could never
 * leave).
 */

/** A control-plane event view: no id field of any kind. See eventView in engine/internal/controlplane/http.go. */
function cpEvent(execId: string, timestamp: string, args: string) {
  return {
    agent: "agent-1",
    exec_id: execId,
    pid: 4242,
    event_type: "file_open",
    process: "/usr/bin/cat",
    args,
    timestamp
  };
}

function snapshotOf(events: SocEvent[] = [], alerts: SocAlert[] = []): SocSnapshot {
  return { ...EMPTY_SOC_SNAPSHOT, events, alerts };
}

/** Normalise the way fetchSocSnapshot does — index-positional, newest first. */
function poll(records: ReturnType<typeof cpEvent>[]): SocEvent[] {
  return records.map((record, index) => normalizeEvent(record, index));
}

describe("a poll of records the server gives no id to does not duplicate them", () => {
  /**
   * normalizeEvent synthesises `${event_type}-${timestamp}-${index}` when the
   * payload has no id, and the multi-tenant control plane's event view emits
   * none — so the SAME event comes back under a NEW id every time a newer event
   * pushes it down the list. Keyed on that id, the merge kept both copies and
   * the buffer filled with duplicates of one event, inflating the stream list
   * and every counter derived from it.
   */
  const first = cpEvent("exec-aaa", "2026-06-25T09:00:00.000000001Z", "/etc/shadow");
  const second = cpEvent("exec-bbb", "2026-06-25T09:00:30.000000002Z", "/etc/passwd");

  it("gives the same event a different id on each poll, or this test is about nothing", () => {
    const before = poll([first]);
    const after = poll([second, first]);
    // The normaliser rounds the wire's RFC3339Nano to milliseconds, so the id
    // it builds carries the millisecond form.
    expect(before[0].id).toBe("file_open-2026-06-25T09:00:00.000Z-0");
    expect(after[1].id, "the record shifted index and was renamed by it").toBe("file_open-2026-06-25T09:00:00.000Z-1");
  });

  it("holds one copy of it across two polls", () => {
    const afterFirstPoll = mergeSocSnapshot(snapshotOf(), snapshotOf(poll([first])));
    const afterSecondPoll = mergeSocSnapshot(afterFirstPoll, snapshotOf(poll([second, first])));
    expect(afterSecondPoll.events.map((event) => event.args)).toEqual(["/etc/passwd", "/etc/shadow"]);
  });

  it("does not collapse two genuinely different events that share a type and second", () => {
    const a = cpEvent("exec-aaa", "2026-06-25T09:00:00.000000001Z", "/etc/shadow");
    const b = cpEvent("exec-ccc", "2026-06-25T09:00:00.000000002Z", "/etc/gshadow");
    const merged = mergeSocSnapshot(snapshotOf(poll([a])), snapshotOf(poll([b, a])));
    expect(merged.events).toHaveLength(2);
  });

  it("still prefers a server-supplied id when there is one", () => {
    const withId = { ...cpEvent("exec-aaa", "2026-06-25T09:00:00Z", "/etc/shadow"), id: "srv-1" };
    const moved = { ...withId, args: "/etc/shadow" };
    const merged = mergeSocSnapshot(snapshotOf([normalizeEvent(withId, 0)]), snapshotOf([normalizeEvent(moved, 3)]));
    expect(merged.events).toHaveLength(1);
  });
});

describe("the poll is authoritative about what still exists", () => {
  /**
   * With the merge unioning and nothing evicting, no record could ever leave a
   * buffer — a manual Refresh included. A row the server had stopped returning
   * stayed on screen and kept feeding counters whose whole job is to be honest
   * about the estate.
   */
  const stays = cpEvent("exec-stays", "2026-06-25T09:00:10Z", "/etc/passwd");
  const removed = cpEvent("exec-removed", "2026-06-25T09:00:05Z", "/etc/shadow");

  it("drops a record the next poll no longer returns", () => {
    const buffered = mergeSocSnapshot(snapshotOf(), snapshotOf(poll([stays, removed])));
    expect(buffered.events).toHaveLength(2);

    const after = mergeSocSnapshot(buffered, snapshotOf(poll([stays])));
    expect(after.events.map((event) => event.execId)).toEqual(["exec-stays"]);
  });

  it("keeps a frame that arrived while the request was in flight", () => {
    // Newer than anything the poll saw: it cannot have been "removed" by a
    // response that was already on the wire when it arrived.
    const inFlight = normalizeEvent(cpEvent("exec-live", "2026-06-25T09:09:00Z", "/tmp/live"), 0);
    const after = mergeSocSnapshot(snapshotOf([inFlight]), snapshotOf(poll([stays, removed])));
    expect(after.events.map((event) => event.execId)).toEqual(["exec-live", "exec-stays", "exec-removed"]);
  });

  it("keeps everything when the feed's own fetch failed", () => {
    // An errored feed normalises to an empty list. Treating that as "the estate
    // has nothing" would wipe the buffer on one flaky poll.
    const buffered = mergeSocSnapshot(snapshotOf(), snapshotOf(poll([stays, removed])));
    const after = mergeSocSnapshot(buffered, snapshotOf([]), { events: "HTTP 500" });
    expect(after.events).toHaveLength(2);
  });

  it("evicts an alert the server stopped returning too", () => {
    const kept = normalizeAlert({ alert_id: "a-1", severity: "critical", timestamp: "2026-06-25T09:00:10Z" }, 0);
    const gone = normalizeAlert({ alert_id: "a-2", severity: "high", timestamp: "2026-06-25T09:00:05Z" }, 1);
    const buffered = mergeSocSnapshot(snapshotOf(), snapshotOf([], [kept, gone]));
    expect(buffered.alerts).toHaveLength(2);
    const after = mergeSocSnapshot(buffered, snapshotOf([], [kept]));
    expect(after.alerts.map((alert) => alert.id)).toEqual(["a-1"]);
  });
});

describe("the empty queue names only the filters that actually excluded something", () => {
  /**
   * Naming every ENGAGED filter is a weaker version of the defect it replaced:
   * "Hide baseline" is on by default, so an analyst whose search emptied the
   * queue was sent to switch off a chip that had removed nothing.
   */
  function alert(id: string, overrides: Partial<SocAlert> = {}): SocAlert {
    return {
      id,
      title: "Suspicious chain: /usr/sbin/runc → /bin/sh",
      description: "attack path",
      severity: "critical",
      score: 88,
      timestamp: "2026-06-25T09:00:00Z",
      raw: undefined,
      ...overrides
    };
  }

  const attacks = [alert("a-1"), alert("a-2")];

  it("counts nothing against a chip that removed no rows", () => {
    const excluded = queueExclusions(attacks, {
      query: "no-such-alert-anywhere",
      // On, and it excludes nothing: every one of these alerts classifies as an
      // attack path, not baseline.
      hideBaseline: true,
      filterUnack: false,
      ackStates: {}
    });
    expect(excluded).toEqual({ query: 2, baseline: 0, unacked: 0 });
  });

  it("does not blame Hide baseline when the search is what emptied the queue", () => {
    const state = queueEmptyState({
      query: "no-such-alert-anywhere",
      windowAlertCount: 2,
      beyondWindow: 0,
      excluded: { query: 2, baseline: 0, unacked: 0 }
    });
    expect(state.detail).toContain("no-such-alert-anywhere");
    expect(state.detail, "a chip that excluded nothing was named as a cause").not.toContain("Hide baseline");
  });

  it("names a chip that did exclude rows, with what it took", () => {
    const excluded = queueExclusions([alert("a-1"), alert("b-1", { title: "cron ran", description: "scheduled job", score: 4, severity: "info" })], {
      query: "",
      hideBaseline: true,
      filterUnack: false,
      ackStates: {}
    });
    expect(excluded.baseline).toBe(1);
    const state = queueEmptyState({ query: "", windowAlertCount: 2, beyondWindow: 0, excluded });
    expect(state.detail).toContain("Hide baseline (1)");
  });

  it("counts Unacked only against the alerts it hid", () => {
    const excluded = queueExclusions(attacks, {
      query: "",
      hideBaseline: false,
      filterUnack: true,
      ackStates: { "a-1": "ack" }
    });
    expect(excluded).toEqual({ query: 0, baseline: 0, unacked: 1 });
  });

  it("still refuses to blame filters on an estate that produced nothing", () => {
    const quiet = queueEmptyState({
      query: "",
      windowAlertCount: 0,
      beyondWindow: 0,
      excluded: { query: 0, baseline: 0, unacked: 0 }
    });
    expect(quiet.title).toMatch(/recorded on this estate/i);
    expect(quiet.detail).not.toMatch(/filter/i);
  });
});
