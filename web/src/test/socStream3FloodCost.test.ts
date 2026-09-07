import { describe, expect, it } from "vitest";
import { EMPTY_SOC_SNAPSHOT, MAX_BUFFERED_EVENTS, normalizeEvent } from "../features/soc/api";
import { applySocStreamBatch, eventIdentity } from "../features/soc/hooks";
import type { SocEvent, SocSnapshot } from "../features/soc/types";
import type { StreamFrame } from "../lib/types";

/**
 * WHAT THIS PINS: the cost of merging a stream batch into a full buffer.
 *
 * The merge is keyed by the record's own identity rather than by its positional
 * `id`, and that identity is a TEN-FIELD CONTENT KEY — a map and a join. The
 * first version of that fix rebuilt the snapshot once per frame, filtering the
 * whole buffer each time, so a batch cost frames x buffer key builds: 500
 * frames over a full 2000-event buffer measured 644ms of unbroken main thread
 * against 36ms for the id compare it replaced. A stream batch is whatever
 * arrived in one animation frame and is uncapped (stores/stream.ts), so the
 * flood the live tail exists to show is exactly when the tab stops responding.
 *
 * The assertion is on WORK DONE, not wall-clock: a timing budget on a loaded
 * CI box is a flaky test that gets deleted, and the defect is algorithmic. Each
 * buffered record's `process` is a counting getter, and the ONLY thing that
 * reads it is a content-key build — so the counter is literally "how many times
 * did this batch recompute a buffered record's identity".
 */

/** Control-plane shape: eventView emits no id, so the id is positional. */
function payload(seq: number) {
  return {
    timestamp: new Date(Date.parse("2026-06-25T09:00:00Z") + seq * 1000).toISOString(),
    event_type: "file_open",
    process: "cat",
    args: `/etc/shadow-${seq}`,
    exec_id: `exec-${seq}`,
    pid: 1000 + seq
  };
}

let identityBuilds = 0;

/** The same record, with its content-key reads counted. */
function counted(event: SocEvent): SocEvent {
  const process = event.process;
  const copy = { ...event };
  Object.defineProperty(copy, "process", {
    get() {
      identityBuilds += 1;
      return process;
    },
    enumerable: true
  });
  return copy as SocEvent;
}

function eventFrame(seq: number): StreamFrame {
  return { type: "event", payload: payload(10_000 + seq) } as StreamFrame;
}

function fullBuffer(): SocEvent[] {
  // Newest-first, as every feed in this console is.
  return Array.from({ length: MAX_BUFFERED_EVENTS }, (_, index) =>
    counted(normalizeEvent(payload(MAX_BUFFERED_EVENTS - index), index))
  );
}

/** The real call site: applySocStreamBatch drives a React setState updater. */
function applyTo(snapshot: SocSnapshot, batch: StreamFrame[]): SocSnapshot {
  let next = snapshot;
  applySocStreamBatch(
    (update) => {
      next = typeof update === "function" ? (update as (prev: SocSnapshot) => SocSnapshot)(next) : update;
    },
    batch
  );
  return next;
}

describe("a stream flood does not rebuild the whole buffer's identities per frame", () => {
  it("computes each buffered record's identity at most once for a 500-frame batch", () => {
    identityBuilds = 0;
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: fullBuffer() };
    const batch = Array.from({ length: 500 }, (_, index) => eventFrame(index));

    const merged = applyTo(snapshot, batch);

    expect(merged.events).toHaveLength(MAX_BUFFERED_EVENTS);
    // One key per buffered record is the honest cost of a union; the slack is
    // there so a second legitimate pass would not fail the test, while the
    // per-frame version (500 x 2000 = 1,000,000) cannot possibly fit.
    expect(
      identityBuilds,
      `the batch rebuilt buffered identities ${identityBuilds} times for a ${MAX_BUFFERED_EVENTS}-record buffer — the merge is O(batch x buffer)`
    ).toBeLessThanOrEqual(MAX_BUFFERED_EVENTS * 2);
  });

  it("remembers an identity it has already built, so the next batch pays nothing for it", () => {
    identityBuilds = 0;
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: fullBuffer() };
    const first = applyTo(snapshot, Array.from({ length: 500 }, (_, index) => eventFrame(index)));
    const afterFirst = identityBuilds;

    applyTo(first, Array.from({ length: 500 }, (_, index) => eventFrame(1_000 + index)));

    expect(
      identityBuilds - afterFirst,
      "records already in the buffer had their content key rebuilt by the next batch"
    ).toBe(0);
  });
});

describe("the cheaper merge keeps the merge's meaning", () => {
  it("puts the newest frame of the batch at row 0", () => {
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: [normalizeEvent(payload(1), 0)] };
    const merged = applyTo(snapshot, [eventFrame(1), eventFrame(2), eventFrame(3)]);
    expect(merged.events[0].args).toBe(`/etc/shadow-${10_003}`);
    expect(merged.events).toHaveLength(4);
  });

  it("does not duplicate a record the stream re-delivers under a fresh positional id", () => {
    const repeated = payload(42);
    const buffered = normalizeEvent(repeated, 7); // positional id ...-7
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: [buffered] };

    const merged = applyTo(snapshot, [{ type: "event", payload: repeated } as StreamFrame]);

    expect(merged.events, "the same event was held twice under two positional ids").toHaveLength(1);
    expect(new Set(merged.events.map(eventIdentity)).size).toBe(1);
  });

  it("collapses a repeat WITHIN one batch to its latest copy", () => {
    const repeated = payload(43);
    const merged = applyTo({ ...EMPTY_SOC_SNAPSHOT }, [
      { type: "event", payload: repeated } as StreamFrame,
      { type: "event", payload: repeated } as StreamFrame
    ]);
    expect(merged.events).toHaveLength(1);
  });

  it("never grows a buffer past its cap", () => {
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: fullBuffer() };
    const merged = applyTo(snapshot, Array.from({ length: 700 }, (_, index) => eventFrame(2_000 + index)));
    expect(merged.events).toHaveLength(MAX_BUFFERED_EVENTS);
  });

  it("leaves the snapshot untouched when a batch carries nothing this dashboard models", () => {
    const snapshot: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, events: [normalizeEvent(payload(1), 0)] };
    const merged = applyTo(snapshot, [{ type: "heartbeat", payload: {} } as unknown as StreamFrame]);
    // Same reference: a chatty stream of frames the dashboard does not render
    // must not re-render every panel that reads the snapshot.
    expect(merged).toBe(snapshot);
  });
});
