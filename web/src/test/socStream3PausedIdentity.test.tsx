import { renderHook } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EMPTY_SOC_SNAPSHOT, normalizeEvent } from "../features/soc/api";
import { applySocStreamBatch, mergeSocSnapshot } from "../features/soc/hooks";
import { useSocWindowModel } from "../features/soc/useSocWindowModel";
import type { SocEvent, SocSnapshot } from "../features/soc/types";
import type { StreamFrame } from "../lib/types";

/**
 * WHAT THIS PINS: Pause surviving a poll on the multi-tenant control plane.
 *
 * That deployment's event view emits no id, so `normalizeEvent` synthesises one
 * from the record's POSITION in the response — and the merge, which keys on the
 * record's own identity, hands the polled copy back in place of the buffered
 * one. Every 30s poll therefore re-mints the id of every event already on
 * screen. The pause set was captured as a set of `event.id`, so one poll after
 * Pause was pressed it matched nothing: the frozen list emptied itself under
 * the operator reading it, and "N arrived while held" counted the whole buffer
 * — including rows that had been on screen BEFORE the pause.
 *
 * Both halves are asserted here, because the readout and the list are the two
 * things an operator reconciles: a held list that says the right number while
 * showing nothing is no better than one that shows rows and lies about them.
 */

/** The control plane's event shape: no id field of any kind. */
function payload(seq: number) {
  return {
    timestamp: new Date(Date.parse("2026-06-25T09:00:00Z") + seq * 60_000).toISOString(),
    event_type: "file_open",
    process: "cat",
    args: `/etc/shadow-${seq}`,
    exec_id: `exec-${seq}`,
    pid: 500 + seq
  };
}

/** A poll response, newest first — the index each record's id is minted from. */
function polledSnapshot(seqs: number[]): SocSnapshot {
  return { ...EMPTY_SOC_SNAPSHOT, events: seqs.map((seq, index) => normalizeEvent(payload(seq), index)) };
}

function streamInto(snapshot: SocSnapshot, seqs: number[]): SocSnapshot {
  let next = snapshot;
  applySocStreamBatch(
    (update) => {
      next = typeof update === "function" ? (update as (prev: SocSnapshot) => SocSnapshot)(next) : update;
    },
    seqs.map((seq) => ({ type: "event", payload: payload(seq) }) as StreamFrame)
  );
  return next;
}

const modelArgs = {
  rangeMin: 30,
  now: Date.parse("2026-06-25T09:10:00Z"),
  truncated: { alerts: false, events: false },
  errors: {},
  statuses: {},
  query: "",
  hideBaseline: false,
  filterUnack: false,
  groupAlerts: false,
  sortField: "time" as const,
  ackStates: {},
  pinnedAlerts: [],
  timelineHidden: [],
  streamFilter: "",
  streamHideNoise: false
};

const args = (events: SocEvent[]) => events.map((event) => event.args);

describe("a paused list survives a poll that re-mints every id", () => {
  it("keeps exactly the rows it was holding, and counts only what arrived after the pause", () => {
    // Three events on screen when Pause is pressed.
    const atPause = polledSnapshot([3, 2, 1]);
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean }) =>
        useSocWindowModel({ ...modelArgs, snapshot: props.snapshot, streamPaused: props.streamPaused }),
      { initialProps: { snapshot: atPause, streamPaused: false } }
    );
    expect(args(result.current.visibleEvents)).toEqual(["/etc/shadow-3", "/etc/shadow-2", "/etc/shadow-1"]);

    rerender({ snapshot: atPause, streamPaused: true });

    // Two frames arrive down the stream while the list is held.
    const withArrivals = streamInto(atPause, [4, 5]);
    rerender({ snapshot: withArrivals, streamPaused: true });
    expect(args(result.current.visibleEvents)).toEqual(["/etc/shadow-3", "/etc/shadow-2", "/etc/shadow-1"]);
    expect(result.current.heldEventCount).toBe(2);

    // The 30s poll lands. Same five records, five NEW positional ids.
    const afterPoll = mergeSocSnapshot(withArrivals, polledSnapshot([5, 4, 3, 2, 1]));
    // Precondition: the ids really did move, or this test proves nothing.
    const idFor = (snapshot: SocSnapshot, arg: string) => snapshot.events.find((event) => event.args === arg)?.id;
    expect(
      idFor(afterPoll, "/etc/shadow-3"),
      "the poll did not re-mint the buffered ids, so the defect cannot reproduce here"
    ).not.toBe(idFor(atPause, "/etc/shadow-3"));

    rerender({ snapshot: afterPoll, streamPaused: true });

    expect(
      args(result.current.visibleEvents),
      "the held list shed its rows when the poll re-minted their ids"
    ).toEqual(["/etc/shadow-3", "/etc/shadow-2", "/etc/shadow-1"]);
    expect(
      result.current.heldEventCount,
      "the held readout counted rows that were already on screen before the pause"
    ).toBe(2);
  });

  it("releases everything that arrived, newest first, on resume", () => {
    const atPause = polledSnapshot([2, 1]);
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean }) =>
        useSocWindowModel({ ...modelArgs, snapshot: props.snapshot, streamPaused: props.streamPaused }),
      { initialProps: { snapshot: atPause, streamPaused: true } }
    );
    const afterPoll = mergeSocSnapshot(streamInto(atPause, [3]), polledSnapshot([3, 2, 1]));
    rerender({ snapshot: afterPoll, streamPaused: true });
    rerender({ snapshot: afterPoll, streamPaused: false });

    expect(args(result.current.visibleEvents)).toEqual(["/etc/shadow-3", "/etc/shadow-2", "/etc/shadow-1"]);
    expect(result.current.heldEventCount, "nothing is held once the list is live again").toBe(0);
  });

  it("holds a fresh set on the NEXT pause, not the one captured before the poll", () => {
    // Re-arming matters: an operator pauses, resumes to catch up, and pauses
    // again. A stale set would freeze the previous pause's rows.
    const atPause = polledSnapshot([2, 1]);
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean }) =>
        useSocWindowModel({ ...modelArgs, snapshot: props.snapshot, streamPaused: props.streamPaused }),
      { initialProps: { snapshot: atPause, streamPaused: true } }
    );
    const afterPoll = mergeSocSnapshot(streamInto(atPause, [3]), polledSnapshot([3, 2, 1]));
    rerender({ snapshot: afterPoll, streamPaused: false });
    rerender({ snapshot: afterPoll, streamPaused: true });

    const later = mergeSocSnapshot(streamInto(afterPoll, [4]), polledSnapshot([4, 3, 2, 1]));
    rerender({ snapshot: later, streamPaused: true });

    expect(args(result.current.visibleEvents)).toEqual(["/etc/shadow-3", "/etc/shadow-2", "/etc/shadow-1"]);
    expect(result.current.heldEventCount).toBe(1);
  });
});
