import { render, screen } from "@testing-library/react";
import { beforeAll, describe, expect, it } from "vitest";
import { normalizeEvent } from "../features/soc/api";
import { EventStream } from "../features/soc/EventStream";
import type { SocEvent } from "../features/soc/types";

/**
 * WHAT THIS PINS: the live event list's React keys are the record's IDENTITY,
 * the same thing the merge de-duplicates by — not `event.id`.
 *
 * The control plane's event view emits no id, so `normalizeEvent` synthesises
 * one from the record's POSITION in the response (`<type>-<timestamp>-<index>`).
 * That has two consequences for a keyed list, and they pull in opposite
 * directions, which is why both are asserted here:
 *
 *   • two DIFFERENT events can carry the SAME positional id — same type, same
 *     millisecond, same index in two different responses — and an id-keyed list
 *     puts them under one React key, where reconciliation is free to omit one.
 *     The list this happens to is the flood tail, and a flood is when the
 *     buffer is fullest and collisions likeliest.
 *   • the SAME event carries a DIFFERENT positional id after the next poll, so
 *     an id-keyed row is torn down and rebuilt every 30 seconds even though
 *     nothing about it changed — losing whatever state lives in that DOM node.
 *
 * Keying by identity makes what React thinks is one row and what the merge
 * thinks is one record the same judgement.
 */

// The virtualiser measures its viewport with offsetHeight/offsetWidth, both of
// which are 0 in jsdom — a zero-height viewport renders zero rows, and the
// assertions below would pass against an empty list. Give it a real viewport.
beforeAll(() => {
  Object.defineProperty(HTMLElement.prototype, "offsetHeight", { configurable: true, value: 600 });
  Object.defineProperty(HTMLElement.prototype, "offsetWidth", { configurable: true, value: 800 });
});

/** The control plane's event shape: no id field of any kind. */
function payload(seq: number, timestamp: string) {
  return {
    timestamp,
    event_type: "file_open",
    process: "cat",
    args: `/etc/shadow-${seq}`,
    exec_id: `exec-${seq}`,
    pid: 500 + seq
  };
}

function stream(events: SocEvent[]) {
  return (
    <EventStream
      events={events}
      paused={false}
      heldCount={0}
      onPaused={() => {}}
      hideNoise={false}
      onHideNoise={() => {}}
      filter=""
      onFilter={() => {}}
      onOpenEvent={() => {}}
    />
  );
}

const rowFor = (seq: number) => screen.queryByRole("button", { name: `file_open cat /etc/shadow-${seq}` });
const rowLabels = () =>
  screen.queryAllByRole("button", { name: /^file_open cat/ }).map((row) => row.getAttribute("aria-label"));

describe("the event list keys rows by identity, not by the positional id", () => {
  it("renders two different events that share one positional id as two rows", () => {
    // Two genuinely different events (different exec_id, different pid,
    // different args) that the normaliser stamps with the same synthetic id:
    // same event_type, same millisecond, same index in their own responses.
    const first = normalizeEvent(payload(1, "2026-06-25T09:00:00.000Z"), 0);
    const second = normalizeEvent(payload(2, "2026-06-25T09:00:00.000Z"), 0);
    expect(first.id, "the premise: the control plane hands both records the same id").toBe(second.id);

    const { rerender } = render(stream([second, first]));
    // The collision costs the list its integrity on RE-RENDER rather than on
    // mount: React reconciles against a key map in which one key can only point
    // at one child, so a colliding row is duplicated and/or omitted. Re-renders
    // are all this list ever does — one per stream batch.
    const third = normalizeEvent(payload(3, "2026-06-25T09:03:00.000Z"), 0);
    rerender(stream([third, second, first]));

    // Three events in the buffer, three rows on screen, each one exactly once.
    expect(rowLabels()).toEqual([
      "file_open cat /etc/shadow-3",
      "file_open cat /etc/shadow-2",
      "file_open cat /etc/shadow-1"
    ]);
    expect(rowFor(1), "the older of the two colliding events must still be on screen").not.toBeNull();
  });

  it("keeps a row's DOM node across a poll that re-mints every id", () => {
    // Three events as the first poll returned them, newest first.
    const poll1 = [3, 2, 1].map((seq, index) =>
      normalizeEvent(payload(seq, `2026-06-25T09:0${seq}:00.000Z`), index)
    );
    const { rerender } = render(stream(poll1));
    const before = rowFor(2);
    expect(before).not.toBeNull();

    // The next poll returns the same three events with a fourth in front, so
    // every surviving event moves index and comes back under a new id.
    const poll2 = [4, 3, 2, 1].map((seq, index) =>
      normalizeEvent(payload(seq, `2026-06-25T09:0${seq}:00.000Z`), index)
    );
    expect(poll2[2].id, "the premise: the same real event is re-minted with a new id").not.toBe(poll1[1].id);
    rerender(stream(poll2));

    const after = rowFor(2);
    expect(after).not.toBeNull();
    // Same DOM node, not a replacement: a remount is what loses an expanded
    // row, a text selection, or the scroll position an operator is holding
    // while they read a burst.
    expect(after, "the row must be reused, not torn down and rebuilt").toBe(before);
  });
});
