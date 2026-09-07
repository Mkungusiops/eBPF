import { render, renderHook, screen } from "@testing-library/react";
import { describe, expect, it } from "vitest";
import { EventStream } from "../features/soc/EventStream";
import { mergeSocSnapshot } from "../features/soc/hooks";
import { useSocWindowModel } from "../features/soc/useSocWindowModel";
import { EMPTY_SOC_SNAPSHOT } from "../features/soc/api";
import type { SocEvent, SocSnapshot } from "../features/soc/types";

/**
 * The live event stream's two ways of losing telemetry the console already had.
 *
 * Both were invisible on screen: the pill kept counting frames, the list kept
 * looking healthy, and the rows an operator needed were simply not in it.
 */
function socEvent(id: string, timestamp: string): SocEvent {
  return { id, eventType: "file_open", timestamp, process: "curl", args: `/var/tmp/${id}`, raw: undefined };
}

function snapshotWith(events: SocEvent[]): SocSnapshot {
  return { ...EMPTY_SOC_SNAPSHOT, events };
}

const modelArgs = {
  rangeMin: 30,
  now: Date.parse("2026-06-25T09:05:00Z"),
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

describe("Pause freezes the list instead of dimming it", () => {
  /**
   * `paused` used to reach nothing but a pill tone and `.is-paused { opacity:
   * .62 }`. Rows kept arriving under the cursor of the operator who had just
   * pressed Pause, so their click opened the drill panel for an event that had
   * scrolled into the position they aimed at.
   */
  it("holds the rows that were on screen when Pause was pressed", () => {
    const first = socEvent("held-1", "2026-06-25T09:00:00Z");
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean }) =>
        useSocWindowModel({ ...modelArgs, snapshot: props.snapshot, streamPaused: props.streamPaused }),
      { initialProps: { snapshot: snapshotWith([first]), streamPaused: false } }
    );
    expect(result.current.visibleEvents.map((event) => event.id)).toEqual(["held-1"]);

    rerender({ snapshot: snapshotWith([first]), streamPaused: true });
    const arrived = socEvent("while-paused-1", "2026-06-25T09:01:00Z");
    rerender({ snapshot: snapshotWith([arrived, first]), streamPaused: true });

    expect(
      result.current.visibleEvents.map((event) => event.id),
      "a frame that arrived while paused was rendered anyway"
    ).toEqual(["held-1"]);
    // The frame is NOT dropped — it is in the buffer, counted, and the panel
    // says so, which is what distinguishes a held list from a quiet estate.
    expect(result.current.heldEventCount).toBe(1);
  });

  it("releases everything that arrived, in order, on resume", () => {
    const first = socEvent("held-1", "2026-06-25T09:00:00Z");
    const arrived = socEvent("while-paused-1", "2026-06-25T09:01:00Z");
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean }) =>
        useSocWindowModel({ ...modelArgs, snapshot: props.snapshot, streamPaused: props.streamPaused }),
      { initialProps: { snapshot: snapshotWith([first]), streamPaused: true } }
    );
    rerender({ snapshot: snapshotWith([arrived, first]), streamPaused: true });
    rerender({ snapshot: snapshotWith([arrived, first]), streamPaused: false });

    expect(result.current.visibleEvents.map((event) => event.id)).toEqual(["while-paused-1", "held-1"]);
    expect(result.current.heldEventCount, "nothing is held once the list is live again").toBe(0);
  });

  it("still applies the filter to the frozen rows", () => {
    // Freezing the RENDERED rows rather than the buffer they came from would
    // leave the filter and the self-noise toggle inert while paused, which is
    // its own dead control.
    const kept = socEvent("keep-1", "2026-06-25T09:00:00Z");
    const other: SocEvent = { ...socEvent("drop-1", "2026-06-25T09:00:00Z"), args: "/var/tmp/other" };
    const { result, rerender } = renderHook(
      (props: { snapshot: SocSnapshot; streamPaused: boolean; streamFilter: string }) =>
        useSocWindowModel({
          ...modelArgs,
          snapshot: props.snapshot,
          streamPaused: props.streamPaused,
          streamFilter: props.streamFilter
        }),
      { initialProps: { snapshot: snapshotWith([other, kept]), streamPaused: true, streamFilter: "" } }
    );
    rerender({ snapshot: snapshotWith([other, kept]), streamPaused: true, streamFilter: "keep-1" });
    expect(result.current.visibleEvents.map((event) => event.id)).toEqual(["keep-1"]);
  });
});

describe("a frame delivered during the first snapshot poll survives it", () => {
  /**
   * useSocData opens the SSE stream and the first /api/events poll together and
   * used to resolve the poll with `setSnapshot(read.snapshot)` — replacing the
   * whole buffer, including whatever the stream had already written into it.
   */
  it("keeps a streamed event the poll did not return", () => {
    const streamed = socEvent("preflight-1", "2026-06-25T09:10:00Z");
    const polled = socEvent("polled-1", "2026-06-25T09:00:00Z");
    const merged = mergeSocSnapshot(snapshotWith([streamed]), snapshotWith([polled]));
    expect(merged.events.map((event) => event.id)).toEqual(["preflight-1", "polled-1"]);
  });

  it("does not duplicate a record both sides hold", () => {
    const shared = socEvent("shared-1", "2026-06-25T09:00:00Z");
    const merged = mergeSocSnapshot(snapshotWith([shared]), snapshotWith([{ ...shared, process: "cat" }]));
    expect(merged.events).toHaveLength(1);
    expect(merged.events[0].process, "the polled record is the authoritative one").toBe("cat");
  });

  it("takes non-feed state from the poll", () => {
    const stale: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, version: { ...EMPTY_SOC_SNAPSHOT.version, sha: "old" } };
    const fresh: SocSnapshot = { ...EMPTY_SOC_SNAPSHOT, version: { ...EMPTY_SOC_SNAPSHOT.version, sha: "new" } };
    expect(mergeSocSnapshot(stale, fresh).version.sha).toBe("new");
  });
});

describe("the stream filter announces itself", () => {
  /**
   * The input carried a placeholder and nothing else, which a screen reader
   * announces as "edit text, blank" — and the placeholder disappears on the
   * first keystroke, so the only description of the control vanishes exactly
   * when it is being used.
   */
  it("has an accessible name that survives typing", () => {
    render(
      <EventStream
        events={[]}
        paused={false}
        heldCount={0}
        onPaused={() => {}}
        hideNoise={false}
        onHideNoise={() => {}}
        filter="/etc/"
        onFilter={() => {}}
        onOpenEvent={() => {}}
      />
    );
    const input = screen.getByRole("textbox", { name: /filter events/i });
    expect(input).toHaveValue("/etc/");
  });

  it("says how many frames arrived while the list was held", () => {
    render(
      <EventStream
        events={[]}
        paused
        heldCount={3}
        onPaused={() => {}}
        hideNoise={false}
        onHideNoise={() => {}}
        filter=""
        onFilter={() => {}}
        onOpenEvent={() => {}}
      />
    );
    expect(screen.getByText(/3 arrived while held/)).toBeTruthy();
  });
});
