// The live kernel-event tail. Virtualised because the list re-renders on every
// stream batch and the buffer holds up to 2000 rows.
import { VirtualList } from "../../components/VirtualList";
import { EmptyState, PanelFrame, StatusPill, ToggleChip, cx } from "./components";
import { PANELS } from "./dashboard";
import { eventIdentity } from "./hooks";
import { EventRow } from "./rows";
import type { SocEvent } from "./types";

export function EventStream({
  events,
  paused,
  heldCount,
  onPaused,
  hideNoise,
  onHideNoise,
  filter,
  onFilter,
  onOpenEvent
}: {
  events: SocEvent[];
  paused: boolean;
  /**
   * Frames that reached the buffer while the list was held.
   *
   * Counted by record IDENTITY upstream (useSocWindowModel), not by `event.id`:
   * the control plane's ids are positional and are re-minted by every poll, so
   * an id-keyed count reported rows that had been on screen since before Pause
   * was pressed as new arrivals.
   */
  heldCount: number;
  onPaused: (value: boolean) => void;
  hideNoise: boolean;
  onHideNoise: (value: boolean) => void;
  filter: string;
  onFilter: (value: string) => void;
  onOpenEvent: (event: SocEvent) => void;
}) {
  return (
    <PanelFrame
      panel={PANELS["live-event-stream"]}
      status={<StatusPill label={`${events.length} events`} tone={paused ? "warn" : "ok"} />}
      actions={
        <div className="soc-control-row">
          <ToggleChip label="Hide self-noise" active={hideNoise} onChange={onHideNoise} />
          <ToggleChip label={paused ? "Paused" : "Pause"} active={paused} onChange={onPaused} tone="warn" />
          {/* A held list that has simply stopped moving is indistinguishable
              from an estate that has gone quiet, so say which. The count lives
              here rather than in the header pill because that pill states how
              many rows are ON SCREEN, and two numbers in one label cannot be
              read as either. */}
          {paused ? (
            <span className="soc-stream-held">
              {heldCount === 0 ? "nothing new while held" : `${heldCount} arrived while held`}
            </span>
          ) : null}
          <input
            className="soc-stream-filter"
            value={filter}
            onChange={(event) => onFilter(event.target.value)}
            placeholder="filter /regex/"
            // The placeholder is not a name: a screen reader announces this as
            // "edit text, blank", and the hint disappears on the first
            // keystroke, so the one description of the control vanishes exactly
            // when someone is using it.
            aria-label="Filter events by regular expression"
          />
        </div>
      }
    >
      <VirtualList
        className={cx("soc-event-list", paused && "is-paused")}
        items={events}
        estimateSize={68}
        // KEYED BY IDENTITY, THE SAME THING THE MERGE DE-DUPLICATES BY.
        //
        // `event.id` is positional on the control plane — the normaliser mints
        // it as `<type>-<timestamp>-<index>` when the payload carries none — so
        // an id-keyed list got both halves of the contract wrong at once: two
        // DIFFERENT events that landed on the same type, millisecond and index
        // shared one React key, and reconciliation duplicated one and dropped
        // the other; while the SAME event came back under a new id after every
        // poll, tearing its row down and rebuilding it, which loses an expanded
        // row and the scroll position of whoever is reading a burst. Keying by
        // identity means what React calls one row and what the merge calls one
        // record are the same judgement.
        //
        // eventIdentity is memoised per record (see hooks.ts), so this costs a
        // WeakMap lookup per rendered row, not a content key.
        getKey={eventIdentity}
        renderItem={(event) => <EventRow event={event} onOpen={onOpenEvent} />}
        empty={
          <EmptyState
            title="No events yet"
            detail="The list is capped at 200 rows and updates from /api/stream when available."
          />
        }
      />
    </PanelFrame>
  );
}
