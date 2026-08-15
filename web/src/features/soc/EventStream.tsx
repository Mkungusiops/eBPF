// The live kernel-event tail. Virtualised because the list re-renders on every
// stream batch and the buffer holds up to 2000 rows.
import { VirtualList } from "../../components/VirtualList";
import { EmptyState, PanelFrame, StatusPill, ToggleChip, cx } from "./components";
import { PANELS } from "./dashboard";
import { EventRow } from "./rows";
import type { SocEvent } from "./types";

export function EventStream({
  events,
  paused,
  onPaused,
  hideNoise,
  onHideNoise,
  filter,
  onFilter,
  onOpenEvent
}: {
  events: SocEvent[];
  paused: boolean;
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
          <input className="soc-stream-filter" value={filter} onChange={(event) => onFilter(event.target.value)} placeholder="filter /regex/" />
        </div>
      }
    >
      <VirtualList
        className={cx("soc-event-list", paused && "is-paused")}
        items={events}
        estimateSize={68}
        getKey={(event) => event.id}
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
