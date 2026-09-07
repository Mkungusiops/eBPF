// The alert triage queue — the page's primary work surface.
//
// Long prop list on purpose: every one of these is a control an operator can
// touch on this panel (three filter chips, three sort modes, per-row ack/pin,
// bulk ack, the context menu and the hover preview), and the state behind them
// is persisted by the route. Hiding them behind a context would make the
// panel's inputs invisible without removing a single one.
import type { MouseEvent } from "react";
import { groupAckState, groupMemberIds } from "./analytics";
import { EmptyState, PanelFrame, StatusPill, ToggleChip } from "./components";
import { PANELS, type AckState, type AlertGroup, type SortField } from "./dashboard";
import { AlertRow, CoveragePill, emptyBecause } from "./rows";

/**
 * WHY the queue is empty — and the two answers are opposite instructions.
 *
 * One hard-coded "No alerts match current filters" served both "you filtered
 * everything out" and "the estate is quiet". An analyst with no query and no
 * chip engaged was told their filters excluded everything, so they went
 * loosening filters that were not set and never learned the feed was dry; and
 * an analyst who has learned the panel says that when the estate is quiet reads
 * the same words as "quiet" on the day a stray query is hiding real alerts.
 *
 * Filters can only be the explanation when there was something for them to
 * exclude, so the window's own pre-filter count decides which claim is made —
 * the same distinction rows.tsx `emptyBecause` already draws for the IOC and
 * network panels.
 *
 * And only a filter that ACTUALLY EXCLUDED rows may be named. Listing every
 * chip that happens to be engaged is a weaker version of the same defect: "Hide
 * baseline" is on by default, so an analyst whose search emptied the queue was
 * sent to switch off a chip that had removed nothing, and learned to distrust
 * the sentence. `excluded` carries the per-filter counts (see queueExclusions);
 * the copy names the non-zero ones and nothing else.
 */
export function queueEmptyState({
  query,
  windowAlertCount,
  beyondWindow,
  excluded
}: {
  query: string;
  windowAlertCount: number;
  beyondWindow: number;
  excluded: { query: number; baseline: number; unacked: number };
}): { title: string; detail: string } {
  const blamed = [
    excluded.query > 0 ? `the search "${query.trim()}" (${excluded.query.toLocaleString()})` : "",
    excluded.baseline > 0 ? `Hide baseline (${excluded.baseline.toLocaleString()})` : "",
    excluded.unacked > 0 ? `Unacked only (${excluded.unacked.toLocaleString()})` : ""
  ].filter(Boolean);
  if (windowAlertCount > 0 && blamed.length) {
    return {
      title: "No alerts match current filters",
      detail: `${windowAlertCount.toLocaleString()} alert${windowAlertCount === 1 ? "" : "s"} in this window ${
        windowAlertCount === 1 ? "is" : "are"
      } excluded by ${blamed.join(" + ")}.`
    };
  }
  if (windowAlertCount > 0) {
    // Alerts in the window, an empty list, and no filter that rejected any of
    // them: naming a filter here would be a guess. Say what is known instead.
    return {
      title: "No alerts to show",
      detail: `${windowAlertCount.toLocaleString()} alert${
        windowAlertCount === 1 ? "" : "s"
      } in this window did not reach the queue, and none of this panel's filters excluded them.`
    };
  }
  if (beyondWindow > 0) {
    return {
      title: "No alerts in the selected window",
      detail: emptyBecause("alerts", beyondWindow, "alerts")
    };
  }
  return {
    title: "No alerts recorded on this estate",
    detail: "Nothing has reached this console yet. Snapshots and SSE updates fill this queue when the engine emits alerts."
  };
}

export function AlertQueue({
  alerts,
  coverage,
  query,
  windowAlertCount,
  excluded,
  beyondWindow,
  hideBaseline,
  onHideBaseline,
  filterUnack,
  onFilterUnack,
  grouped,
  onGrouped,
  sortField,
  onSortField,
  selectedIds,
  onToggleSelected,
  onClearSelection,
  onBulkAck,
  ackStates,
  pinnedAlerts,
  onOpen,
  onAck,
  onPin,
  onContext,
  onHover,
  onLeave
}: {
  alerts: AlertGroup[];
  coverage: { short: boolean; coveredMs: number };
  /** The search box's current text — one of the three things that can empty this list. */
  query: string;
  /** Alerts in the selected window BEFORE this panel's filters ran. */
  windowAlertCount: number;
  /** How many of those each filter actually excluded — see queueExclusions. */
  excluded: { query: number; baseline: number; unacked: number };
  /** Alerts the console holds that fall outside the selected window. */
  beyondWindow: number;
  hideBaseline: boolean;
  onHideBaseline: (value: boolean) => void;
  filterUnack: boolean;
  onFilterUnack: (value: boolean) => void;
  grouped: boolean;
  onGrouped: (value: boolean) => void;
  sortField: SortField;
  onSortField: (value: SortField) => void;
  selectedIds: Set<string>;
  onToggleSelected: (id: string) => void;
  onClearSelection: () => void;
  onBulkAck: (value: AckState) => void;
  ackStates: Record<string, AckState>;
  pinnedAlerts: string[];
  // Every one of these hands over the WHOLE ROW. A row is N alerts, and the
  // surfaces these open (the drill panel, the context menu) act on it — so they
  // are given the group, not the representative member whose id it carries.
  onOpen: (alert: AlertGroup) => void;
  /** Takes every id the row stands for — a grouped row is N alerts, not one. */
  onAck: (ids: string[], value: AckState) => void;
  onPin: (ids: string[]) => void;
  onContext: (event: MouseEvent, alert: AlertGroup) => void;
  onHover: (event: MouseEvent, alert: AlertGroup) => void;
  onLeave: () => void;
}) {
  const selectedAlertCount = selectedIds.size;
  return (
    <PanelFrame
      panel={PANELS["alert-triage-queue"]}
      className="soc-alert-panel"
      status={
        <>
          <CoveragePill feed={coverage} />
          <StatusPill label={`${alerts.length} shown`} tone="info" />
        </>
      }
      actions={
        <div className="soc-control-row">
          <ToggleChip label="Hide baseline" active={hideBaseline} onChange={onHideBaseline} />
          <ToggleChip label="Unacked only" active={filterUnack} onChange={onFilterUnack} tone="warn" />
          <ToggleChip label="Group" active={grouped} onChange={onGrouped} />
        </div>
      }
    >
      <div className="soc-sort-row">
        <span>sort by</span>
        {(["time", "severity", "score"] as SortField[]).map((field) => (
          <button key={field} type="button" className={sortField === field ? "is-active" : ""} onClick={() => onSortField(field)}>
            {field}
          </button>
        ))}
      </div>
      {selectedAlertCount ? (
        <div className="soc-bulk-bar">
          <strong>{selectedAlertCount} selected</strong>
          <button type="button" onClick={() => onBulkAck("ack")}>
            Acknowledge
          </button>
          <button type="button" onClick={() => onBulkAck("resolved")}>
            Resolve
          </button>
          <button type="button" onClick={onClearSelection}>
            Clear
          </button>
        </div>
      ) : null}
      <div className="soc-alert-list">
        {alerts.length ? (
          alerts.map((alert) => (
            <AlertRow
              key={alert.id}
              alert={alert}
              ack={groupAckState(alert.members, ackStates)}
              selected={selectedIds.has(alert.id)}
              pinned={pinnedAlerts.includes(alert.id)}
              onSelect={() => onToggleSelected(alert.id)}
              onOpen={() => onOpen(alert)}
              onAck={(value) => onAck(groupMemberIds(alert), value)}
              onPin={() => onPin(groupMemberIds(alert))}
              onContext={(event) => onContext(event, alert)}
              onHover={(event) => onHover(event, alert)}
              onLeave={onLeave}
            />
          ))
        ) : (
          <EmptyState {...queueEmptyState({ query, windowAlertCount, beyondWindow, excluded })} />
        )}
      </div>
    </PanelFrame>
  );
}
