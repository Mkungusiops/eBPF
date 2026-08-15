// The alert triage queue — the page's primary work surface.
//
// Long prop list on purpose: every one of these is a control an operator can
// touch on this panel (three filter chips, three sort modes, per-row ack/pin,
// bulk ack, the context menu and the hover preview), and the state behind them
// is persisted by the route. Hiding them behind a context would make the
// panel's inputs invisible without removing a single one.
import type { MouseEvent } from "react";
import { EmptyState, PanelFrame, StatusPill, ToggleChip } from "./components";
import { PANELS, type AckState, type AlertGroup, type SortField } from "./dashboard";
import { AlertRow, CoveragePill } from "./rows";
import type { SocAlert } from "./types";

export function AlertQueue({
  alerts,
  coverage,
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
  onOpen: (alert: SocAlert) => void;
  onAck: (id: string, value: AckState) => void;
  onPin: (id: string) => void;
  onContext: (event: MouseEvent, alert: SocAlert) => void;
  onHover: (event: MouseEvent, alert: SocAlert) => void;
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
              ack={ackStates[alert.id] || "new"}
              selected={selectedIds.has(alert.id)}
              pinned={pinnedAlerts.includes(alert.id)}
              onSelect={() => onToggleSelected(alert.id)}
              onOpen={() => onOpen(alert)}
              onAck={(value) => onAck(alert.id, value)}
              onPin={() => onPin(alert.id)}
              onContext={(event) => onContext(event, alert)}
              onHover={(event) => onHover(event, alert)}
              onLeave={onLeave}
            />
          ))
        ) : (
          <EmptyState title="No alerts match current filters" detail="Snapshots and SSE updates will fill this queue when the engine emits alerts." />
        )}
      </div>
    </PanelFrame>
  );
}
