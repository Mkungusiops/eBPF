// The decision tape: the audited record of what the gateway did, newest first.
// Rows carry ack state because the tape doubles as the triage queue — an
// operator marks a burst read rather than scrolling past it forever.
import type React from "react";
import type { Decision } from "./types";
import { actorLabel, formatTime } from "./utils";
import { EmptyState, StateBadge } from "./components";
import { VirtualList } from "../../components/VirtualList";

export function DecisionTape({
  refEl,
  rows,
  selected,
  acked,
  onSelect,
  onDrill,
  onFilterExec,
  filterExec,
  onClearFilterExec,
  onAck,
  onUnack,
  onCopy,
}: {
  refEl: React.MutableRefObject<HTMLDivElement | null>;
  rows: Array<{ decision: Decision; count: number }>;
  selected: Set<number>;
  acked: Set<number>;
  onSelect: (id: number) => void;
  onDrill: (execId: string) => void;
  onFilterExec: (execId: string) => void;
  /** The exec_id the tape is pinned to, when a row's "filter" was clicked. */
  filterExec?: string | null;
  onClearFilterExec?: () => void;
  onAck: (ids: number[]) => void;
  onUnack: (ids: number[]) => void;
  onCopy: (value: string) => void;
}) {
  const selectedIds = Array.from(selected);
  return (
    <div className="choke-tape-wrap">
      {/* Undo lives where the filter was applied.
          The clear chip existed, but only in the page-level filter strip at the
          very top — and the tape sits at the bottom of a long scroll. So
          clicking "filter" on a row narrowed the tape to one decision and left
          no way back from where the operator was standing. A control whose undo
          is off-screen is, from the user's position, a one-way door. */}
      {filterExec ? (
        <button
          type="button"
          className="choke-tape-pinned"
          onClick={() => onClearFilterExec?.()}
          aria-label="Clear the process filter and show all decisions"
          title="Show all decisions again"
        >
          pinned to one process · <strong>{filterExec.slice(0, 12)}…</strong>
          <span aria-hidden="true">✕</span>
        </button>
      ) : null}
      <div className="choke-tape-head"><span /> <span>time</span><span>action</span><span>exec_id / reason</span><span>tools</span></div>
      <VirtualList
        className="choke-tape"
        viewportRef={refEl}
        items={rows}
        estimateSize={58}
        getKey={({ decision }) => `${decision.id || 0}-${decision.exec_id}`}
        empty={
          <EmptyState
            title="No decisions match"
            body={
              filterExec
                ? "The tape is pinned to one process. Clear the pin above to see the rest."
                : "The tape is filtered by time, action, search, and ack state."
            }
          />
        }
        renderItem={({ decision, count }) => {
          const id = decision.id || 0;
          return (
            <div key={`${id}-${decision.exec_id}`} className={`choke-tape-row ${selected.has(id) ? "selected" : ""} ${acked.has(id) ? "acked" : ""}`}>
              <input type="checkbox" checked={selected.has(id)} onChange={() => onSelect(id)} aria-label={`Select decision ${id}`} />
              <span>{formatTime(decision.timestamp)}</span>
              <StateBadge state={decision.to_state || decision.action} />
              <button type="button" className="choke-tape-main" onClick={() => decision.exec_id && onDrill(decision.exec_id)}>
                <strong className="choke-execid-mono">{decision.exec_id || "-"}</strong>
                <span>{decision.reason || decision.binary || "-"}</span>
                {decision.pid ? <em>pid {decision.pid}</em> : null}
                {/* Who ordered it. An automatic decision has no actor, and
                    saying so is the point: "by whom" and "by the score" are
                    the two answers a review needs to tell apart, and a blank
                    where an operator's name should be is indistinguishable
                    from an unattributed one. */}
                <em className="choke-tape-actor">{actorLabel(decision.actor)}</em>
                {count > 0 ? <em>+{count}</em> : null}
                {decision.dry_run ? <em>dry-run</em> : null}
                {acked.has(id) ? <em>acked</em> : null}
              </button>
              <div className="choke-tape-actions">
                {decision.exec_id ? <button type="button" onClick={() => onFilterExec(decision.exec_id || "")}>filter</button> : null}
                <button type="button" onClick={() => onCopy(JSON.stringify(decision))}>copy</button>
              </div>
            </div>
          );
        }}
      />
      {selected.size > 0 ? (
        <div className="choke-tape-bulkbar">
          <span>{selected.size} selected</span>
          <button type="button" onClick={() => onAck(selectedIds)}>ack</button>
          <button type="button" onClick={() => onUnack(selectedIds)}>unack</button>
          <button type="button" onClick={() => onCopy(rows.filter((row) => selected.has(row.decision.id || 0)).map((row) => JSON.stringify(row.decision)).join("\n"))}>copy JSONL</button>
        </div>
      ) : null}
    </div>
  );
}
