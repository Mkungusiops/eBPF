// The decision tape: the audited record of what the gateway did, newest first.
// Rows carry ack state because the tape doubles as the triage queue — an
// operator marks a burst read rather than scrolling past it forever.
import type React from "react";
import type { Decision } from "./types";
import { formatTime } from "./utils";
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
  onAck: (ids: number[]) => void;
  onUnack: (ids: number[]) => void;
  onCopy: (value: string) => void;
}) {
  const selectedIds = Array.from(selected);
  return (
    <div className="choke-tape-wrap">
      <div className="choke-tape-head"><span /> <span>time</span><span>action</span><span>exec_id / reason</span><span>tools</span></div>
      <VirtualList
        className="choke-tape"
        viewportRef={refEl}
        items={rows}
        estimateSize={58}
        getKey={({ decision }) => `${decision.id || 0}-${decision.exec_id}`}
        empty={<EmptyState title="No decisions match" body="The tape is filtered by time, action, search, and ack state." />}
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
