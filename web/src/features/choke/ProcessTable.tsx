// The tracked-process list: the primary target-selection surface. Every row is
// a live circuit an operator can escalate straight from, so the column set is
// pinned by `data-choke-col` — the e2e certification selects on it.
import { VirtualList } from "../../components/VirtualList";
import type { ChokeAction, CircuitEntry } from "./types";
import { ACTIONS, originLabel } from "./utils";
import { EmptyState, StateBadge } from "./components";

const PROCESS_TABLE_COLUMNS = [
  { key: "select", label: "select" },
  { key: "state", label: "status" },
  { key: "pid", label: "process id" },
  { key: "binary", label: "binary" },
  { key: "origin", label: "origin" },
  { key: "exec", label: "exec id" },
  { key: "score", label: "risk" },
  { key: "actions", label: "actions" },
] as const;

function ProcessTableHeader() {
  return (
    <div className="choke-process-head">
      {PROCESS_TABLE_COLUMNS.map((column) => (
        <span key={column.key} data-choke-col={column.key}>
          {column.label}
        </span>
      ))}
    </div>
  );
}

export function ProcessTable({
  rows,
  selected,
  density,
  alertCounts,
  truncated,
  total,
  onSelect,
  onSelectAll,
  onClear,
  onAction,
  onDrill,
  onFilterBinary,
  onFilterExec,
  onCopy,
}: {
  rows: CircuitEntry[];
  selected: Set<string>;
  density: "normal" | "compact";
  alertCounts: Map<string, number>;
  truncated: boolean;
  total: number;
  onSelect: (execId: string) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onAction: (entry: CircuitEntry, action: ChokeAction) => void;
  onDrill: (execId: string) => void;
  onFilterBinary: (binary: string) => void;
  onFilterExec: (execId: string) => void;
  onCopy: (value: string) => void;
}) {
  if (rows.length === 0) return <EmptyState title="No tracked processes match" body="Clear filters or wait for the next circuit snapshot." />;
  return (
    <div className={`choke-process-table ${density}`}>
      <div className="choke-process-bulkbar" role="group" aria-label="Tracked process selection">
        <button type="button" onClick={onSelectAll}>Select all visible</button>
        <button type="button" onClick={onClear}>Clear selection</button>
        <span>{selected.size} selected</span>
      </div>
      <VirtualList
        className="choke-process-virtual"
        items={rows}
        estimateSize={density === "compact" ? 34 : 48}
        getKey={(entry) => entry.exec_id}
        before={<ProcessTableHeader />}
        renderItem={(entry) => {
          const selectedRow = selected.has(entry.exec_id);
          return (
            <div className={`choke-process-row ${selectedRow ? "selected" : ""}`}>
              <input type="checkbox" checked={selectedRow} onChange={() => onSelect(entry.exec_id)} aria-label={`Select ${entry.exec_id}`} />
              <StateBadge state={entry.state} />
              <button type="button" className="choke-link-text" data-choke-col="pid" onClick={() => onCopy(String(entry.pid || ""))}>{entry.pid || "-"}</button>
              <button type="button" className="choke-link-text truncate" data-choke-col="binary" title={entry.binary} onClick={() => entry.binary && onFilterBinary(entry.binary)}>{entry.binary || "(unknown)"}</button>
              <span className="truncate" data-choke-col="origin">{originLabel(entry) || "-"}</span>
              <button type="button" className="choke-link-text choke-exec-cell" data-choke-col="exec" title={entry.exec_id} onClick={() => onDrill(entry.exec_id)}>
                <span className="choke-execid-mono">{entry.exec_id || "-"}</span>
                <span className="choke-exec-badges">
                  {entry.annotation?.note ? <em>note</em> : null}
                  {entry.revert_pending ? <em>revert</em> : null}
                  {(alertCounts.get(entry.exec_id) || 0) > 0 ? <em>{alertCounts.get(entry.exec_id)} alerts</em> : null}
                </span>
              </button>
              <span className="choke-score" data-choke-col="score">
                <strong>{entry.score || 0}</strong><span><span style={{ width: `${Math.min(100, entry.score || 0)}%` }} /></span>
              </span>
              <span className="choke-row-actions" data-choke-col="actions">
                {ACTIONS.map((action) => (
                  <button key={action} type="button" onClick={() => onAction(entry, action)}>{action.slice(0, 3)}</button>
                ))}
                <button type="button" onClick={() => onFilterExec(entry.exec_id)}>tape</button>
              </span>
            </div>
          );
        }}
      />
      {truncated ? <div className="choke-table-tail">{total - rows.length} more match. Narrow the filter to inspect them.</div> : null}
    </div>
  );
}
