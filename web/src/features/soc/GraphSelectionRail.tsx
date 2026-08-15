// The correlation graph's selection rail.
//
// Every node answers the same question — "which processes are behind this?" —
// and this rail is where that answer is read and acted on. It renders no
// enforcement of its own: picking a process hands it back up to the surface,
// which opens the action modal.
import { cx } from "./components";
import { shortGraphLabel } from "./format";
import type { ChokeCircuit } from "./api";
import type { GraphNode, ProcessInstance } from "./graphModel";

export function GraphSelectionRail({
  selected,
  neighbours,
  nodeProcesses,
  visibleProcesses,
  procFilter,
  onProcFilterChange,
  containedOnly,
  onToggleContainedOnly,
  circuits,
  drillExecId,
  onPickProcess,
  onSelectNode
}: {
  selected: GraphNode | null;
  neighbours: GraphNode[];
  nodeProcesses: ProcessInstance[];
  visibleProcesses: ProcessInstance[];
  procFilter: string;
  onProcFilterChange: (value: string) => void;
  containedOnly: boolean;
  onToggleContainedOnly: () => void;
  circuits: Map<string, ChokeCircuit>;
  drillExecId?: string;
  onPickProcess: (proc: ProcessInstance) => void;
  onSelectNode: (id: string) => void;
}) {
  return (
    <aside className="soc-graph-selection">
      <span className="soc-stat-label">Selection</span>

      {/* The node: what it is, and the processes behind it. Picking a process
          opens the action modal (below) rather than a cramped second panel. */}
      {selected ? (
        <div className="soc-graph-detail">
          <strong className={selected.group === "process" && selected.cls ? `cls-${selected.cls}` : undefined}>
            {selected.fullLabel || selected.label}
          </strong>
          <dl>
            <div>
              <dt>kind</dt>
              <dd>{selected.group}</dd>
            </div>
            {selected.group === "process" ? (
              <>
                <div>
                  <dt>classification</dt>
                  <dd className={selected.cls ? `cls-${selected.cls}` : undefined}>{selected.cls ?? "—"}</dd>
                </div>
                <div>
                  <dt>max score</dt>
                  <dd>{Math.round(selected.score ?? 0)}</dd>
                </div>
              </>
            ) : null}
            <div>
              <dt>connections</dt>
              <dd>{neighbours.length}</dd>
            </div>
          </dl>

          <div className="soc-graph-procs">
            <span className="soc-stat-label">
              Processes ({visibleProcesses.length}
              {visibleProcesses.length !== nodeProcesses.length ? ` of ${nodeProcesses.length}` : ""})
              {selected.group !== "process" ? " · via this node" : ""}
            </span>
            {nodeProcesses.length > 6 ? (
              <div className="soc-proc-tools">
                <input
                  value={procFilter}
                  onChange={(event) => onProcFilterChange(event.target.value)}
                  placeholder="Filter by pid or exec_id"
                  aria-label="Filter processes"
                />
                <button
                  type="button"
                  className={cx("soc-proc-toggle", containedOnly && "is-on")}
                  onClick={onToggleContainedOnly}
                  title="Show only processes already on a rung above pristine"
                >
                  Contained
                </button>
              </div>
            ) : null}
            {visibleProcesses.length ? (
              visibleProcesses.map((proc) => (
                <button
                  key={proc.execId}
                  type="button"
                  className={cx("soc-graph-proc", drillExecId === proc.execId && "is-active")}
                  onClick={() => onPickProcess(proc)}
                  title={`${proc.binary} · exec_id ${proc.execId}`}
                >
                  <span className="soc-graph-proc-bin">{shortGraphLabel(proc.binary, 22)}</span>
                  <span className="soc-graph-proc-meta">
                    {proc.pid ? `pid ${proc.pid}` : "pid —"}
                    {/* Live rung, so the list shows what is already contained
                        rather than making the operator open each one. */}
                    {(() => {
                      const st = circuits.get(proc.execId)?.state;
                      return st && st !== "pristine" ? <b className={`soc-rung-${st}`}>{st}</b> : null;
                    })()}
                    <em className={proc.score >= 25 ? "cls-attack" : proc.score >= 10 ? "cls-threat" : "cls-baseline"}>
                      {Math.round(proc.score)}
                    </em>
                  </span>
                </button>
              ))
            ) : (
              // Q2: distinguish "your filter hid them" from "this node has
              // nothing you can act on" — same empty box, very different
              // meaning, and conflating them wastes an operator's time.
              <p className="soc-graph-selection-empty">
                {nodeProcesses.length
                  ? "No process matches this filter."
                  : selected.group === "process"
                    ? "No live process resolved — these records carry no exec_id, so there is nothing to enforce against."
                    : "Nothing actionable here. This node is evidence; open a process it connects to."}
              </p>
            )}
          </div>

          {neighbours.length ? (
            <div className="soc-graph-neighbours">
              <span className="soc-stat-label">Connected</span>
              {neighbours.slice(0, 14).map((node) => (
                <button
                  key={node.id}
                  type="button"
                  className={cx("soc-graph-neighbour", `node-${node.group}`)}
                  onClick={() => onSelectNode(node.id)}
                  title={node.fullLabel || node.label}
                >
                  <i />
                  {node.label}
                </button>
              ))}
            </div>
          ) : null}
        </div>
      ) : null}

      {!selected ? (
        <p className="soc-graph-selection-empty">
          Click a node to see the processes behind it, then pick one to inspect and act.
        </p>
      ) : null}
    </aside>
  );
}
