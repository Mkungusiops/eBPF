// The Command lens — the operating view. Threat-intelligence ribbon, the
// three-column workbench (engine diagnostics · tracked processes · decision
// tape) and the bulk-action bar.
//
// It takes the route's hook bundles rather than forty individual props: the
// view is a projection of the whole route state, and threading each field
// separately would mean a signature nobody reads and a rename in three files
// every time a filter is added.
import type { ChokeAction, CircuitEntry, Thresholds } from "./types";
import { READ_ONLY_TITLE } from "./canRespond";
import { auditVerdict } from "../common/enforcement";
import { ACTIONS, appliedTierCounts, bucketizeDecisions, countCgroupPids, enforcementGapReason } from "./utils";
import { formatWindow, toggleSetValue } from "./constants";
import type { ChokeData } from "./useChokeData";
import type { useChokeFilters } from "./useChokeFilters";
import type { useChokePosture } from "./useChokePosture";
import { MiniPanel, Panel, RankedList, Sparkline, StateLadder } from "./components";
import { BucketList, EngineStack, ThresholdPanel } from "./panels";
import { ProcessTable } from "./ProcessTable";
import { DecisionTape } from "./DecisionTape";

export function CommandView({
  data,
  filters,
  posture,
  writesWithheld,
  commitWithheld,
  withheldReason,
  density,
  acked,
  onDensity,
  onCopy,
  onAck,
  onUnack,
  onManualAction,
  onBulkAction,
  onBulkForget,
  onDrill,
  onCommitThresholds,
}: {
  data: ChokeData;
  filters: ReturnType<typeof useChokeFilters>;
  posture: ReturnType<typeof useChokePosture>;
  /**
   * The operator gate, decided once in ChokeRoute and handed down rather than
   * re-derived here.
   *
   * `writesWithheld` covers BOTH "the server refused" and "the server has not
   * answered yet" — posture alone cannot express the second, and reading
   * `posture.readOnlyAccount` here is what armed every row action for the first
   * paint of a read-only session.
   */
  writesWithheld: boolean;
  /** Also true when the DEPLOYMENT is not serving — the threshold commit's gate. */
  commitWithheld: boolean;
  /** The sentence that goes with whichever withholding it is; "" when none. */
  withheldReason: string;
  density: "normal" | "compact";
  acked: Set<number>;
  onDensity: () => void;
  onCopy: (value: string) => void;
  onAck: (ids: number[]) => void;
  onUnack: (ids: number[]) => void;
  onManualAction: (entry: CircuitEntry, action: ChokeAction) => void;
  onBulkAction: (action: ChokeAction) => void;
  onBulkForget: () => void;
  onDrill: (execId: string) => void;
  onCommitThresholds: (next: Thresholds) => Promise<void>;
}) {
  const { buckets, cgroups, chokeState, circuits, decisions, now, streamInfo, systemHealth } = data;
  const { disabled, engineOnlyHint, isFleetConsole, mode, stateCounts, thresholds } = posture;
  // Two different disablers, deliberately kept apart. `disabled` says the
  // gateway is not serving; the withheld pair is about the OPERATOR — refused,
  // or not yet answered for. Panels that only READ (the engine stack) stay on
  // the first; anything that writes uses the second.
  return (
    <>
      <section className="choke-ti-ribbon" data-panel="threat-intelligence-ribbon">
        <MiniPanel title="Decision Velocity" meta={`${filters.currentWindowDecisions.length} in ${formatWindow(filters.windowMin)}`}>
          <div className="choke-velocity">
            <strong>{(filters.currentWindowDecisions.length / Math.max(1, filters.windowMin)).toFixed(filters.windowMin <= 60 ? 1 : 0)}</strong>
            <span>/ min avg</span>
          </div>
          <Sparkline bars={filters.velocityBuckets} tone="accent" />
        </MiniPanel>
        <MiniPanel title="Top Offenders" meta={`${filters.topBinaries.length} binaries`}>
          <RankedList rows={filters.topBinaries} onPick={(key) => filters.setGlobalSearch(`binary:${key}`)} />
        </MiniPanel>
        <MiniPanel title="Signal Patterns" meta={`${filters.topReasons.length} reasons`}>
          <RankedList rows={filters.topReasons} onPick={(key) => filters.setGlobalSearch(`"${key}"`)} />
        </MiniPanel>
        {/* Three states, not two — see auditVerdict. Testing only `ok === false`
            made this tile read "chain broken" on every multi-tenant deployment,
            for a chain the control plane does not maintain centrally. */}
        <MiniPanel
          title="System Health"
          meta={auditVerdict(chokeState?.audit) === "broken" ? "chain broken" : mode}
        >
          <div className="choke-kv-mini">
            <span>audit</span>
            <strong>
              {auditVerdict(chokeState?.audit) === "broken"
                ? "broken"
                : auditVerdict(chokeState?.audit) === "unverifiable"
                  ? "not verified here"
                  : `${chokeState?.audit?.total || 0} rows`}
            </strong>
            <span>tracked</span><strong>{chokeState?.tracked || circuits.length}</strong>
            <span>bpf</span><strong>{buckets.length}</strong>
            <span>cgroups</span><strong>{countCgroupPids(cgroups)}</strong>
          </div>
        </MiniPanel>
      </section>

      <main className="choke-grid">
        <section className="choke-left-rail">
          <Panel dataPanel="engine-stack-panel" title="Engine Stack">
            <EngineStack health={systemHealth} disabled={disabled} />
          </Panel>
          <Panel dataPanel="state-ladder-panel" title="State Ladder">
            <StateLadder
              counts={stateCounts}
              applied={appliedTierCounts(cgroups)}
              gapReason={enforcementGapReason(chokeState)}
            />
          </Panel>
          <ThresholdPanel
            dataPanel="thresholds-panel"
            thresholds={thresholds}
            circuits={circuits}
            disabled={commitWithheld}
            disabledReason={withheldReason}
            onCommit={onCommitThresholds}
          />
          <Panel dataPanel="choke-map-bpf-mirror" title="Choke Map / BPF Mirror">
            <BucketList buckets={buckets} />
          </Panel>
        </section>

        <section className="choke-center">
          <Panel
            dataPanel="tracked-processes-list"
            title="Tracked Processes"
            actions={
              <>
                <span className="choke-muted">{filters.visibleCircuits.length} / {circuits.length}</span>
                <button className="choke-inline-button" type="button" onClick={onDensity}>
                  {density === "compact" ? "Comfort" : "Compact"}
                </button>
              </>
            }
          >
            <div className="choke-table-toolbar">
              <input aria-label="Filter tracked processes" value={filters.procFilter} onChange={(event) => filters.setProcFilter(event.target.value)} placeholder="filter binary, pid, exec_id, origin" />
              <div className="choke-chip-row">
                {["throttled", "tarpit", "quarantined", "severed", "pristine"].map((state) => (
                  <button
                    key={state}
                    className={`choke-chip ${filters.stateFilters.has(state) ? "on" : ""}`}
                    type="button"
                    onClick={() => filters.setStateFilters((prev) => toggleSetValue(prev, state))}
                  >
                    {state}
                  </button>
                ))}
              </div>
            </div>
            <ProcessTable
              rows={filters.visibleCircuits}
              selected={filters.selectedExecs}
              density={density}
              alertCounts={filters.alertCounts}
              truncated={filters.truncatedCircuits}
              total={filters.searchFilteredCircuits.length}
              onSelect={(execId) => filters.setSelectedExecs((prev) => toggleSetValue(prev, execId))}
              onSelectAll={() => filters.setSelectedExecs(new Set(filters.visibleCircuits.map((entry) => entry.exec_id)))}
              onClear={() => filters.setSelectedExecs(new Set())}
              onAction={onManualAction}
              onDrill={onDrill}
              onFilterBinary={(binary) => filters.setGlobalSearch(`binary:${binary}`)}
              onFilterExec={filters.setTapeFilterExec}
              onCopy={onCopy}
              readOnly={writesWithheld}
              readOnlyTitle={withheldReason}
            />
          </Panel>
        </section>

        <section className="choke-right-rail">
          <Panel
            dataPanel="decision-tape"
            title="Decision Tape"
            actions={<span className={`choke-live-indicator ${streamInfo.state}`}>{filters.filteredDecisions.length} / {formatWindow(filters.windowMin)}</span>}
          >
            {/* Stacked, grouped toolbar (BPF-mirror style): full-width search, then a clean
               filter row — action facets divided from display toggles. */}
            <div className="choke-tape-toolbar">
              {/* Named for assistive tech; the placeholder documents the syntax
                  but vanishes as soon as anything is typed. */}
              <input
                className="choke-tape-search"
                aria-label="Search the decision tape"
                value={filters.tapeSearch}
                onChange={(event) => filters.setTapeSearch(event.target.value)}
                placeholder="Search reason, pid, exec_id, binary or /regex/"
              />
              <div className="choke-tape-filters" role="group" aria-label="Decision tape filters">
                {["throttle", "tarpit", "quarantine", "sever", "thaw"].map((action) => (
                  <button
                    key={action}
                    type="button"
                    className={`choke-chip ${filters.tapeActions.has(action) ? "on" : ""}`}
                    onClick={() => filters.setTapeActions((prev) => toggleSetValue(prev, action))}
                  >
                    {action}
                  </button>
                ))}
                <button type="button" className={`choke-chip ${filters.groupTape ? "on" : ""}`} onClick={() => filters.setGroupTape((prev) => !prev)}>
                  group
                </button>
                <button type="button" className={`choke-chip ${filters.hideAcked ? "on" : ""}`} onClick={() => filters.setHideAcked((prev) => !prev)}>
                  hide acked
                </button>
                <button type="button" className={`choke-chip ${filters.autoScrollTape ? "on" : ""}`} onClick={() => filters.setAutoScrollTape((prev) => !prev)}>
                  auto
                </button>
              </div>
              <div className="choke-tape-spark" aria-label="Decision rate, last 40s">
                <Sparkline bars={bucketizeDecisions(decisions, now, 1, 40)} tone="danger" />
              </div>
            </div>
            {bucketizeDecisions(decisions, now, 1, 1)[0] > 5 && (
              <div className="choke-burst-banner">
                {bucketizeDecisions(decisions, now, 1, 1)[0]} decisions in 1s
                <button type="button" onClick={() => filters.setGroupTape(true)}>Group by exec_id</button>
              </div>
            )}
            <DecisionTape
              refEl={filters.tapeRef}
              rows={filters.groupedDecisions}
              selected={filters.selectedDecisionIds}
              acked={acked}
              onSelect={(id) => filters.setSelectedDecisionIds((prev) => toggleSetValue(prev, id))}
              onDrill={onDrill}
              onFilterExec={filters.setTapeFilterExec}
              filterExec={filters.tapeFilterExec}
              onClearFilterExec={() => filters.setTapeFilterExec(null)}
              onAck={onAck}
              onUnack={onUnack}
              onCopy={onCopy}
            />
          </Panel>
        </section>
      </main>

      {filters.selectedExecs.size > 0 && (
        <div className="choke-bulkbar" data-panel="bulk-action-bar">
          <span>{filters.selectedExecs.size} selected</span>
          {ACTIONS.map((action) => (
            <button
              key={action}
              type="button"
              disabled={writesWithheld}
              title={writesWithheld ? withheldReason || READ_ONLY_TITLE : undefined}
              onClick={() => onBulkAction(action)}
            >
              {action}
            </button>
          ))}
          <button
            type="button"
            disabled={writesWithheld}
            title={writesWithheld ? withheldReason || READ_ONLY_TITLE : undefined}
            onClick={onBulkForget}
          >
            forget
          </button>
          {/* Clearing the selection is not a write, and taking it away would
              strand an operator with a selection they cannot dismiss. */}
          <button type="button" onClick={() => filters.setSelectedExecs(new Set())}>clear</button>
          {withheldReason ? (
            <span className="choke-bulkbar-note">{withheldReason}</span>
          ) : null}
        </div>
      )}

      {/* The Policy Workbench was here, and it is deliberately gone.
          It edited the ChokePolicy DSL (apiVersion: chokegw/v1) and was
          labelled "dry-run · never installs". That was the smaller half of the
          problem. The larger half: what it would have installed does nothing.
          `buckets.rate_per_sec` is parsed, validated and installed into
          tokens.Manager (choke/gateway.go:656) and then read by NOBODY —
          grep for .Allow(/.AllowN( across the tree returns only the three
          self-recursive definitions inside choke/tokens/tokens.go. The kernel
          BPF map is fed from enforce.DefaultThrottlerConfig()
          (gateway.go:631), a compiled-in constant, never from a policy.
          So the DSL has no effect on any host, including the three policies
          that ship in policies/choke/. A better editor for it would have been
          a better editor for nothing.
          The fleet-wide response knob that DOES reach hosts — over the signed,
          acknowledged command channel — is the threshold ladder above. */}
    </>
  );
}
