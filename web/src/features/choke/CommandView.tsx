// The Command lens — the operating view. Threat-intelligence ribbon, the
// three-column workbench (engine diagnostics · tracked processes · decision
// tape), the bulk-action bar, and the dry-run policy workbench.
//
// It takes the route's hook bundles rather than forty individual props: the
// view is a projection of the whole route state, and threading each field
// separately would mean a signature nobody reads and a rename in three files
// every time a filter is added.
import type { ChokeAction, CircuitEntry, Thresholds } from "./types";
import { ACTIONS, bucketizeDecisions, countCgroupPids } from "./utils";
import { formatWindow, toggleSetValue } from "./constants";
import type { ChokeData } from "./useChokeData";
import type { useChokeFilters } from "./useChokeFilters";
import type { useChokePosture } from "./useChokePosture";
import type { usePolicyWorkbench } from "./usePolicyWorkbench";
import { MiniPanel, Panel, RankedList, Sparkline, StateLadder } from "./components";
import { BucketList, CgroupTiers, EngineStack, PolicyPreview, ThresholdPanel } from "./panels";
import { ProcessTable } from "./ProcessTable";
import { DecisionTape } from "./DecisionTape";

export function CommandView({
  data,
  filters,
  posture,
  workbench,
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
  workbench: ReturnType<typeof usePolicyWorkbench>;
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
        <MiniPanel title="System Health" meta={chokeState?.audit?.ok === false ? "chain broken" : mode}>
          <div className="choke-kv-mini">
            <span>audit</span><strong>{chokeState?.audit?.ok === false ? "broken" : `${chokeState?.audit?.total || 0} rows`}</strong>
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
            <StateLadder counts={stateCounts} />
          </Panel>
          <ThresholdPanel
            dataPanel="thresholds-panel"
            thresholds={thresholds}
            circuits={circuits}
            disabled={disabled}
            onCommit={onCommitThresholds}
          />
          <Panel dataPanel="cgroup-tiers-panel" title="Cgroup Tiers">
            <CgroupTiers cgroups={cgroups} />
          </Panel>
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
              <input value={filters.procFilter} onChange={(event) => filters.setProcFilter(event.target.value)} placeholder="filter binary, pid, exec_id, origin" />
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
              <input
                className="choke-tape-search"
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
            <button key={action} type="button" onClick={() => onBulkAction(action)}>{action}</button>
          ))}
          <button type="button" onClick={onBulkForget}>forget</button>
          <button type="button" onClick={() => filters.setSelectedExecs(new Set())}>clear</button>
        </div>
      )}

      <section className="choke-policy-workbench" data-panel="policy-workbench">
        <Panel title="Policy Workbench" actions={<span className="choke-muted">dry-run · evaluates against the live snapshot, never installs</span>}>
          <div className="choke-policy-grid">
            <div className="choke-policy-editor">
              <textarea value={workbench.policyYaml} onChange={(event) => workbench.setPolicyYaml(event.target.value)} spellCheck={false} />
              <div className="choke-policy-actions">
                <button className="choke-action-button" type="button" onClick={workbench.insertSamplePolicy}>Insert sample</button>
                <button className="choke-action-button" type="button" onClick={workbench.insertLivePolicy} title="Build a policy from the processes currently tracked so preview returns real matches">Build from live</button>
                <button className="choke-action-button ok" type="button" onClick={() => void workbench.runPolicyPreview()} disabled={disabled || workbench.policyChecking || isFleetConsole} title={isFleetConsole ? engineOnlyHint : undefined}>{workbench.policyChecking ? "Checking…" : "Preview matches"}</button>
              </div>
            </div>
            <PolicyPreview preview={workbench.policyPreview} error={workbench.policyError} checking={workbench.policyChecking} circuits={circuits} />
          </div>
        </Panel>
      </section>
    </>
  );
}
