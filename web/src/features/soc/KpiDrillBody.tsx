// What sits behind a KPI tile when an operator clicks it. Three shapes: the
// ingestion-rate drill, the process drill, and the per-severity alert drill.
import { EmptyState, Sparkline } from "./components";
import { topProcessRows } from "./analytics";
import { formatTime, shortId } from "./format";
import { MiniBarList } from "./rows";
import { KpiStat } from "./tiles";
import { aggregateEventProcesses, aggregateEventTypes, eventSpark, eventsPerSecond } from "./telemetry";
import type { AckState, KpiDrill } from "./dashboard";
import type { SocAlert, SocEvent } from "./types";

export function KpiDrillBody({
  drill,
  alerts,
  events,
  ackStates,
  now
}: {
  drill: KpiDrill | null;
  alerts: SocAlert[];
  events: SocEvent[];
  ackStates: Record<string, AckState>;
  now: number;
}) {
  if (!drill) return <EmptyState title="No KPI selected" />;
  if (drill.kind === "eps") {
    const spark = eventSpark(events, now);
    const total60 = spark.reduce((sum, value) => sum + value, 0);
    const byProcess = aggregateEventProcesses(events).slice(0, 5);
    const byType = aggregateEventTypes(events);
    return (
      <div className="soc-kpi-drill">
        <div className="soc-kpi-stat-grid">
          <KpiStat label="Current" value={eventsPerSecond(events, now).toFixed(1)} meta="events/sec" />
          <KpiStat label="Last 60s" value={total60} meta="events ingested" />
          <KpiStat label="Peak" value={Math.max(0, ...spark)} meta="events / 5s bucket" />
          <KpiStat label="Live buffer" value={events.length} meta="events in view" />
        </div>
        <section className="soc-kpi-panel">
          <h3>Last 60 seconds</h3>
          <Sparkline values={spark} tone="accent" />
        </section>
        <section className="soc-kpi-panel">
          <h3>Top emitting binaries</h3>
          <MiniBarList rows={byProcess.map((row) => ({ label: row.label, value: row.value, meta: `${row.value} events` }))} empty="No emitting binaries in this window." />
        </section>
        <section className="soc-kpi-breakdown">
          {byType.map((row) => (
            <div key={row.label}>
              <strong>{row.value}</strong>
              <span>{row.label}</span>
            </div>
          ))}
        </section>
      </div>
    );
  }
  if (drill.kind === "procs") {
    const rows = topProcessRows(alerts);
    const uniqueBinaries = new Set(rows.map((row) => row.process)).size;
    const flagged = rows.filter((row) => row.count > 0).length;
    const avgEvents = rows.length ? (events.length / rows.length).toFixed(1) : "0";
    return (
      <div className="soc-kpi-drill">
        <div className="soc-kpi-stat-grid">
          <KpiStat label="Unique exec_ids" value={new Set(alerts.map((alert) => alert.execId || alert.id)).size} meta="with alert signal" />
          <KpiStat label="Distinct binaries" value={uniqueBinaries} meta="unique paths" />
          <KpiStat label="Flagged" value={flagged} meta="with at least 1 alert" />
          <KpiStat label="Avg events" value={avgEvents} meta="per process" />
        </div>
        <section className="soc-kpi-panel">
          <h3>Top processes</h3>
          <div className="soc-kpi-table">
            <div><span>Binary</span><span>Events</span><span>Alerts</span><span>Max score</span><span>Exec ID</span></div>
            {rows.slice(0, 25).map((row) => (
              <div key={row.execId || row.process}>
                <strong>{row.process}</strong>
                <span>{events.filter((event) => (event.execId && event.execId === row.execId) || event.process === row.process).length}</span>
                <span>{row.count}</span>
                <span>{row.score}</span>
                <code>{shortId(row.execId || row.process)}</code>
              </div>
            ))}
          </div>
        </section>
      </div>
    );
  }
  const scopedAlerts = alerts.filter((alert) => alert.severity === drill.kind);
  const ackCounts = scopedAlerts.reduce(
    (acc, alert) => {
      const state = ackStates[alert.id] || "new";
      acc[state] += 1;
      return acc;
    },
    { new: 0, ack: 0, resolved: 0 }
  );
  const topRows = topProcessRows(scopedAlerts);
  return (
    <div className="soc-kpi-drill">
      <div className="soc-kpi-stat-grid">
        <KpiStat label="Total" value={scopedAlerts.length} meta="in current view" tone={drill.kind} />
        <KpiStat label="Unack" value={ackCounts.new} meta="needs triage" />
        <KpiStat label="Acked" value={ackCounts.ack} meta="acknowledged" />
        <KpiStat label="Resolved" value={ackCounts.resolved} meta="closed" />
      </div>
      <section className="soc-kpi-panel">
        <h3>Top originating processes</h3>
        <MiniBarList rows={topRows.map((row) => ({ label: row.process, value: row.score, meta: `${row.count} alerts` }))} empty="No originating processes in this bucket." />
      </section>
      <section className="soc-kpi-panel">
        <h3>Top 10 by score</h3>
        <div className="soc-kpi-table">
          <div><span>Time</span><span>Score</span><span>Title</span><span>State</span></div>
          {scopedAlerts.slice(0, 10).map((alert) => (
            <div key={alert.id}>
              <span>{formatTime(alert.timestamp)}</span>
              <strong className={`severity-${alert.severity}`}>{alert.score}</strong>
              <span>{alert.title}</span>
              <span>{ackStates[alert.id] || "new"}</span>
            </div>
          ))}
        </div>
      </section>
    </div>
  );
}
