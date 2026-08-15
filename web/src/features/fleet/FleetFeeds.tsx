/**
 * Decisions and alerts from every peer, merged into one time-ordered rail.
 *
 * Each entry keeps its `_host` because a merged feed without provenance is
 * unusable: "SEVER /usr/bin/curl" means nothing until you know which box it
 * happened on. Rows are keyed on host + timestamp + index rather than
 * timestamp alone — two hosts routinely decide within the same millisecond,
 * and duplicate keys would make React reuse the wrong row.
 */
import { PanelTitle } from "./PanelTitle";
import { actionClass, formatTime, severityTone } from "./fleetLogic";

export function FleetFeedRail({
  decisions,
  alerts
}: {
  decisions: Array<{ _host: string; timestamp?: string; action?: string; binary?: string; reason?: string }>;
  alerts: Array<{ _host: string; timestamp?: string; severity?: string; title?: string; summary?: string; score?: number }>;
}) {
  return (
    <aside className="fleet-feedrail">
      <section className="fleet-panel fleet-feed-panel">
        <div className="fleet-panel__head fleet-panel__head--tight">
          <div>
            <PanelTitle title="Live Decisions" />
            <p className="fleet-muted">merged across the fleet</p>
          </div>
          <span className="fleet-live-label"><span className="fleet-dot fleet-dot--ok fleet-dot--live" /> live</span>
        </div>
        <DecisionFeed decisions={decisions} />
      </section>

      <section className="fleet-panel fleet-alert-panel">
        <div className="fleet-panel__head fleet-panel__head--tight">
          <PanelTitle title="Alerts" />
          <span className="fleet-muted">latest 50</span>
        </div>
        <AlertFeed alerts={alerts} />
      </section>
    </aside>
  );
}

function DecisionFeed({ decisions }: { decisions: Array<{ _host: string; timestamp?: string; action?: string; binary?: string; reason?: string }> }) {
  if (decisions.length === 0) {
    return <div className="fleet-empty">No decisions yet.</div>;
  }
  return (
    <div className="fleet-decision-feed">
      {decisions.map((decision, index) => (
        <div className="fleet-decision-row" key={`${decision._host}-${decision.timestamp ?? index}-${index}`}>
          <span>{formatTime(decision.timestamp)}</span>
          <strong>{decision._host}</strong>
          <em className={`fleet-action ${actionClass(decision.action)}`}>{(decision.action ?? "?").toUpperCase()}</em>
          <p title={`${decision.binary ?? ""} ${decision.reason ?? ""}`}>
            {decision.binary ?? "?"}
            <small>{decision.reason ? ` · ${decision.reason}` : ""}</small>
          </p>
        </div>
      ))}
    </div>
  );
}

function AlertFeed({ alerts }: { alerts: Array<{ _host: string; timestamp?: string; severity?: string; title?: string; summary?: string; score?: number }> }) {
  if (alerts.length === 0) {
    return <div className="fleet-empty">No recent alerts.</div>;
  }
  return (
    <div className="fleet-alerts">
      {alerts.map((alert, index) => (
        <article className="fleet-alert" key={`${alert._host}-${alert.timestamp ?? index}-${index}`}>
          <div>
            <span className={`fleet-pill fleet-pill--${severityTone(alert.severity)}`}>{(alert.severity ?? "info").toUpperCase()}</span>
            <span>{formatTime(alert.timestamp)}</span>
            <strong>{alert._host}</strong>
            {alert.score != null ? <em>score {alert.score}</em> : null}
          </div>
          <p>{alert.title || alert.summary || "(no title)"}</p>
        </article>
      ))}
    </div>
  );
}
