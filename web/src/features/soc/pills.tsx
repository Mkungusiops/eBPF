// The three popover bodies behind the top-bar pills: stream health, host
// reachability, and the risk breakdown. Each answers the one question the pill
// itself can only hint at.
import { useMemo } from "react";
import { socIdentityOf } from "./api";
import { InlineNotice, MetricTile } from "./components";
import { estateSubjectOf } from "./pdf";
import { RiskGauge } from "./panels";
import type { StreamTelemetry } from "./dashboard";
import type { Severity, SocAlert, SocSnapshot } from "./types";

export function PillLiveContent({
  stream,
  staleSeconds,
  onReconnect
}: {
  stream: StreamTelemetry;
  staleSeconds?: number;
  onReconnect: () => void;
}) {
  return (
    <div className="soc-popover-body">
      <MetricTile label="State" value={stream.state} />
      <MetricTile label="Frames" value={stream.frames} />
      <MetricTile label="Last message" value={staleSeconds === undefined ? "never" : `${staleSeconds}s ago`} />
      {stream.error ? <InlineNotice tone="warn" title="Stream note">{stream.error}</InlineNotice> : null}
      <button type="button" onClick={onReconnect}>
        Reconnect
      </button>
    </div>
  );
}

export function PillHostContent({
  whoami,
  errors,
  statuses,
  onRefresh
}: {
  whoami: SocSnapshot["whoami"];
  errors: Record<string, string>;
  statuses: Record<string, number | undefined>;
  onRefresh: () => void;
}) {
  // The same two facts the host pill carries, in the popover the pill opens.
  // `whoami.host` is an IDENTITY — for a cross-tenant account the server
  // answers "all tenants", because the account belongs to no tenant — and the
  // endpoint statuses listed below it are reads of exactly one customer's data.
  // Left on its own the row read as the scope of everything under it, so the
  // tenant those reads actually resolve to is named beside it.
  const identity = socIdentityOf(whoami);
  const estate = estateSubjectOf(whoami);
  return (
    <div className="soc-popover-body">
      <div className="soc-popover-kv">
        <div>
          <span>User</span>
          <strong>{whoami.user}{identity.crossTenant ? " · cross-tenant account" : ""}</strong>
        </div>
        <div>
          <span>Host</span>
          <strong>{whoami.host}</strong>
        </div>
        {identity.crossTenant ? (
          <div>
            <span>Showing</span>
            <strong>{estate.subject} only</strong>
          </div>
        ) : null}
      </div>
      <div className="soc-endpoint-list">
        {Object.entries(statuses).map(([key, status]) => (
          <span key={key}>
            <code>{key}</code>
            <em>{status || "n/a"}</em>
          </span>
        ))}
      </div>
      {Object.keys(errors).length ? <InlineNotice tone="warn" title="Endpoint errors">{Object.keys(errors).join(", ")}</InlineNotice> : null}
      <button type="button" onClick={onRefresh}>
        Probe now
      </button>
    </div>
  );
}

export function PillRiskContent({
  counts,
  riskScore,
  riskPerHour,
  alerts,
  windowLabel
}: {
  counts: Record<Severity, number>;
  riskScore: number;
  riskPerHour: number;
  alerts: SocAlert[];
  windowLabel: string;
}) {
  const contributors = useMemo(
    () =>
      [...alerts]
        .filter((alert) => alert.severity === "critical" || alert.severity === "high")
        .sort((a, b) => b.score - a.score)
        .slice(0, 5)
        .map((alert) => ({ title: alert.title, score: alert.score, severity: alert.severity })),
    [alerts]
  );
  return (
    <div className="soc-popover-body soc-popover-risk">
      <RiskGauge score={riskScore} ratePerHour={riskPerHour} counts={counts} contributors={contributors} window={windowLabel} />
    </div>
  );
}
