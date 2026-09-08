// The three popover bodies behind the top-bar pills: stream health, host
// reachability, and the risk breakdown. Each answers the one question the pill
// itself can only hint at.
import { useMemo } from "react";
import { socIdentityOf, useSelectedTenant } from "./api";
import { InlineNotice, MetricTile } from "./components";
import { estateSubjectOf } from "./pdf";
import { RiskGauge } from "./panels";
import type { StreamTelemetry } from "./dashboard";
import type { Severity, SocAlert, SocSnapshot } from "./types";

/**
 * The live tail, and what these three tiles are counting.
 *
 * They describe THE CUSTOMER ON SCREEN, with nothing extra to say about scope,
 * because the connection is opened through the same scoping step as every other
 * request and a switch tears it down and re-opens it for the customer now
 * selected (lib/stream.tsx). This popover used to carry a "live tail held back"
 * notice for the period when that was not true: the socket was opened without a
 * tenant, kept delivering the account's default customer, and SocRoute dropped
 * its frames rather than merge one customer's alerts into another's queue. The
 * stream is scoped now, the frames are the selected customer's by the time they
 * arrive, and nothing is dropped — so the notice, and the prop that fed it, are
 * gone rather than left to describe a mechanism that no longer exists.
 *
 * The counters restart at zero on a switch, because the connection they count
 * is a new one. That is the honest reading: none of the frames behind the
 * previous number were this customer's.
 */
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
  // WHO CHOSE THE CUSTOMER. Both answers are legitimate — the operator picked
  // one in the switcher, or the server resolved this account's default — but
  // they are not the same fact, and an operator reading an empty dashboard
  // needs to know which of the two put them there.
  const chosenHere = Boolean(useSelectedTenant());
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
        {identity.crossTenant ? (
          <div>
            <span>Scope</span>
            <strong>{chosenHere ? "the customer you selected" : "this server’s default for your account"}</strong>
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
