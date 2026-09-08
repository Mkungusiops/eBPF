/**
 * The host table — one row per configured peer, reachable or not.
 *
 * An unreachable peer keeps its row and its checkbox rather than disappearing:
 * a host that stopped answering is exactly the one an operator needs to see,
 * and dropping it from the table would silently shrink the "All hosts" target
 * set without saying so. Its row collapses to the error the fan-out returned.
 *
 * Drift marks compare each host against the fleet majority. They are advisory —
 * a deliberate one-off configuration drifts too — which is why they annotate the
 * cell rather than gate anything.
 */
import { RefreshCw } from "lucide-react";

import { classifyAudit, deriveFleet, thresholdKey } from "./fleetLogic";
import { PanelTitle } from "./PanelTitle";
import type { FleetKpis } from "./types";

export function FleetHostsPanel({
  rows,
  kpis,
  selected,
  onSelect,
  onSelectAll,
  onClear,
  onRefresh,
  loading
}: {
  rows: ReturnType<typeof deriveFleet>["rows"];
  kpis: FleetKpis;
  selected: Set<string>;
  onSelect: (host: string, checked: boolean) => void;
  onSelectAll: () => void;
  onClear: () => void;
  onRefresh: () => void;
  loading: boolean;
}) {
  return (
    <section className="fleet-panel fleet-panel--table">
      <div className="fleet-panel__head">
        <div>
          <PanelTitle title="Fleet" />
          {/* The same three-state reading as the KPI strip, for the same
              reason: "0 kill-switched" over hosts that reported nothing is a
              claim about enforcement nobody measured, and a drift count over a
              single reporting host can only ever be zero. */}
          <p className="fleet-muted">
            {kpis.healthy}/{kpis.total} reachable · {kpis.enforcing} enforcing · {kpis.killed} kill-switched
            {kpis.killUnknown > 0 ? ` · ${kpis.killUnknown} kill state not reported` : ""}
            {kpis.healthy >= 2 ? ` · ${kpis.drift} drift` : ""}
          </p>
        </div>
        <div className="fleet-toolbar">
          <button
            className="fleet-btn fleet-btn--sm"
            type="button"
            onClick={onSelectAll}
          >
            Select all
          </button>
          <button
            className="fleet-btn fleet-btn--sm"
            type="button"
            onClick={onClear}
          >
            Clear
          </button>
          <button className="fleet-btn fleet-btn--sm" type="button" onClick={onRefresh}>
            <RefreshCw size={14} />
            Refresh
          </button>
        </div>
      </div>
      <FleetTable rows={rows} selected={selected} onSelect={onSelect} loading={loading} />
    </section>
  );
}

function FleetTable({
  rows,
  selected,
  onSelect,
  loading
}: {
  rows: ReturnType<typeof deriveFleet>["rows"];
  selected: Set<string>;
  onSelect: (host: string, checked: boolean) => void;
  loading: boolean;
}) {
  if (loading) {
    return (
      <div className="fleet-table-empty">
        <div className="fleet-skeleton" />
        <div className="fleet-skeleton fleet-skeleton--short" />
      </div>
    );
  }
  if (rows.length === 0) {
    return <div className="fleet-table-empty">No fleet peers configured.</div>;
  }

  return (
    <div className="fleet-table-wrap">
      <table className="fleet-table">
        <thead>
          <tr>
            <th aria-label="Selected" />
            <th>Host</th>
            <th>State</th>
            <th>Mode</th>
            <th>Kill</th>
            <th>Thresholds</th>
            <th>Tracked</th>
            <th>Quarantined</th>
            <th>Tarpit</th>
            <th>Throttled</th>
            <th>Audit</th>
          </tr>
        </thead>
        <tbody>
          {rows.map((row) => {
            const data = row.result?.data;
            if (!row.reachable || !data) {
              return (
                <tr className="is-unreachable" key={row.peer.name}>
                  <td>
                    <input
                      aria-label={`Select ${row.peer.name}`}
                      checked={selected.has(row.peer.name)}
                      type="checkbox"
                      onChange={(event) => onSelect(row.peer.name, event.target.checked)}
                    />
                  </td>
                  <td>
                    <strong>{row.peer.name}</strong>
                    <small>{row.peer.url}</small>
                  </td>
                  <td colSpan={9}>
                    <span className="fleet-pill fleet-pill--danger">unreachable</span>
                    <span className="fleet-row-error">{row.result?.error ?? "no response"}</span>
                  </td>
                </tr>
              );
            }
            const counts = data.counts ?? {};
            const audit = data.audit;
            return (
              <tr className={row.driftMode || row.driftKill || row.driftThresholds ? "has-drift" : ""} key={row.peer.name}>
                <td>
                  <input
                    aria-label={`Select ${row.peer.name}`}
                    checked={selected.has(row.peer.name)}
                    type="checkbox"
                    onChange={(event) => onSelect(row.peer.name, event.target.checked)}
                  />
                </td>
                <td>
                  <strong>{row.peer.name}</strong>
                  <small>{row.peer.url}</small>
                </td>
                <td>
                  {/* Three states, because the servers report three. A host
                      whose kill-switch the control plane cannot read used to
                      get the same green "live" pill as one that answered
                      "off" — the console asserting enforcement is armed on a
                      host that never said so. */}
                  <span
                    className={`fleet-pill ${
                      row.killState === "on"
                        ? "fleet-pill--danger"
                        : row.killState === "off"
                          ? "fleet-pill--good"
                          : "fleet-pill--muted"
                    }`}
                    title={
                      row.killState === "unknown"
                        ? "This host did not report a kill-switch state, so enforcement here is unknown"
                        : undefined
                    }
                  >
                    {row.killState === "on" ? "bypass" : row.killState === "off" ? "live" : "not reported"}
                  </span>
                </td>
                <td>
                  {row.driftMode ? <DriftMark /> : null}
                  <span className={`fleet-pill ${data.mode === "enforcing" ? "fleet-pill--info" : "fleet-pill--muted"}`}>{data.mode ?? "?"}</span>
                </td>
                <td>
                  {row.driftKill ? <DriftMark /> : null}
                  {row.killState === "unknown" ? "not reported" : row.killState}
                </td>
                <td>
                  {row.driftThresholds ? <DriftMark /> : null}
                  {thresholdKey(data.thresholds)}
                </td>
                <td>{data.tracked ?? 0}</td>
                <td>{counts.quarantined ?? 0}</td>
                <td>{counts.tarpit ?? 0}</td>
                <td>{counts.throttled ?? 0}</td>
                <td>
                  {/* The SAME classification the KPI strip counts, from
                      classifyAudit — not a second guess made here. This cell
                      decided "broken" on `bad_at != null`, so a host reporting
                      {ok: false} with no offending index — a BROKEN chain, and
                      one of the auditBroken the strip was counting — rendered
                      as "not maintained": the row said this host keeps no
                      tamper-evidence while the tile above it said its evidence
                      had failed.

                      "not maintained" rather than "—". A dash in a security
                      column is read as missing data on a check that ran; this
                      host chains nothing centrally, which is a stated property
                      of the deployment and not a gap in its evidence. */}
                  {classifyAudit(audit) === "ok" ? (
                    <span className="fleet-pill fleet-pill--good">ok · {audit?.total ?? 0}</span>
                  ) : classifyAudit(audit) === "broken" ? (
                    <span className="fleet-pill fleet-pill--danger">
                      {audit?.bad_at != null ? `broken @${audit.bad_at}` : "broken"}
                    </span>
                  ) : (
                    <span
                      className="fleet-pill fleet-pill--muted"
                      title="This host does not maintain a central hash chain; its agent chains its own decisions"
                    >
                      not maintained
                    </span>
                  )}
                </td>
              </tr>
            );
          })}
        </tbody>
      </table>
    </div>
  );
}

function DriftMark() {
  return (
    <span className="fleet-drift" title="Differs from fleet majority">
      !
    </span>
  );
}
