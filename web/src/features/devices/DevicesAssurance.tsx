/**
 * Assurance lens for the network plane — the device equivalent of the Choke
 * Gateway's, read for a CISO/board: posture with a transparent breakdown,
 * network reach, reversible data-plane integrity, and board-ready evidence.
 */
import { type CommandMetrics } from "../common/ContainmentCommand";
import { LADDER } from "../common/enforcement";
import type { DeviceDataPlaneState } from "./types";

export function DevicesAssuranceView({
  metrics,
  counts,
  state,
  protectedCount,
  onExport
}: {
  metrics: CommandMetrics;
  counts: Record<string, number>;
  state: DeviceDataPlaneState | null;
  protectedCount: number;
  onExport: (kind: "report" | "bundle") => void;
}) {
  const needing = metrics.activeThreats + metrics.contained;
  const coverage = needing === 0 ? 100 : Math.round((metrics.contained / needing) * 100);
  const postureTone = metrics.posture >= 80 ? "good" : metrics.posture >= 55 ? "warn" : "bad";
  const enforcing = metrics.mode === "enforcing";
  const planeOk = metrics.auditOk;
  return (
    <section className="devices-grid">
      <div className="cc-assur-grid">
        <article className={`cc-assur-card span2 tone-${postureTone}`}>
          <header>
            <h3>Network posture</h3>
            <span className="cc-assur-score">
              {metrics.posture}
              <small>/100</small>
            </span>
          </header>
          <div className="cc-assur-drivers">
            <div className={`cc-assur-driver ${coverage >= 80 ? "good" : "warn"}`}>
              <span>Containment coverage</span>
              <strong>{coverage}%</strong>
            </div>
            <div className={`cc-assur-driver ${enforcing ? "good" : "warn"}`}>
              <span>Enforcement</span>
              <strong>{enforcing ? "Enforcing" : "Detect-only"}</strong>
            </div>
            <div className={`cc-assur-driver ${planeOk ? "good" : "warn"}`}>
              <span>Data plane</span>
              <strong>{planeOk ? "Active" : "Offline"}</strong>
            </div>
            <div className={`cc-assur-driver ${metrics.killSwitched ? "warn" : "good"}`}>
              <span>Kill-switch</span>
              <strong>{metrics.killSwitched ? "Engaged" : "Standby"}</strong>
            </div>
          </div>
          <p className="cc-assur-note">
            Network-plane posture reflects how much of the tracked device population is contained, adjusted for
            enforcement mode and data-plane health.
            {enforcing ? "" : " Switch to Enforcing to apply drop/throttle rules at the link layer."}
          </p>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Network reach</h3>
          </header>
          <div className="cc-assur-kv wide">
            <span>Devices tracked</span>
            <strong>{metrics.tracked.toLocaleString()}</strong>
            <span>Links attached</span>
            <strong>{state?.links_attached ?? 0}</strong>
            <span>Frames seen</span>
            <strong>{(state?.frames_seen ?? 0).toLocaleString()}</strong>
            <span>Protected assets</span>
            <strong>{protectedCount}</strong>
          </div>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Data-plane integrity</h3>
          </header>
          <div className={`cc-assur-audit ${planeOk ? "ok" : "bad"}`}>{planeOk ? "Plane active" : "PLANE OFFLINE"}</div>
          <p className="cc-assur-note">
            Every device choke is a reversible drop/throttle rule — sever cuts a device off the network, thaw restores
            it. Quarantine still permits DHCP/DNS so a device can always recover.
          </p>
        </article>

        <article className="cc-assur-card">
          <header>
            <h3>Containment ladder</h3>
          </header>
          <ul className="cc-assur-top">
            {LADDER.map((r) => (
              <li key={r}>
                <span>{r}</span>
                <strong>{counts[r] || 0}</strong>
              </li>
            ))}
          </ul>
        </article>

        <article className="cc-assur-card span2 cc-assur-export">
          <header>
            <h3>Board-ready evidence</h3>
          </header>
          <p>
            Export a point-in-time network-containment summary — device inventory, ladder state and data-plane
            health — for leadership, audit, or cyber-insurance.
          </p>
          <div className="cc-assur-actions">
            <button type="button" className="devices-button devices-button--primary" onClick={() => onExport("report")}>
              Board report
            </button>
            <button type="button" className="devices-button" onClick={() => onExport("bundle")}>
              Evidence bundle (JSON)
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}
