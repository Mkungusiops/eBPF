// The Assurance lens: the same live containment data, read for a CISO/board —
// posture with a transparent breakdown, control effectiveness, audit-chain
// integrity, enforcement + reversibility, and one-click board-ready evidence.
//
// The printable report this view exports is built by buildAssuranceReportHtml
// in ChokeRoute.tsx; both read the same CommandMetrics so the page and the PDF
// can never disagree about posture.
import type { CommandMetrics } from "../common/ContainmentCommand";
import type { Decision, Thresholds } from "./types";
import { formatWindow } from "./constants";
import { basename } from "./utils";
import { Sparkline } from "./components";

function DriverPill({ label, value, good }: { label: string; value: string; good: boolean }) {
  return (
    <div className={`choke-assur-driver ${good ? "good" : "warn"}`}>
      <span>{label}</span>
      <strong>{value}</strong>
    </div>
  );
}

export function AssuranceView({
  metrics,
  thresholds,
  decisions,
  windowMin,
  topBinaries,
  velocityBuckets,
  auditHash,
  onVerifyAudit,
  onCopyAudit,
  onExport
}: {
  metrics: CommandMetrics;
  thresholds: Thresholds;
  decisions: Decision[];
  windowMin: number;
  topBinaries: Array<{ key: string; count: number }>;
  velocityBuckets: number[];
  auditHash?: string;
  onVerifyAudit: () => void;
  onCopyAudit: () => void;
  onExport: (kind: "report" | "bundle") => void;
}) {
  const needing = metrics.activeThreats + metrics.contained;
  const coverage = needing === 0 ? 100 : Math.round((metrics.contained / needing) * 100);
  const postureTone = metrics.posture >= 80 ? "good" : metrics.posture >= 55 ? "warn" : "bad";
  const enforcing = metrics.mode === "enforcing";
  const hashShort = auditHash ? `${auditHash.slice(0, 24)}…` : "—";
  return (
    <section className="choke-assurance" data-panel="assurance-view">
      <div className="choke-assur-grid">
        <article className={`choke-assur-card span2 tone-${postureTone}`}>
          <header>
            <h3>Security posture</h3>
            <span className="choke-assur-score">
              {metrics.posture}
              <small>/100</small>
            </span>
          </header>
          <div className="choke-assur-drivers">
            <DriverPill label="Containment coverage" value={`${coverage}%`} good={coverage >= 80} />
            <DriverPill label="Enforcement" value={enforcing ? "Enforcing" : "Detect-only"} good={enforcing} />
            {/* Three states, not two. The control plane does not hash-chain
                centrally — each agent chains its own decisions — so `supported:
                false` means "not maintained here", NOT "broken". Collapsing
                them told a fleet operator their tamper-evidence had failed,
                which is both false and alarming. */}
            <DriverPill
              label="Audit chain"
              value={metrics.auditSupported === false ? "Not verified here" : metrics.auditOk ? "Intact" : "Broken"}
              good={metrics.auditSupported === false ? true : metrics.auditOk}
            />
            <DriverPill label="Kill-switch" value={metrics.killSwitched ? "Engaged" : "Standby"} good={!metrics.killSwitched} />
          </div>
          <p className="choke-assur-note">
            Posture is containment coverage adjusted for enforcement mode, audit-chain integrity and kill-switch state.
            {enforcing ? "" : " Switch to Enforcing to apply decisions to the kernel and lift this score."}
          </p>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Control effectiveness</h3>
          </header>
          <div className="choke-assur-bigstat">
            <strong>{coverage}%</strong>
            <span>threats contained</span>
          </div>
          <div className="choke-assur-bar">
            <span style={{ width: `${coverage}%` }} />
          </div>
          <div className="choke-assur-kv">
            <span>Contained</span>
            <strong>{metrics.contained}</strong>
            <span>Active threats</span>
            <strong className={metrics.activeThreats ? "danger" : ""}>{metrics.activeThreats}</strong>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Audit integrity</h3>
          </header>
          <div className={`choke-assur-audit ${metrics.auditOk ? "ok" : "bad"}`}>
            {metrics.auditOk ? "Chain intact" : "CHAIN BROKEN"}
          </div>
          <div className="choke-assur-kv">
            <span>Records</span>
            <strong>{metrics.auditRows.toLocaleString()}</strong>
          </div>
          <code className="choke-assur-hash" title={auditHash || ""}>
            {hashShort}
          </code>
          <div className="choke-assur-actions">
            <button type="button" className="choke-action-button" onClick={onVerifyAudit}>
              Verify chain
            </button>
            <button type="button" className="choke-action-button" onClick={onCopyAudit}>
              Copy head
            </button>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Enforcement &amp; reversibility</h3>
          </header>
          <div className="choke-assur-kv wide">
            <span>Mode</span>
            <strong>{enforcing ? "Enforcing" : "Detect-only"}</strong>
            <span>Throttle ≥</span>
            <strong>{thresholds.throttle_at}</strong>
            <span>Tarpit ≥</span>
            <strong>{thresholds.tarpit_at}</strong>
            <span>Quarantine ≥</span>
            <strong>{thresholds.quarantine_at}</strong>
            <span>Sever ≥</span>
            <strong>{thresholds.sever_at}</strong>
            <span>Auto-revert</span>
            <strong>available</strong>
          </div>
        </article>

        <article className="choke-assur-card">
          <header>
            <h3>Containment activity · {formatWindow(windowMin)}</h3>
          </header>
          <div className="choke-assur-bigstat">
            <strong>{decisions.length}</strong>
            <span>decisions</span>
          </div>
          <Sparkline bars={velocityBuckets} tone="accent" />
          <ul className="choke-assur-top">
            {topBinaries.length === 0 ? (
              <li className="choke-muted">no decisions in window</li>
            ) : (
              topBinaries.map((b) => (
                <li key={b.key}>
                  <span className="truncate">{basename(b.key)}</span>
                  <strong>{b.count}</strong>
                </li>
              ))
            )}
          </ul>
        </article>

        <article className="choke-assur-card span2 choke-assur-export">
          <header>
            <h3>Board-ready evidence</h3>
          </header>
          <p>
            Export a point-in-time containment summary for leadership, audit, or cyber-insurance — every figure is
            backed by the tamper-evident decision chain.
          </p>
          <div className="choke-assur-actions">
            <button type="button" className="choke-action-button ok" onClick={() => onExport("report")}>
              Board report
            </button>
            <button type="button" className="choke-action-button" onClick={() => onExport("bundle")}>
              Evidence bundle (JSON)
            </button>
          </div>
        </article>
      </div>
    </section>
  );
}
