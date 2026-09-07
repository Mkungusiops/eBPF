// Executive summary band: a 5-second posture read for the Head of SOC / CTO / CEO,
// built entirely from signals already computed on the dashboard. Collapsible for
// analysts who live in the queue below.
//
// Everything here is presentation of numbers the route already has — the band
// computes no telemetry of its own. What it does own is the WORDING, which is
// where the honesty rules live: a failing feed must never be narrated as a calm
// estate, and an unmapped server must never be narrated as an unattacked one.
import { BookOpen } from "lucide-react";
import { cx } from "./components";
import { shortGraphLabel } from "./format";

export function postureSeverityClass(label: string) {
  if (label === "critical") return "severity-critical";
  if (label === "high") return "severity-high";
  if (label === "elevated") return "severity-medium";
  return "severity-low";
}

function techniqueId(label: string) {
  return /T\d{4}(?:\.\d+)?/.exec(label)?.[0] || label.split(" ")[0] || "—";
}

function techniqueName(label: string) {
  return label.replace(/^T\d{4}(?:\.\d+)?\s*/, "").trim() || "technique";
}

// `saturated` means the alert RATE is an order of magnitude past half-scale —
// a real reading about the estate, not the old artefact where any tenant with
// more than thirteen criticals pinned the dial at 100 forever. The curve is
// asymptotic, so the dial never actually runs out of room and a worsening
// estate always moves it.
function ExecPostureGauge({
  score,
  label,
  saturated,
  unavailable
}: {
  score: number;
  label: string;
  saturated?: boolean;
  unavailable?: boolean;
}) {
  const radius = 56;
  const centerX = 66;
  const centerY = 66;
  const circumference = Math.PI * radius;
  const filled = unavailable ? 0 : (score / 100) * circumference;
  const arc = `M ${centerX - radius} ${centerY} A ${radius} ${radius} 0 0 1 ${centerX + radius} ${centerY}`;
  return (
    <div className={cx("soc-exec-gauge", postureSeverityClass(label))}>
      <svg
        viewBox="0 0 132 76"
        role="img"
        aria-label={
          unavailable
            ? "Security posture unavailable: the telemetry feed is down"
            : saturated
              ? `Security posture ${label}, sustained extreme alert rate`
              : `Security posture ${label} score ${score} of 100`
        }
      >
        <path className="soc-exec-gauge-track" d={arc} strokeWidth={11} fill="none" strokeLinecap="round" />
        <path
          className="soc-exec-gauge-fill"
          d={arc}
          strokeWidth={11}
          fill="none"
          strokeLinecap="round"
          strokeDasharray={`${filled} ${circumference}`}
        />
      </svg>
      <div className="soc-exec-gauge-readout">
        <strong>{unavailable ? "—" : score}</strong>
        {unavailable ? null : <small>/100</small>}
      </div>
    </div>
  );
}

export function ExecutiveBand({
  open,
  onToggle,
  briefingOpen,
  onToggleBriefing,
  riskScore,
  riskLabel,
  riskDelta,
  riskSaturated,
  riskBaselineRate,
  riskPerHour,
  countsUnfounded,
  countsAreFloor,
  windowLabel,
  totalAlerts,
  openCritical,
  openHigh,
  containmentActions,
  containmentActionsAreFloor,
  topTechnique,
  techniqueMapped,
  eps,
  activeProcesses,
  topProcess,
  affectedScope,
  providerView,
  hostOk,
  streamState,
  onReviewCriticals,
  onOpenRisk
}: {
  open: boolean;
  onToggle: () => void;
  briefingOpen: boolean;
  onToggleBriefing: () => void;
  riskScore: number;
  riskLabel: string;
  riskDelta: number;
  riskSaturated: boolean;
  /** The estate's own typical weighted rate, or null when unknown. */
  riskBaselineRate: number | null;
  /** The rate being scored right now, so the dial's input is on screen. */
  riskPerHour: number;
  /** The alert/event feed is failing, so every count feeding this band is an artefact of the gap. */
  countsUnfounded: boolean;
  /**
   * The alert buffer does not reach back across the whole window, so the counts
   * derived from it are FLOORS.
   *
   * This band mixes two populations and that is not going to change: the
   * posture dial is computed from server-side counts for the full window, while
   * "Needs containment", the alert total and the response count are computed in
   * the browser from a buffer capped at 1000 alerts. On a busy tenant that
   * buffer is about thirty minutes, so a 24h view puts a dial built from ~48,000
   * alerts directly beside a critical count built from the newest 1,000 — two
   * numbers about the same window, differing by a factor of fifty, with nothing
   * saying so.
   *
   * Disclosed rather than hidden, and disclosed HERE rather than only in the
   * notices strip, because this is the panel an executive reads.
   */
  countsAreFloor: boolean;
  windowLabel: string;
  totalAlerts: number;
  openCritical: number;
  openHigh: number;
  containmentActions: number;
  /**
   * The response count is a page of rows rather than a window total, because
   * this deployment does not serve /api/decision-stats. Rendered with a "≥"
   * so a fetch limit is never mistaken for a measurement.
   */
  containmentActionsAreFloor: boolean;
  topTechnique?: { label: string; value: number };
  /** Whether this server supplies any policy→ATT&CK mapping at all. Absent mapping is not the same as no technique observed. */
  techniqueMapped: boolean;
  eps: number;
  activeProcesses: number;
  topProcess?: string;
  /**
   * The estate the numbers in this band describe — see estateSubjectOf.
   *
   * NOT `whoami.host`, which is what it used to be. For a cross-tenant MSOC
   * account the server answers "all tenants" there, so the "What is affected"
   * tile headed a process count drawn from ONE customer with the provider's
   * entire book of business.
   */
  affectedScope?: string;
  /** That account reaches more than one tenant — stated in the DETAIL line, never as the subject. */
  providerView?: boolean;
  hostOk: boolean;
  streamState: string;
  onReviewCriticals: () => void;
  onOpenRisk: () => void;
}) {
  const trend = countsUnfounded ? "flat" : riskDelta > 0 ? "up" : riskDelta < 0 ? "down" : "flat";
  // A delta across a window the console could not load is a measurement of the
  // outage, not of the estate.
  const trendText = countsUnfounded
    ? "trend unavailable — telemetry feed down"
    : riskDelta === 0
      ? `no change vs prior ${windowLabel}`
      : `${riskDelta > 0 ? "+" : ""}${riskDelta} vs prior ${windowLabel}`;
  const postureClass = postureSeverityClass(riskLabel);
  const healthy = hostOk && streamState === "live";
  const priorityCount = openCritical + openHigh;
  const responseGap = Math.max(0, priorityCount - containmentActions);
  const topTechniqueName = topTechnique ? `${techniqueId(topTechnique.label)} ${techniqueName(topTechnique.label)}` : "";
  const readableTopProcess = topProcess ? shortGraphLabel(topProcess, 32) : undefined;
  const leadSignal = topTechniqueName || readableTopProcess || "No dominant technique or process yet";
  const incidentLabel = countsUnfounded
    ? "Telemetry feed down — posture unknown"
    : openCritical
    ? "Critical active incident queue"
    : riskScore >= 45
      ? "High-risk security posture"
      : riskScore >= 18
        ? "Elevated security posture"
        : "No priority incident in the current window";
  const briefingSummary = countsUnfounded
    ? "The console cannot load alerts or events, so it cannot say what is happening. Restore the telemetry feed before drawing any conclusion from this page; what is shown is only what the live stream pushed since the last successful load."
    : openCritical
    ? `${openCritical} critical alert${openCritical === 1 ? "" : "s"} need containment review. Telemetry is ${healthy ? "healthy, so the dashboard can support triage" : "degraded, so treat these counts as incomplete"}.`
    : totalAlerts
      ? `${totalAlerts} alert${totalAlerts === 1 ? "" : "s"} are visible in this window. The next step is to confirm whether any create business or service impact.`
      : "No alerts are visible in this window. Keep monitoring stream health and host reachability.";
  const responseLine = priorityCount
    ? responseGap
      ? `${responseGap} priority item${responseGap === 1 ? "" : "s"} still need containment ownership.`
      : "Response decisions are logged; confirm they map to the open priority items."
    : "No critical or high containment queue is open.";
  const briefingItems = [
    {
      label: "What is happening",
      value: incidentLabel,
      detail: briefingSummary
    },
    {
      label: "Why it matters",
      value: leadSignal,
      detail: topTechnique
        ? `${topTechnique.value} kernel hit${topTechnique.value === 1 ? "" : "s"} since sensor start point to the current threat pattern.`
        : techniqueMapped
          ? "No policy with an ATT&CK mapping fired in this window; use the alert queue and process view to confirm the pattern."
          : "This server publishes no policy→ATT&CK mapping, so technique attribution is unavailable here — not absent from the telemetry."
    },
    {
      label: "What is affected",
      value: affectedScope || "Current SOC host",
      // The reach of the ACCOUNT belongs here and not in the value above: a
      // provider reads this tile to learn whose estate the count came from, and
      // an answer of "all tenants" over one customer's processes is the same
      // false breadth the scope banner exists to deny.
      detail: `${activeProcesses} active process${activeProcesses === 1 ? "" : "es"} observed${readableTopProcess ? `; top signal is ${readableTopProcess}.` : "."}${
        providerView
          ? " Your account reaches more than one customer; this counts only the tenant named above."
          : ""
      }`
    },
    {
      label: "What has been done",
      value: `${containmentActions} response action${containmentActions === 1 ? "" : "s"}`,
      detail: `${responseLine} Host is ${hostOk ? "reachable" : "showing errors"} and stream state is ${streamState}.`
    },
    {
      label: "Next action",
      value: countsUnfounded
        ? "Restore telemetry"
        : openCritical
          ? "Contain criticals first"
          : priorityCount
            ? "Clear high-priority queue"
            : "Keep watch",
      detail: countsUnfounded
        ? "Check the control plane's store connectivity — the read endpoints named in the banner are all store-backed. Triage cannot resume until they answer."
        : openCritical
        ? "Validate true positives, group duplicates, identify asset owner, and execute the safest containment path."
        : priorityCount
          ? "Review high-severity items, confirm scope, and decide whether containment needs approval."
          : "Maintain monitoring and investigate any new spike, asset owner change, or stream degradation."
    }
  ];

  if (!open) {
    return (
      <section className="soc-exec-band is-collapsed" data-panel="exec-summary" aria-label="Executive summary">
        <span className="soc-exec-eyebrow">Executive summary</span>
        <button type="button" className={cx("soc-exec-mini-score", postureClass)} onClick={onOpenRisk} title="View risk breakdown">
          {countsUnfounded ? "—" : riskScore}
          <em>{countsUnfounded ? "unavailable" : riskLabel} · {trendText}</em>
        </button>
        <span className="soc-exec-mini-stat">
          <strong className={openCritical ? "severity-critical" : ""}>
            {countsAreFloor && !countsUnfounded ? "≥" : ""}
            {openCritical}
          </strong>{" "}
          open critical · {countsAreFloor && !countsUnfounded ? "≥" : ""}
          {openHigh} high
        </span>
        <span className={cx("soc-exec-mini-health", healthy ? "is-ok" : "is-warn")}>
          host {hostOk ? "ok" : "degraded"} · stream {streamState}
        </span>
        <button
          type="button"
          className={cx("soc-exec-toggle", "soc-exec-briefing-toggle", briefingOpen && "is-active")}
          onClick={() => {
            if (!briefingOpen) onToggleBriefing();
            onToggle();
          }}
          aria-pressed={briefingOpen}
        >
          <BookOpen size={13} aria-hidden="true" />
          Briefing
        </button>
        <button type="button" className="soc-exec-toggle" onClick={onToggle} aria-expanded={false}>
          Expand
        </button>
      </section>
    );
  }

  return (
    <section className="soc-exec-band" data-panel="exec-summary" aria-label="Executive summary">
      <div className="soc-exec-band-head">
        <span className="soc-exec-eyebrow">Executive summary · live security posture</span>
        <div className="soc-exec-head-actions">
          <button
            type="button"
            className={cx("soc-exec-toggle", "soc-exec-briefing-toggle", briefingOpen && "is-active")}
            onClick={onToggleBriefing}
            aria-pressed={briefingOpen}
          >
            <BookOpen size={13} aria-hidden="true" />
            Briefing
          </button>
          <button type="button" className="soc-exec-toggle" onClick={onToggle} aria-expanded>
            Collapse
          </button>
        </div>
      </div>
      <div className="soc-exec-band-body">
        <button type="button" className="soc-exec-posture" onClick={onOpenRisk} title="View risk breakdown">
          <ExecPostureGauge
            score={riskScore}
            label={riskLabel}
            saturated={riskSaturated && !countsUnfounded}
            unavailable={countsUnfounded}
          />
          <div className="soc-exec-posture-meta">
            <span className="soc-exec-cell-label">Security posture</span>
            <strong className={cx("soc-exec-posture-label", !countsUnfounded && postureClass)}>
              {countsUnfounded ? "unavailable" : riskLabel}
            </strong>
            <span className={cx("soc-exec-trend", `is-${trend}`)}>{trendText}</span>
            {riskSaturated ? (
              <span className="soc-exec-cell-sub">sustained extreme alert rate · check for a noisy source</span>
            ) : null}
            {/* WHAT THE DIAL IS MEASURED AGAINST.
                The score is relative to this estate's own typical rate, which
                means a chronically bad estate reads "normal". That trade is
                acceptable only while the absolute rate and the baseline are on
                screen beside it — a relative number whose reference is hidden
                is one nobody can check. When there is too little history the
                dial falls back to a fixed scale and says so, rather than
                implying a baseline it does not have. */}
            {!countsUnfounded ? (
              <span className="soc-exec-cell-sub">
                {riskBaselineRate === null
                  ? `${Math.round(riskPerHour)} weighted alerts/hr · fixed scale (not enough history for a baseline)`
                  : `${Math.round(riskPerHour)} weighted alerts/hr vs ${Math.round(riskBaselineRate)}/hr typical here`}
              </span>
            ) : null}
          </div>
        </button>
        <div className="soc-exec-cells">
          <button type="button" className="soc-exec-cell is-action" onClick={onReviewCriticals}>
            <span className="soc-exec-cell-label">Needs containment</span>
            <strong className={openCritical ? "severity-critical" : ""}>
              {countsAreFloor && !countsUnfounded ? "≥" : ""}
              {openCritical}
            </strong>
            {/* The "≥" is the whole point. This cell counts the browser's alert
                buffer; the dial to its left is computed server-side over the
                full window. Without the marker the two read as one measurement. */}
            <span className="soc-exec-cell-sub">
              {countsAreFloor && !countsUnfounded
                ? `≥${openHigh} high-sev also open · buffer covers part of this ${windowLabel} · review →`
                : `${openHigh} high-sev also open · review →`}
            </span>
          </button>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Response actions</span>
            {/* Counted server-side over the whole window when the deployment
                serves /api/decision-stats. Where it does not, this falls back
                to counting a 200-row browser page — which on a busy host spans
                minutes, so the cell reported exactly 200 for every window at
                least that long. A fetch limit is not a measurement, so the
                fallback is marked "≥" rather than printed as a total. */}
            <strong>{containmentActionsAreFloor ? `≥${containmentActions}` : containmentActions}</strong>
            <span className="soc-exec-cell-sub">
              {containmentActionsAreFloor
                ? `containment decisions held for this ${windowLabel} · page-limited`
                : `containment decisions in this ${windowLabel}`}
            </span>
          </div>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Top technique</span>
            <strong className="soc-exec-cell-tech">{topTechnique ? techniqueId(topTechnique.label) : techniqueMapped ? "—" : "n/a"}</strong>
            <span className="soc-exec-cell-sub">
              {/* "hits" are Tetragon's per-policy NPOST — a counter that has
                  been running since the sensor started, NOT alerts in the
                  window this band otherwise describes. Sitting unqualified
                  beside 5-minute tiles it read as "115 alerts in five
                  minutes" against a window holding 17. The window is named so
                  the number cannot be misread as one. */}
              {topTechnique
                ? `${topTechnique.value} kernel hit${topTechnique.value === 1 ? "" : "s"} since sensor start · ${techniqueName(topTechnique.label)}`
                : techniqueMapped
                  ? "no techniques in window"
                  : "no ATT&CK mapping from this server"}
            </span>
          </div>
          <div className="soc-exec-cell">
            <span className="soc-exec-cell-label">Throughput</span>
            <strong>
              {eps.toFixed(1)}
              <small>/s</small>
            </strong>
            <span className="soc-exec-cell-sub">{activeProcesses} processes seen</span>
          </div>
          <div className="soc-exec-cell">
            {/* "Telemetry", not "Operations". This measures whether the data is
                arriving — endpoints answering, stream live — and nothing about
                whether the estate is secure. Under the old label an executive
                read "Operations: Healthy" on a box with thousands of open
                criticals, because the feed was fine. */}
            <span className="soc-exec-cell-label">Telemetry</span>
            <strong className={cx("soc-exec-health", healthy ? "is-ok" : "is-warn")}>{healthy ? "Healthy" : hostOk ? "Degraded" : "Check"}</strong>
            <span className="soc-exec-cell-sub">host {hostOk ? "reachable" : "errors"} · stream {streamState}</span>
          </div>
        </div>
      </div>
      {briefingOpen ? (
        <div className="soc-briefing" aria-label="Briefing mode">
          <div className="soc-briefing-summary">
            <div>
              <span className="soc-exec-cell-label">Briefing mode</span>
              <strong>{incidentLabel}</strong>
            </div>
            <p>{briefingSummary}</p>
          </div>
          <div className="soc-briefing-grid">
            {briefingItems.map((item) => (
              <section key={item.label} className="soc-briefing-item">
                <span>{item.label}</span>
                <strong>{item.value}</strong>
                <p>{item.detail}</p>
              </section>
            ))}
          </div>
          <div className="soc-briefing-lenses" aria-label="Briefing decision lenses">
            <div>
              <span>Business impact</span>
              <p>Confirm affected services, data exposure, customer impact, and whether executive escalation is required.</p>
            </div>
            <div>
              <span>Technical scope</span>
              <p>Map hosts, accounts, processes, and recent changes before isolation, credential rotation, or rollback.</p>
            </div>
            <div>
              <span>Response execution</span>
              <p>Validate true positives, group duplicate alerts, assign owners, and remove blockers from containment.</p>
            </div>
          </div>
        </div>
      ) : null}
    </section>
  );
}
