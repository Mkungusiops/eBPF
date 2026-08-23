/**
 * Containment Command — the shared hero + ladder that front both enforcement
 * surfaces (Choke Gateway, Devices). This is the platform's unique value made
 * visual: graduated, reversible, audited containment. It reads identically on
 * both pages so an operator never relearns it, and it carries a Command lens
 * (operator war-room) and an Assurance lens (executive / board) on one surface.
 */
import { Power, ShieldAlert, ShieldCheck } from "lucide-react";
import type { CSSProperties, ReactNode } from "react";
import { LADDER, LABEL_FOR_RUNG, type Rung } from "./enforcement";
import "./containment.css";

export type ViewMode = "command" | "assurance";

/** Rung colours — the one palette the whole product uses for the state machine. */
export const RUNG_COLOR: Record<Rung, string> = {
  pristine: "#8b98b0",
  throttled: "#6e8bff",
  tarpit: "#f5b13d",
  quarantined: "#fb8c3c",
  severed: "#f4556e"
};

export interface CommandMetrics {
  /** Plural noun for the tracked population: "processes" | "devices". */
  subject: string;
  mode: "detect-only" | "enforcing";
  /**
   * Uncontained targets scoring at/over the first enforcement threshold, or
   * null where this subject cannot measure it.
   *
   * The device plane cannot: nothing scores a device — DeviceSummary carries no
   * score field the way ChokeSummary does — so the surface hardcoded 0. That is
   * not a measurement, and it fed computePosture, where zero threats and N
   * contained produces coverage = 1 and pins the dial at "fully covered" no
   * matter what the estate is doing.
   */
  activeThreats: number | null;
  /** Everything on a rung above pristine (throttled..severed). */
  contained: number;
  tracked: number;
  auditOk: boolean;
  /**
   * False when this deployment cannot verify the chain at all (the fleet
   * control plane does not hash-chain decisions centrally). Distinct from
   * auditOk=false, which means a chain exists and is BROKEN — that is an
   * incident; this is a capability gap, and conflating them either invents a
   * breach or hides one.
   */
  auditSupported?: boolean;
  /** Null where this subject has no audit-row count to report. */
  auditRows: number | null;
  /** Override the integrity tile (defaults to the audit-chain framing). Devices
   *  reuse it as "Data plane" without a second header component. */
  integrityLabel?: string;
  integrityValue?: string;
  integritySub?: string;
  /** Tri-state: null where the deployment cannot read the switch. */
  killSwitched?: boolean | null;
  /** Optional headline stat (e.g. decision rate) shown in the metric strip. */
  headline?: string;
  headlineLabel?: string;
  /** 0..100, or null when a required input is unmeasurable — see computePosture. */
  posture: number | null;
}

/**
 * A single, defensible posture number. Coverage (how much of what needs
 * handling is actually contained) is the spine; enforcing vs detect-only, a
 * broken audit chain, and an engaged kill-switch adjust it. Documented so a
 * buyer's security team can audit the formula rather than trust a magic score.
 */
export function computePosture(m: {
  mode: "detect-only" | "enforcing";
  activeThreats: number | null;
  contained: number;
  auditOk: boolean;
  auditSupported?: boolean;
  killSwitched?: boolean | null;
}): number | null {
  // No threat count, no posture. Substituting zero here is what produced a
  // permanent 100%: the arithmetic below reads "nothing uncontained" as
  // "everything contained", which is only true if the zero was measured.
  if (m.activeThreats === null) return null;
  const needing = m.activeThreats + m.contained;
  const coverage = needing === 0 ? 1 : m.contained / needing;
  let score = 55 + coverage * 45; // 55..100 from containment coverage
  if (m.mode === "detect-only") score -= 22; // watching, not stopping
  // Only a BROKEN chain is a posture penalty. Docking 30 points because this
  // deployment cannot verify centrally would report a capability gap as
  // tampering, and would make the fleet console permanently score worse than
  // the identical single-host one for a reason that is not about the estate.
  if (m.auditSupported !== false && !m.auditOk) score -= 30;
  if (m.killSwitched) score -= 10; // enforcement globally bypassed
  return Math.max(0, Math.min(100, Math.round(score)));
}

// An unmeasured posture is not a good one. "muted" keeps the header from
// painting itself green over a number nobody computed.
function toneForPosture(p: number | null): "good" | "warn" | "bad" | "muted" {
  if (p === null) return "muted";
  return p >= 80 ? "good" : p >= 55 ? "warn" : "bad";
}

function Metric({
  label,
  value,
  sub,
  tone
}: {
  label: string;
  value: ReactNode;
  sub?: string;
  tone?: "good" | "bad" | "accent" | "muted";
}) {
  return (
    <div className={`cc-metric${tone ? ` tone-${tone}` : ""}`}>
      <span className="cc-metric-value">{value}</span>
      <span className="cc-metric-label">{label}</span>
      {sub ? <span className="cc-metric-sub">{sub}</span> : null}
    </div>
  );
}

export function ContainmentCommandHeader({
  metrics,
  viewMode,
  onViewMode,
  onToggleMode,
  onKillSwitch,
  disabled
}: {
  metrics: CommandMetrics;
  viewMode: ViewMode;
  onViewMode: (mode: ViewMode) => void;
  onToggleMode?: () => void;
  onKillSwitch?: () => void;
  disabled?: boolean;
}) {
  const m = metrics;
  const enforcing = m.mode === "enforcing";
  const tone = toneForPosture(m.posture);
  return (
    <section className={`cc-header tone-${tone}`} data-panel="containment-command">
      <div className="cc-head-lead">
        {/* An unknown posture renders as an empty track, not as a number.
            The ring is `conic-gradient(... calc(var(--pct) * 1%) ...)`, so
            interpolating `null` yields calc(null * 1%) — invalid, which drops
            the whole background declaration and takes the ring's track with
            it, not just the fill. Zero is not a substitute either: it would
            read as "posture 0", the opposite of "not measured". */}
        <div
          className={`cc-posture ring-${tone}${m.posture === null ? " ring-unknown" : ""}`}
          style={{ "--pct": `${m.posture ?? 0}` } as CSSProperties}
          title={m.posture === null
            ? "Posture cannot be computed for this subject — nothing scores a device, so there is no threat count to measure coverage against"
            : "Composite containment posture (0–100)"}
        >
          <div className="cc-posture-face">
            <strong>{m.posture === null ? "—" : m.posture}</strong>
            <span>posture</span>
          </div>
        </div>
        <div className="cc-head-title">
          <h2>Containment Command</h2>
          <p>
            {/* "all devices under control" was the worst line on the page: it
                was printed whenever the threat count was zero, and on the
                device plane that zero was hardcoded. The reassurance was
                unconditional. */}
            {m.activeThreats === null
              ? `threat count not measured for ${m.subject}`
              : m.activeThreats > 0
                ? `${m.activeThreats} active threat${m.activeThreats === 1 ? "" : "s"} ${
                    m.activeThreats === 1 ? "needs" : "need"
                  } attention`
                : `all ${m.subject} under control`}
            {m.mode === "detect-only" ? " · detect-only (no containment applied)" : null}
            {m.killSwitched ? " · kill-switch engaged" : null}
          </p>
        </div>
      </div>

      <div className="cc-head-metrics">
        <Metric
          label="Active threats"
          value={m.activeThreats === null ? "—" : m.activeThreats}
          tone={m.activeThreats === null ? "muted" : m.activeThreats > 0 ? "bad" : "good"}
        />
        <Metric label="Contained" value={m.contained} tone="accent" />
        <Metric label={`Tracked ${m.subject}`} value={m.tracked.toLocaleString()} />
        <Metric
          label={m.integrityLabel ?? "Audit chain"}
          value={
            m.integrityValue ??
            (m.auditSupported === false ? "not verified here" : m.auditOk ? "intact" : "BROKEN")
          }
          sub={
            m.integritySub ??
            (m.auditSupported === false
              ? "chained on the agent, not centrally"
              : m.auditRows === null ? "not counted" : `${m.auditRows.toLocaleString()} rows`)
          }
          tone={m.auditSupported === false ? "muted" : m.auditOk ? "good" : "bad"}
        />
        {m.headline ? <Metric label={m.headlineLabel || ""} value={m.headline} tone="muted" /> : null}
      </div>

      <div className="cc-head-controls">
        <div className="cc-viewtoggle" role="tablist" aria-label="View mode">
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "command"}
            className={viewMode === "command" ? "on" : ""}
            onClick={() => onViewMode("command")}
          >
            Command
          </button>
          <button
            type="button"
            role="tab"
            aria-selected={viewMode === "assurance"}
            className={viewMode === "assurance" ? "on" : ""}
            onClick={() => onViewMode("assurance")}
          >
            Assurance
          </button>
        </div>
        {/* The two most consequential controls, grouped as one instrument
            cluster and differentiated by role: the mode control is a STATE
            (amber = watching, green = armed); the kill-switch is a break-glass
            ACTION (danger outline idle, solid red when engaged). */}
        <div className="cc-plane-controls" role="group" aria-label="Containment plane controls">
          <button
            type="button"
            className={`cc-ctl cc-ctl-mode ${enforcing ? "enforcing" : "detect"}`}
            onClick={onToggleMode}
            disabled={disabled || !onToggleMode}
            title={
              enforcing
                ? "Enforcing — decisions are applied to the kernel/network. Click to return to detect-only."
                : "Detect-only — decisions are logged, not applied. Click to arm enforcement."
            }
          >
            {enforcing ? <ShieldCheck size={16} aria-hidden="true" /> : <ShieldAlert size={16} aria-hidden="true" />}
            <span className="cc-ctl-body">
              <span className="cc-ctl-label">Enforcement</span>
              <span className="cc-ctl-value">{enforcing ? "Enforcing" : "Detect-only"}</span>
            </span>
          </button>
          <button
            type="button"
            className={`cc-ctl cc-ctl-kill ${m.killSwitched ? "engaged" : ""}`}
            onClick={onKillSwitch}
            disabled={disabled || !onKillSwitch}
            title={
              m.killSwitched
                ? "Kill-switch engaged — all enforcement is globally bypassed. Click to disengage."
                : "Emergency kill-switch — globally bypass all enforcement."
            }
          >
            <Power size={16} aria-hidden="true" />
            <span className="cc-ctl-body">
              <span className="cc-ctl-label">Emergency</span>
              <span className="cc-ctl-value">{m.killSwitched ? "Engaged" : "Kill-switch"}</span>
            </span>
          </button>
        </div>
      </div>
    </section>
  );
}

export function ContainmentLadder({
  counts,
  activeRung,
  onRungClick,
  subject
}: {
  counts: Record<string, number>;
  activeRung?: string | null;
  onRungClick?: (rung: Rung) => void;
  subject?: string;
}) {
  const contained = LADDER.filter((r) => r !== "pristine").reduce((sum, r) => sum + (counts[r] || 0), 0);
  const clean = counts.pristine || 0;
  const interactive = Boolean(onRungClick);
  return (
    <section className="cc-ladder" data-panel="containment-ladder" aria-label="Containment ladder">
      <div className="cc-ladder-track">
        {LADDER.map((rung, i) => {
          const count = counts[rung] || 0;
          const active = activeRung === rung;
          return (
            <div key={rung} className="cc-ladder-cell">
              {i > 0 ? (
                <span className="cc-ladder-arrow" aria-hidden="true">
                  ›
                </span>
              ) : null}
              <button
                type="button"
                className={`cc-rung${active ? " is-active" : ""}${count > 0 && rung !== "pristine" ? " has-pop" : ""}`}
                style={{ "--rung": RUNG_COLOR[rung] } as CSSProperties}
                onClick={interactive ? () => onRungClick?.(rung) : undefined}
                disabled={!interactive}
                aria-pressed={interactive ? active : undefined}
                title={interactive ? `Filter to ${LABEL_FOR_RUNG[rung]}` : LABEL_FOR_RUNG[rung]}
              >
                <span className="cc-rung-count">{count}</span>
                <span className="cc-rung-label">{LABEL_FOR_RUNG[rung]}</span>
              </button>
            </div>
          );
        })}
      </div>
      <div className="cc-ladder-legend">
        <span className="cc-ladder-escalation">graduated escalation →</span>
        <span className="cc-ladder-summary">
          <strong>{contained}</strong> contained · <strong>{clean}</strong> clean{subject ? ` ${subject}` : ""}
          {interactive ? " · click a rung to filter" : ""}
        </span>
      </div>
    </section>
  );
}
