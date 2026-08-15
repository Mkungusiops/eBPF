/**
 * The fleet console's top bar: identity, poll health, and the links across to
 * the other three consoles.
 *
 * The status readout answers "is what I am looking at current?" — the dot's
 * colour, the label, the refresh cadence and the wall-clock time of the last
 * successful fan-out. "connecting" covers both the pre-first-poll idle state
 * and a poll in flight, because to an operator those are the same thing.
 */
import { ShieldCheck } from "lucide-react";

import type { PollStatus } from "./types";

export function FleetTopbar({
  who,
  pollStatus,
  pollMs,
  lastUpdated
}: {
  who: string;
  pollStatus: PollStatus;
  pollMs: number;
  lastUpdated: Date | null;
}) {
  const statusLabel =
    pollStatus === "connected"
      ? "connected"
      : pollStatus === "disabled"
        ? "disabled"
        : pollStatus === "loading" || pollStatus === "idle"
          ? "connecting"
          : "degraded";

  return (
    <header className="fleet-topbar">
      <div className="fleet-brand">
        <div className="fleet-brand__mark" aria-hidden="true">
          <ShieldCheck size={22} />
        </div>
        <div>
          <div className="fleet-brand__title">Choke Fleet Console</div>
          <div className="fleet-brand__sub">eBPF Threat Gateway · Tier 1</div>
        </div>
      </div>

      <div className="fleet-status" aria-live="polite">
        <span className={`fleet-dot fleet-dot--${pollStatus === "connected" ? "ok" : pollStatus === "disabled" ? "warn" : "err"} ${pollStatus === "connected" ? "fleet-dot--live" : ""}`} />
        <span>{statusLabel}</span>
        <span className="fleet-status__divider" />
        <span>auto-refresh {pollMs / 1000}s</span>
        {lastUpdated ? (
          <>
            <span className="fleet-status__divider" />
            <span>{lastUpdated.toLocaleTimeString([], { hour: "2-digit", minute: "2-digit", second: "2-digit" })}</span>
          </>
        ) : null}
      </div>

      <nav className="fleet-nav" aria-label="Console navigation">
        <a className="fleet-btn fleet-btn--sm" href="/">
          Single Host
        </a>
        <a className="fleet-btn fleet-btn--sm" href="/choke">
          Choke
        </a>
        <a className="fleet-btn fleet-btn--sm" href="/devices">
          Devices
        </a>
        <span className="fleet-btn fleet-btn--sm fleet-btn--active">Fleet</span>
      </nav>

      <div className="fleet-user">
        <span>signed in as</span>
        <strong>{who}</strong>
        <a className="fleet-btn fleet-btn--sm" href="/api/logout">
          Sign out
        </a>
      </div>
    </header>
  );
}
