/**
 * The frame around the device console: the sticky top bar, the live plane-state
 * pills that sit in it, and the banner strip that explains why the plane is not
 * doing what the operator expects.
 *
 * None of this renders device data — it renders the console's own condition.
 * Keeping it out of the route is what lets the route read as "here is what the
 * page is made of" rather than 120 lines of chrome before the first device.
 */
import { AlertTriangle, ArrowLeft, Search, ShieldAlert } from "lucide-react";
import type { ReactNode } from "react";

import type { DeviceDataPlaneState } from "./types";
import { isBridgeMasterWarning, planeIsActive } from "./utils";

export function DevicesTopbar({
  search,
  onSearch,
  state,
  disabledMessage,
  updatedAt
}: {
  search: string;
  onSearch: (value: string) => void;
  state: DeviceDataPlaneState | null;
  disabledMessage: string | null;
  updatedAt: number | null;
}) {
  return (
    /* Uniform platform header: full-width sticky bar — back-to-SOC · brand · mode,
       then status + theme. Mirrors the Choke gateway header standard. */
    <header className="devices-topbar">
      {/* Same header standard as the Choke Gateway: brand cluster · search ·
          status pills — so the two containment surfaces read as one product. */}
      <div className="devices-topbar-row devices-topbar-primary" data-panel="topbar-row-1">
        <div className="devices-brand">
          <a className="devices-back" href="/" title="Back to SOC dashboard">
            <ArrowLeft size={15} aria-hidden="true" />
            <span>SOC</span>
          </a>
          <span className="devices-brand-divider" aria-hidden="true" />
          <h1 className="devices-brand-mark">Device Choke</h1>
        </div>
        <label className="devices-search">
          <Search size={16} aria-hidden="true" />
          <input
            value={search}
            onChange={(event) => onSearch(event.target.value)}
            placeholder="Search devices — MAC, IP, hostname, vendor…"
            aria-label="Search devices"
          />
        </label>
        <PlaneStateStrip state={state} disabledMessage={disabledMessage} updatedAt={updatedAt} />
      </div>
    </header>
  );
}

/**
 * One banner shape for every reason the plane cannot be trusted.
 *
 * `live` is not decoration: the three banners that can appear while the
 * operator is already looking at the page announce themselves, and the dry-run
 * one — which is true from boot and never changes — deliberately does not.
 */
export function DevicesBanner({
  tone = "info",
  live = false,
  title,
  copy
}: {
  tone?: "info" | "warn";
  live?: boolean;
  title: ReactNode;
  copy: ReactNode;
}) {
  return (
    <section className="devices-grid" aria-live={live ? "polite" : undefined}>
      <div className={`devices-banner${tone === "warn" ? " devices-banner--warn" : ""}`}>
        {tone === "warn" ? (
          <AlertTriangle size={19} aria-hidden="true" />
        ) : (
          <ShieldAlert size={19} aria-hidden="true" />
        )}
        <div>
          <strong>{title}</strong>
          <div className="devices-panel-copy">{copy}</div>
        </div>
      </div>
    </section>
  );
}

function PlaneStateStrip({
  state,
  disabledMessage,
  updatedAt
}: {
  state: DeviceDataPlaneState | null;
  disabledMessage: string | null;
  updatedAt: number | null;
}) {
  if (disabledMessage) {
    return (
      <div className="devices-status-cluster">
        <span className="devices-status-pill">
          <span className="devices-status-dot down" />
          plane <strong>disabled</strong>
        </span>
      </div>
    );
  }

  const planeActive = planeIsActive(state?.data_plane);
  const mode = state?.mode ?? "unknown";
  return (
    <div className="devices-status-cluster" aria-label="Device data-plane state">
      {/* Choke-style dot+label status pills — quiet at rest, boxed on hover.
          Enforcement mode leads (amber = detect-only, green = enforcing); the
          header's ENFORCEMENT control remains the actionable toggle. */}
      <span className={`devices-status-pill mode-${mode}`} title={`enforcement mode: ${mode}`}>
        <span className="devices-status-dot" />
        mode <strong>{mode}</strong>
      </span>
      <span
        className="devices-status-pill"
        title="Data-plane actuator: 'noop' = audit only, no kernel enforcement; 'tc' = live TC/eBPF dropping or rate-limiting by MAC."
      >
        <span className={`devices-status-dot${planeActive ? "" : " idle"}`} />
        plane <strong>{state?.data_plane ?? "-"}</strong>
      </span>
      <span
        className="devices-status-pill"
        title="Network interfaces the device-choke BPF program is attached to. 0 = not attached (single-NIC box / no inline bridge)."
      >
        links <strong>{state?.links_attached ?? 0}</strong>
      </span>
      <span
        className={`devices-status-pill${isBridgeMasterWarning(state) ? " is-warn" : ""}`}
        title="Forwarded Ethernet frames the data plane has actually seen. Turns amber if links are up but frames stay 0 — a sign it is attached to a bridge master instead of a slave."
      >
        frames <strong>{state?.frames_seen ?? 0}</strong>
      </span>
      <LiveBeacon updatedAt={updatedAt} />
    </div>
  );
}

// A calm "live" beacon: a steady dot that emits a single radar-style ping ripple
// each time a poll lands fresh data (keyed on updatedAt so the ring re-animates).
// Replaces the old jarring "polling" text flash.
function LiveBeacon({ updatedAt }: { updatedAt: number | null }) {
  return (
    <span className="devices-beacon" title="Live · auto-refreshing" aria-label="Live, auto-refreshing">
      <span className="devices-beacon-core" />
      {updatedAt ? <span className="devices-beacon-ping" key={updatedAt} /> : null}
      <span className="devices-beacon-label">live</span>
    </span>
  );
}
