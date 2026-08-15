// View-model vocabulary for the SOC dashboard.
//
// These are the types and constants the dashboard modules agree on: the shapes
// the route derives from a snapshot, the surfaces it can open, and the two
// lookup tables (panel inventory, severity ordering) that would otherwise be
// re-declared in every file that renders a panel header or sorts by severity.
// Nothing here fetches, renders or computes — see analytics.ts and telemetry.ts
// for the derivations and the *Body modules for the surfaces.
import { SOC_PANEL_INVENTORY } from "./panelInventory";
import type { Severity, SocAlert, SocPanelInventoryItem, StreamState } from "./types";

export type AckState = "new" | "ack" | "resolved";
export type SortField = "time" | "severity" | "score";
export type OpenSurface =
  | "policies"
  | "attacks"
  | "graph"
  | "simulator"
  | "mitre"
  | "fleet"
  | "watchlist"
  | "honeypots"
  | "kprobes"
  | "time-machine"
  | "command"
  | "notifications"
  | "profile"
  | "kpi"
  | "help"
  | "export";
export type PillSurface = "live" | "host" | "risk";

export const PANELS = Object.fromEntries(SOC_PANEL_INVENTORY.map((item) => [item.id, item])) as Record<
  string,
  SocPanelInventoryItem
>;

export const SEVERITIES: Severity[] = ["critical", "high", "medium", "low", "info"];
export const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 5,
  high: 4,
  medium: 3,
  low: 2,
  info: 1
};

export const DEFAULT_WATCHLIST = { paths: [] as string[], ips: [] as string[], binaries: [] as string[] };

// The severity ramp the two chart surfaces paint with — the threshold
// simulator's histogram and the Time Machine's severity cells. Shared so the
// same severity never reads as two different colours across the two panels.
export const SIM_SEVERITY_COLOR: Record<Severity, string> = {
  critical: "#f0556b",
  high: "#ff8a4c",
  medium: "#e1b53e",
  low: "#2f81f7",
  info: "#7f8aa3"
};

export interface StreamTelemetry {
  state: StreamState;
  lastMessageAt?: number;
  lastEventAt?: number;
  frames: number;
  error?: string;
}

export interface AlertGroup extends SocAlert {
  groupCount: number;
  members: SocAlert[];
}

export interface TimelineBucket {
  label: string;
  total: number;
  anomaly: boolean;
  counts: Record<Severity, number>;
}

export interface KpiDrill {
  kind: "critical" | "high" | "medium" | "eps" | "procs";
  title: string;
}

export interface ContextMenuState {
  alert: SocAlert;
  x: number;
  y: number;
}

export interface HoverPreviewState {
  alert: SocAlert;
  x: number;
  y: number;
}
