// Route-wide constants, view-model types and the two set helpers every Choke
// surface shares. Kept apart from utils.ts (pure data functions over the API
// types) because these describe how the CONSOLE is bounded — render caps,
// reachability probes, the layer names — not what the engine reports.
import type { ProcessDetailPayload, SysProcDetail, SysProcEntry } from "./types";

// Render caps. The tracked-process list and the decision tape are both fed by
// unbounded server responses; the caps keep a busy host from rendering tens of
// thousands of rows, and every capped surface says so on screen rather than
// silently truncating.
export const PROC_RENDER_CAP = 300;
export const DECISION_CAP = 400;
export const CIRCUIT_CAP = 2000;

// Probed by the host pill to distinguish "the page is idle" from "the engine
// stopped answering". Deliberately the four endpoints this route depends on.
export const HOST_ENDPOINTS = ["/api/whoami", "/api/choke/state", "/api/choke/circuits", "/api/decisions?limit=1"];

export const PRESET_DESCRIPTIONS: Record<string, string> = {
  containment: "Aggressive thresholds for active incidents: throttle early, sever late.",
  forensic: "Engages kill-switch so evidence is recorded while enforcement is bypassed.",
  maintenance: "Raises thresholds above normal scores for planned maintenance windows.",
  default: "Restores everyday 10/30/60/100 thresholds and normal posture.",
};

/** Which status-pill popover is open, if any. */
export type PopoverName = "host" | "live" | "audit" | "mode" | null;

/** Process drill-in slide-over. */
export type DrillState =
  | { kind: "closed" }
  | { kind: "loading"; execId: string }
  | { kind: "ready"; execId: string; payload: ProcessDetailPayload }
  | { kind: "error"; execId: string; message: string };

/** Live /proc inspection inside the jail picker. */
export type JailDetail =
  | { kind: "closed" }
  | { kind: "loading"; process: SysProcEntry }
  | { kind: "ready"; process: SysProcEntry; detail: SysProcDetail }
  | { kind: "error"; process: SysProcEntry; message: string };

/** SSE health as this route reports it, derived from the shared stream. */
export interface StreamInfo {
  state: "connecting" | "live" | "reconnect" | "down";
  retries: number;
  lastMessageAt: number;
  totalMessages: number;
  messagesByMinute: number[];
}

export function formatWindow(value: number): string {
  if (value < 60) return `${value}m`;
  if (value === 1440) return "24h";
  // Days past a day: 10080 rendered as "168h" is technically true and unreadable.
  if (value % 1440 === 0) return `${value / 1440}d`;
  return `${Math.floor(value / 60)}h`;
}

export function toggleSetValue<T>(set: Set<T>, value: T): Set<T> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}

export function toggleNumber(set: Set<number>, value: number): Set<number> {
  const next = new Set(set);
  if (next.has(value)) next.delete(value);
  else next.add(value);
  return next;
}
