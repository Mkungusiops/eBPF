export type ApplyMode = "all" | "sel";
export type PollStatus = "idle" | "loading" | "connected" | "degraded" | "disabled";
export type PresetName = "default" | "containment" | "forensic" | "maintenance";
export type ToastKind = "ok" | "warn" | "err";

export interface FleetPeer {
  name: string;
  url: string;
}

export interface HostResult<T = unknown> {
  name: string;
  url?: string;
  ok: boolean;
  status?: number;
  data?: T;
  error?: string;
}

export interface FleetEnvelope<T> {
  hosts: Array<HostResult<T>>;
}

export interface Thresholds {
  throttle_at: number;
  tarpit_at: number;
  quarantine_at: number;
  sever_at: number;
}

export interface ChokeCounts {
  pristine?: number;
  throttled?: number;
  tarpit?: number;
  quarantined?: number;
  severed?: number;
}

export interface AuditState {
  ok?: boolean;
  total?: number;
  bad_at?: number;
}

export interface ChokeState {
  mode?: string;
  dry_run?: boolean;
  kill_switched?: boolean;
  tracked?: number;
  counts?: ChokeCounts;
  thresholds?: Thresholds;
  audit?: AuditState;
}

export type CgroupSnapshot = Record<string, unknown[] | null | undefined>;

export interface Decision {
  timestamp?: string;
  action?: string;
  binary?: string;
  reason?: string;
  score?: number;
  exec_id?: string;
  pid?: number;
  [key: string]: unknown;
}

export interface Alert {
  timestamp?: string;
  severity?: string;
  title?: string;
  summary?: string;
  score?: number;
  exec_id?: string;
  policy?: string;
  [key: string]: unknown;
}

export interface FleetDevice {
  mac?: string;
  device_id?: string;
  hostname?: string;
  state?: string;
  protected?: boolean;
  [key: string]: unknown;
}

export interface FleetStateSnapshot {
  peers: FleetPeer[];
  states: Array<HostResult<ChokeState>>;
  cgroups: Array<HostResult<CgroupSnapshot>>;
  decisions: Array<HostResult<Decision[]>>;
  alerts: Array<HostResult<Alert[]>>;
  devices: Array<HostResult<FleetDevice[]>>;
}

export interface DriftResult {
  mode: string | null;
  kill: "on" | "off" | null;
  thresholds: string | null;
}

export interface RowModel {
  peer: FleetPeer;
  result?: HostResult<ChokeState>;
  reachable: boolean;
  driftMode: boolean;
  driftKill: boolean;
  driftThresholds: boolean;
}

export interface FleetKpis {
  total: number;
  healthy: number;
  enforcing: number;
  killed: number;
  drift: number;
  auditOk: number;
  auditTotal: number;
  tracked: number;
  quarantined: number;
  tarpit: number;
  throttled: number;
  deviceHosts: number;
  devices: number;
}

export interface DerivedFleet {
  rows: RowModel[];
  kpis: FleetKpis;
  drift: DriftResult;
  majorityThresholds: Thresholds | null;
}

export interface ToastMessage {
  id: number;
  kind: ToastKind;
  title: string;
  body?: string;
}

export interface ConfirmState {
  title: string;
  body: string;
  tone?: "default" | "danger";
  confirmLabel?: string;
  reasonLabel?: string;
  reasonRequired?: boolean;
  defaultReason?: string;
  onConfirm: (reason: string) => void | Promise<void>;
}
