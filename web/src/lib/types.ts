export type Severity = "critical" | "high" | "medium" | "low" | "info";
export type ChokeState = "pristine" | "throttled" | "tarpit" | "quarantined" | "severed";
export type Mode = "enforcing" | "detect-only" | "dry-run" | "kill-switched";

export interface Whoami {
  user: string;
  hostname?: string;
  server_ip?: string;
  csrf?: string;
}

export interface Alert {
  id?: number;
  exec_id?: string;
  severity?: Severity | string;
  policy_name?: string;
  process?: string;
  binary?: string;
  uid?: number;
  score?: number;
  reason?: string;
  message?: string;
  timestamp?: string;
  [key: string]: unknown;
}

export interface Event {
  id?: number;
  exec_id?: string;
  policy_name?: string;
  binary?: string;
  args?: string;
  pid?: number;
  uid?: number;
  timestamp?: string;
  [key: string]: unknown;
}

export interface Decision {
  id?: number;
  exec_id?: string;
  action?: string;
  state?: ChokeState | string;
  binary?: string;
  reason?: string;
  score?: number;
  timestamp?: string;
  [key: string]: unknown;
}

export interface StreamFrame {
  type: "heartbeat" | "event" | "alert" | "process_exit" | "decision";
  payload?: unknown;
}

export interface DeviceBucket {
  rate_per_sec?: number;
  burst?: number;
  tokens?: number;
  flags?: number;
}

export interface DeviceFlow {
  dest_ip?: string;
  dest_port?: number;
  proto?: string;
  packets?: number;
  bytes?: number;
}

export interface DeviceEntry {
  mac: string;
  device_id?: string;
  last_ip?: string;
  hostname?: string;
  vendor?: string;
  state?: ChokeState | string;
  protected?: boolean;
  source?: string;
  first_seen?: string;
  last_seen?: string;
  bucket?: DeviceBucket;
  flows?: number;
  revert_pending?: boolean;
}

export interface DevicePlaneState {
  data_plane?: string;
  links_attached?: number;
  frames_seen?: number;
  devices_seen?: number;
  mode?: Mode | string;
  enforcing?: boolean;
  dry_run?: boolean;
  kill_switched?: boolean;
  tracked?: number;
  devices_known?: number;
  counts?: Record<ChokeState, number>;
}

export interface FleetHost {
  name: string;
  url?: string;
  reachable?: boolean;
  [key: string]: unknown;
}

export interface FleetEnvelope<T = unknown> {
  name?: string;
  ok?: boolean;
  error?: string;
  status?: number;
  data?: T;
}
