export type DeviceStateName =
  | "pristine"
  | "throttled"
  | "tarpit"
  | "quarantined"
  | "severed";

export type DeviceAction = "throttle" | "tarpit" | "quarantine" | "sever";

export type DeviceMode = "enforcing" | "detect-only" | "dry-run" | "kill-switched" | string;

export interface DeviceStateCounts {
  pristine?: number;
  throttled?: number;
  tarpit?: number;
  quarantined?: number;
  severed?: number;
}

export interface DeviceDataPlaneState {
  data_plane?: string;
  links_attached?: number;
  frames_seen?: number;
  devices_seen?: number;
  mode?: DeviceMode;
  enforcing?: boolean;
  dry_run?: boolean;
  /**
   * null when the deployment cannot observe it. The control plane has no
   * heartbeat field for the agent's kill-switch, so it reports null rather
   * than the literal `false` it used to send — a definite "Standby" for a
   * bypass that may well be engaged. Callers must not derive a toggle
   * direction from an unknown.
   */
  kill_switched?: boolean | null;
  tracked?: number;
  devices_known?: number;
  counts?: DeviceStateCounts;
}

export interface DeviceBucket {
  rate_per_sec?: number;
  burst?: number;
  tokens?: number;
  flags?: number;
}

export interface DeviceEntry {
  mac: string;
  device_id?: string;
  last_ip?: string;
  hostname?: string;
  vendor?: string;
  state: DeviceStateName | string;
  protected?: boolean;
  packets?: number;
  source?: string;
  first_seen?: string;
  last_seen?: string;
  bucket?: DeviceBucket | null;
  flows?: number;
  revert_pending?: boolean;
}

export interface DeviceFlow {
  dest_ip: string;
  dest_port?: number;
  proto?: string;
  packets?: number;
  bytes?: number;
}

export interface DeviceFlowsResponse {
  mac: string;
  flows?: DeviceFlow[];
}

export interface DeviceActionResult {
  mac: string;
  ok: boolean;
  error?: string;
  state?: string;
  outcome?: string;
}

export interface DeviceJailRequest {
  macs: string[];
  action: DeviceAction;
  reason: string;
  revert_after_seconds?: number;
}

export interface DeviceJailResponse {
  action: DeviceAction | string;
  reason: string;
  results: DeviceActionResult[];
}

export interface DeviceThawRequest {
  macs: string[];
  reason?: string;
}

export interface DeviceThawResponse {
  results: DeviceActionResult[];
}

export interface DeviceModeResponse {
  mode: string;
  previous: string;
}

export interface DeviceKillSwitchResponse {
  engaged: boolean;
  previous: boolean;
}

