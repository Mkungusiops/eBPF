export type ChokeStateName = "pristine" | "throttled" | "tarpit" | "quarantined" | "severed";

export type ChokeAction = "throttle" | "tarpit" | "quarantine" | "sever" | "thaw";

export type ChokeMode = "enforcing" | "detect-only" | "dry-run" | "kill-switched" | string;

export interface Thresholds {
  throttle_at: number;
  tarpit_at: number;
  quarantine_at: number;
  sever_at: number;
}

export interface AuditChainStatus {
  ok?: boolean;
  total?: number;
  bad_at?: number | string;
  bad_field?: string;
  head_hash?: string;
  head?: string;
  tip?: string;
}

export interface ChokeState {
  mode?: ChokeMode;
  dry_run?: boolean;
  kill_switched?: boolean;
  tracked?: number;
  counts?: Partial<Record<ChokeStateName, number>>;
  thresholds?: Thresholds;
  audit?: AuditChainStatus;
}

export interface Annotation {
  note?: string;
  actor?: string;
  timestamp?: string;
}

export interface OriginInfo {
  kind?: string;
  remote_ip?: string;
  remote_port?: number;
  user?: string;
  fingerprint?: string;
  first_seen?: string;
}

export interface CircuitEntry {
  exec_id: string;
  pid?: number;
  binary?: string;
  state?: ChokeStateName | string;
  score?: number;
  uid?: number;
  args?: string;
  parent_id?: string;
  start_time?: string;
  last_seen?: string;
  annotation?: Annotation;
  revert_pending?: boolean;
  origin?: OriginInfo;
}

export interface BucketEntry {
  pid: number;
  rate_per_sec: number;
  burst: number;
  tokens: number;
  flags: number;
}

export interface Decision {
  id?: number;
  timestamp?: string;
  exec_id?: string;
  pid?: number;
  binary?: string;
  action?: ChokeAction | string;
  from_state?: string;
  to_state?: string;
  score?: number;
  reason?: string;
  dry_run?: boolean;
  backend?: string;
  outcome?: string;
  origin_kind?: string;
  origin_ip?: string;
  origin_port?: number;
  origin_user?: string;
  origin_fingerprint?: string;
  prev_hash?: string;
  hash?: string;
}

export interface Alert {
  id?: number;
  timestamp?: string;
  severity?: string;
  title?: string;
  description?: string;
  exec_id?: string;
  score?: number;
  event_ids?: number[];
}

export interface SystemHealth {
  [key: string]: unknown;
}

export type CgroupValue = number[] | { pids?: number[]; count?: number; error?: string };

export type CgroupMap = Record<string, CgroupValue>;

export interface Whoami {
  username?: string;
  user?: string;
  host?: string;
  hostname?: string;
  server_ip?: string;
  [key: string]: unknown;
}

export interface ProcessEvent {
  id?: number;
  timestamp?: string;
  event_type?: string;
  pid?: number;
  parent_pid?: number;
  exec_id?: string;
  binary?: string;
  args?: string;
  uid?: number;
  policy_name?: string;
}

export interface ChainNode {
  exec_id?: string;
  pid?: number;
  binary?: string;
  score?: number;
}

export interface ProcessDetailPayload {
  entry?: CircuitEntry | null;
  chain?: ChainNode[];
  events?: ProcessEvent[];
  decisions?: Decision[];
  annotation?: Annotation;
}

export interface SysProcEntry {
  pid: number;
  ppid?: number;
  uid?: number;
  comm?: string;
  exe?: string;
  cmdline?: string;
  start_time?: number;
  tracked?: boolean;
  state?: string;
  exec_id?: string;
  score?: number;
}

export interface SysProcDetail {
  pid?: number;
  status?: string;
  threads?: number;
  vm_rss_kb?: number;
  vm_size_kb?: number;
  started_unix?: number;
  cwd?: string;
  root?: string;
  num_fds?: number;
  fd_samples?: string[];
  num_conns?: number;
  conn_peers?: string[];
}

export interface PolicyBucket {
  dimension?: string;
  rate_per_sec?: number;
  burst?: number;
}

export interface PolicyDocument {
  metadata?: {
    name?: string;
    description?: string;
  };
  match?: {
    binaries?: string[];
    states?: string[];
  };
  buckets?: PolicyBucket[];
  deny_syscalls?: string[];
  deny_paths?: string[];
}

export interface PolicyPreviewResponse {
  valid?: boolean;
  errors?: string[];
  policy?: PolicyDocument;
  matches?: CircuitEntry[];
  // Size of the live tracked snapshot the policy was evaluated against.
  scanned?: number;
}

export interface StreamEnvelope {
  type?: "heartbeat" | "event" | "alert" | "process_exit" | "decision" | string;
  payload?: unknown;
}

export type LoadState =
  | { kind: "loading" }
  | { kind: "ready" }
  | { kind: "disabled"; message: string }
  | { kind: "error"; message: string };

export interface HostPingResult {
  path: string;
  ok: boolean;
  status?: number;
  rtt_ms: number;
  checked_at: number;
  error?: string;
}

export interface ToastMessage {
  id: number;
  kind: "ok" | "warn" | "err";
  message: string;
}

export interface ConfirmRequest {
  title: string;
  body: string;
  danger?: boolean;
  confirmLabel?: string;
  reasonRequired?: boolean;
  withRevert?: boolean;
  initialReason?: string;
  onConfirm: (input: { reason: string; revert_after_seconds?: number }) => Promise<void> | void;
}
