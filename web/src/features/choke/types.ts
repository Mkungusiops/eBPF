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
  /**
   * False when the deployment cannot verify the chain at all (the fleet control
   * plane does not hash-chain decisions centrally). Distinct from ok=false,
   * which means a chain exists and is BROKEN.
   */
  supported?: boolean;
  detail?: string;
  ok?: boolean;
  total?: number;
  bad_at?: number | string;
  bad_field?: string;
  head_hash?: string;
  head?: string;
  tip?: string;
}

// KernelPosture is the host's OTHER enforcement authority: Tetragon
// TracingPolicies, which enforce independently of `mode` above. A policy loaded
// in Tetragon's `enforce` mode can kill regardless of what this console says the
// mode is — with no audit row, no reversal, and no kill-switch coverage. Shipped
// policies all declare `policy-mode: monitor`, so anything armed is hand-loaded
// or deliberate. See docs/plan/threat-model.md EN-3.
export interface KernelPosture {
  // agents_reporting < agents_total means some agent did not answer. That is not
  // a clean agent, it is an unknown one, so the UI must not read it as safe.
  agents_reporting?: number;
  agents_total?: number;
  enforcing_agents?: string[];
  // True when this console shows detect-only while a kernel authority is armed.
  diverged?: boolean;
  diverged_agents?: string[];
  // Enforcing actions that have ACTUALLY fired. Non-zero is evidence, not risk:
  // something was killed with no decision behind it and no audit row for it.
  enforce_actions?: number;
}

export interface ChokeState {
  mode?: ChokeMode;
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
  counts?: Partial<Record<ChokeStateName, number>>;
  thresholds?: Thresholds;
  audit?: AuditChainStatus;
  kernel?: KernelPosture;
  /**
   * Hosts whose containment ladder the control plane put back to tenant policy.
   *
   * Setting a ladder on ONE host is supported — the agent serves its own
   * console. The tenant policy is authoritative, so the reconciler corrects
   * that host within two minutes, correctly and, until now, silently: the
   * operator watched their change apply and then vanish, with the only
   * explanation in a control-plane log they cannot reach.
   */
  ladder_corrections?: LadderCorrection[];
}

export interface LadderCorrection {
  agent: string;
  /** The ladder the host was running, as "throttle/tarpit/quarantine/sever". */
  from: string;
  /** The tenant policy it was replaced with, same shape. */
  to: string;
  at: string;
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
  /**
   * The agent this circuit lives on (fleet console only; the single-host engine
   * omits it). Sent back on jail/thaw so containment is ROUTED to the right
   * host rather than guessed from a PID — PIDs are per-host and collide across
   * a fleet, and the control plane refuses an unroutable sever outright.
   */
  agent?: string;
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
  /**
   * The host this bucket lives on. Present on the fleet console, absent on the
   * single-host engine where there is only one answer.
   *
   * The control plane has always sent it and this type never declared it, so
   * it was dropped — leaving the fleet's kernel map as a flat list of PIDs
   * from different hosts. PIDs are per-host and collide, so "PID 1156421" was
   * not just unattributed, it was ambiguous: the row key did not include the
   * agent either, so two hosts throttling the same PID number rendered as one
   * row and the other silently disappeared.
   */
  agent?: string;
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
  /**
   * Who ordered this, empty for a score-driven one.
   *
   * The engine has always sent it and this type never declared it, so the
   * console dropped it on the floor. The control plane never received it at
   * all until the decision uplink carried it. It is chain-hashed either way,
   * which is the tell that it is part of the record rather than decoration:
   * the reason says why, and without this nothing says who.
   */
  actor?: string;
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
  /**
   * What a policy push REACHES on this deployment: "fleet" on the multi-tenant
   * control plane, absent on the single-tenant engine, which serves one host.
   *
   * A DEPLOYMENT capability, not a permission — the control plane emits the
   * same value for every principal it serves. It is the console's only
   * server-stated answer to "which deployment am I talking to", which is why
   * the approvals queue keys off it: dual control is a control-plane feature
   * and /api/approvals does not exist on the engine.
   */
  policy_scope?: string;
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
