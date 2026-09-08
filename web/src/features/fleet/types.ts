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

/**
 * One host's outcome inside a fan-out WRITE result.
 *
 * Deliberately looser than HostResult about `status`: the single-tenant engine
 * reports the peer's HTTP status code, while the control plane reports the
 * agent's ack word ("APPLIED", or "timeout" when no ack arrived). Both are what
 * an operator needs to read next to the host name, so both are kept as-is
 * rather than coerced into a number the control plane never sent.
 */
export interface FanoutHost {
  name: string;
  ok: boolean;
  status?: number | string;
  error?: string;
}

/**
 * A fan-out write's response, as either server may shape it.
 *
 * The engine answers with `hosts`; the control plane answers with `applied` /
 * `total` / `detail` and, since the fleet-targeting contract, `hosts` too. Every
 * field is optional because the console must be able to tell "the server said
 * nothing about coverage" apart from "the server said it reached nobody" — the
 * two used to be the same green toast.
 */
export interface FanoutEnvelope {
  hosts?: FanoutHost[] | null;
  applied?: number | null;
  total?: number | null;
  detail?: string | null;
  [key: string]: unknown;
}

/** A fan-out response read into the only two facts a toast may claim. */
export interface FanoutReport {
  /** Per-host outcomes, when the server named them. Empty when it only counted. */
  hosts: FanoutHost[];
  /** Coverage as the server reported it; null when it reported none at all. */
  applied: number | null;
  total: number | null;
  detail: string;
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
  /**
   * Whether this host maintains a hash chain AT ALL. The multi-tenant control
   * plane does not — each agent chains its own — and answers
   * {ok: false, supported: false}. Without this field the fleet view could only
   * see "not ok" and reported such a host as having a BROKEN chain.
   */
  supported?: boolean;
}

/** The kill-switch as reported, which is three-valued — see `KillState`. */
export type KillState = "on" | "off" | "unknown";

export interface ChokeState {
  mode?: string;
  dry_run?: boolean;
  /**
   * `null` when the server could not read it, and that is not `false`.
   *
   * The multi-tenant control plane sends `"kill_switched": nil` on every host
   * in /api/fleet/state: no heartbeat field carries the agent's switch, so it
   * has nothing to report. Typing this as `boolean` made the console fold the
   * unknown into "off" — a green "live" pill over a host whose enforcement
   * state nobody knows, and an "off" vote in the drift majority, so part of a
   * measured "DRIFT 0" was an artefact of a field the server said it could not
   * read.
   */
  kill_switched?: boolean | null;
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
  /**
   * The majority over the hosts that actually REPORTED a kill-switch state.
   * `null` when none did — which is the whole fleet on the control plane, and
   * must not collapse into "off": a host compared against a majority nobody
   * voted in would be marked drifted for a field neither side knows.
   */
  kill: "on" | "off" | null;
  thresholds: string | null;
}

export interface RowModel {
  peer: FleetPeer;
  result?: HostResult<ChokeState>;
  reachable: boolean;
  /**
   * What this host said about its kill-switch: on, off, or it did not say.
   * Carried on the row so the table renders the same three states the KPIs
   * count, rather than each deriving its own two-state guess.
   */
  killState: KillState;
  driftMode: boolean;
  /** Never true for a host whose kill-switch state is unknown — see DriftResult. */
  driftKill: boolean;
  driftThresholds: boolean;
}

export interface FleetKpis {
  total: number;
  healthy: number;
  enforcing: number;
  /** Reachable hosts that reported the kill-switch ENGAGED. */
  killed: number;
  /**
   * Reachable hosts that did not report a kill-switch state at all.
   *
   * Counted separately because `killed: 0` over a fleet that reported nothing
   * is not the same reading as `killed: 0` over a fleet that reported "off",
   * and the tile used to render both as the reassuring one.
   */
  killUnknown: number;
  /** Hosts differing from the fleet majority on a field they REPORTED. */
  drift: number;
  auditOk: number;
  /** Hosts that maintain a chain and report it broken. */
  auditBroken: number;
  /** Hosts that do not maintain a chain centrally. Not a failure. */
  auditUnsupported: number;
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
