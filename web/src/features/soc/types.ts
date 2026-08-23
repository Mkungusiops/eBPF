export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AlertClassification = "attack" | "threat" | "baseline" | "unknown";

export type StreamState = "connecting" | "live" | "reconnect" | "down";

/**
 * "write" is a panel that can CHANGE the estate — it dispatches a signed
 * command, not just a read. Distinguished from "live" because the inventory is
 * how an operator (and a reviewer) tells at a glance which surfaces can act.
 */
export type PanelMode = "live" | "read-only" | "local" | "placeholder" | "write";

export type PanelRisk = "H" | "M" | "L";

export interface SocPanelInventoryItem {
  id: string;
  title: string;
  risk: PanelRisk;
  mode: PanelMode;
  description: string;
  api?: string[];
  storage?: string[];
}

export interface SocReadResult<T> {
  ok: boolean;
  data: T;
  status?: number;
  error?: string;
  disabled?: boolean;
}

export interface SocWhoami {
  user: string;
  host: string;
  role?: string;
  /**
   * Whether THIS deployment can dispatch a policy to a fleet. The
   * single-tenant engine cannot — it has no agents and no push route — and
   * does not send the field, so absent must read as false.
   */
  canPushPolicy?: boolean;
  /**
   * How far a policy change reaches on this deployment. The control plane
   * dispatches to a fleet and cannot promise convergence; the engine applies to
   * its own host and can. Defaults to "host", the narrower claim.
   */
  policyScope: "fleet" | "host";
}

export interface SocVersion {
  sha: string;
  startedAt?: string;
  /**
   * Whether this deployment exposes the demo/lab surfaces (Attack Sim,
   * Honeypots, Rule Simulator).
   *
   * Defaults FALSE when the server does not report it, which is the safe
   * direction: an older server that has not grown the field hides the surfaces
   * rather than offering a nav entry whose endpoint 404s.
   */
  labMode: boolean;
}

export interface SocAlert {
  id: string;
  title: string;
  description: string;
  severity: Severity;
  score: number;
  timestamp: string;
  policyName?: string;
  execId?: string;
  pid?: number;
  process?: string;
  args?: string;
  mitreId?: string;
  tactic?: string;
  // Owning agent/host. Only the multi-tenant control plane reports it (the
  // single-tenant engine IS the host), but the enforcement panel must show it:
  // acting on the right process on the WRONG host is the nightmare case.
  agent?: string;
  raw: unknown;
}

export interface SocEvent {
  id: string;
  eventType: string;
  timestamp: string;
  process?: string;
  args?: string;
  execId?: string;
  pid?: number;
  /**
   * The parent process id, when the sensor reports one.
   *
   * The single-tenant engine sends it on every exec; the control plane's
   * tenant-scoped event view does not. It is the only lineage signal available
   * on a host whose alerting processes were started before the engine was, so
   * the correlation graph uses it to draw parent → child edges that the alert
   * title cannot supply.
   */
  parentPid?: number;
  policyName?: string;
  severity?: Severity;
  path?: string;
  remoteIp?: string;
  destIp?: string;
  destPort?: number;
  proto?: string;
  agent?: string;
  raw: unknown;
}

export interface SocDecision {
  id: string;
  action: string;
  state?: string;
  target?: string;
  reason?: string;
  timestamp: string;
  ok?: boolean;
  /**
   * What the engine actually recorded, verbatim — "ok", or "skipped: system-critical
   * chain (auto-only; manual override allowed)", or a failure string.
   *
   * No backend sends a boolean `ok` on a decision; they send this. So `ok` above
   * is almost always undefined, and any code that reads absence as success is
   * asserting an outcome nobody reported.
   */
  outcome?: string;
}

export interface SocPolicy {
  name: string;
  description?: string;
  mitre?: string;
  yaml?: string;
  /** "host" = read off the monitored machine; "shipped" = this build's source. */
  yamlSource?: string;
  sensors?: string[];
  /**
   * How many of the tenant's agents report this policy ENABLED in the kernel,
   * and the strongest mode any of them reports.
   *
   * Both come from the heartbeat (DataPlaneState.kernel_policies), so they
   * describe what the kernel has, not what a config file says. Absent on a
   * server that does not report them — which must render as "unknown", never
   * as a claim that the policy is loaded.
   */
  loadedAgents?: number;
  kernelMode?: string;
  /**
   * Whether the server reported kernel state AT ALL for this policy.
   *
   * false means "we could not ask Tetragon", which is NOT the same as "nothing
   * is loaded" — and rendering the two the same is how a console ends up
   * showing a red "no host is watching for this" on a host with every policy
   * loaded. That shipped once; this field is why it cannot again.
   */
  kernelStateKnown?: boolean;
  /**
   * Whether this platform SHIPS this policy and therefore expects a host to be
   * running it. Only an absent expected policy is a coverage gap — a policy
   * that fired once and was then removed lingers in the control plane's list
   * and is not a hole.
   */
  expected?: boolean;
}

export interface SocPolicyStat {
  name: string;
  posts: number;
  ratePerMin?: number;
  memoryBytes?: number;
  status?: string;
}

export interface SocAttack {
  id: string;
  name: string;
  description?: string;
  severity?: Severity;
}

export interface SocHoneypot {
  path: string;
  description?: string;
  hits: number;
  lastSeen?: string;
  bytes?: number;
}

export interface SocSystemHealth {
  status: string;
  host?: string;
  tetragon?: string;
  choke?: string;
  kernel?: string;
  uptime?: string;
  /** Central-store reachability. When this is not ok, every store-backed read endpoint fails together. */
  storeOk?: boolean;
  storeError?: string;
  details: Record<string, unknown>;
}

export interface SocProcessDetail {
  execId: string;
  chain: Array<{
    execId?: string;
    pid?: number;
    binary?: string;
    args?: string;
    timestamp?: string;
  }>;
  events: SocEvent[];
  origin?: Record<string, unknown>;
}

export interface SocSnapshot {
  whoami: SocWhoami;
  version: SocVersion;
  alerts: SocAlert[];
  events: SocEvent[];
  decisions: SocDecision[];
  policies: SocPolicy[];
  policyStats: SocPolicyStat[];
  attacks: SocAttack[];
  honeypots: SocHoneypot[];
  health: SocSystemHealth;
}

export interface SocSnapshotRead {
  snapshot: SocSnapshot;
  /** Per-feed: the server returned a full page, so older records exist that the console does not hold. */
  truncated: { alerts: boolean; events: boolean };
  errors: Record<string, string>;
  statuses: Record<string, number | undefined>;
}
