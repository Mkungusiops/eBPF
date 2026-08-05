export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type AlertClassification = "attack" | "threat" | "baseline" | "unknown";

export type StreamState = "connecting" | "live" | "reconnect" | "down";

export type PanelMode = "live" | "read-only" | "local" | "placeholder";

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
}

export interface SocVersion {
  sha: string;
  startedAt?: string;
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
}

export interface SocPolicy {
  name: string;
  description?: string;
  mitre?: string;
  yaml?: string;
  sensors?: string[];
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
