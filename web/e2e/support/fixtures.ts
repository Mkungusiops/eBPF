export const fakeModeStreamFrames = [
  { type: "heartbeat", payload: {} },
  {
    type: "event",
    payload: {
      id: 101,
      timestamp: "2026-06-25T09:00:00Z",
      policy: "override-credential-read",
      process: "cat",
      pid: 4242,
      exec_id: "exec-fake-1"
    }
  },
  {
    type: "alert",
    payload: {
      id: "alert-fake-1",
      severity: "critical",
      policy: "override-credential-read",
      process: "cat",
      exec_id: "exec-fake-1",
      acknowledged: false
    }
  },
  {
    type: "decision",
    payload: {
      exec_id: "exec-fake-1",
      action: "quarantine",
      score: 44,
      reason: "fake-mode certification fixture"
    }
  }
] as const;

export const representativeAlerts = [
  {
    id: "alert-1",
    severity: "critical",
    policy: "override-credential-read",
    process: "cat",
    exec_id: "exec-alert-1",
    uid: 0,
    score: 44
  },
  {
    id: "alert-2",
    severity: "medium",
    policy: "network-observe",
    process: "curl",
    exec_id: "exec-alert-2",
    uid: 1000,
    score: 12
  }
] as const;

export const representativeProcessLineage = {
  exec_id: "exec-alert-1",
  process: "cat",
  ancestors: [
    { pid: 1, process: "systemd" },
    { pid: 4200, process: "bash" }
  ],
  events: representativeAlerts
} as const;

export const representativeDecisions = [
  {
    exec_id: "exec-alert-1",
    action: "quarantine",
    state: "quarantined",
    score: 44,
    reason: "fixture decision"
  },
  {
    exec_id: "exec-alert-2",
    action: "throttle",
    state: "throttled",
    score: 12,
    reason: "fixture decision"
  }
] as const;

export const chokeStateSnapshot = {
  mode: "detect-only",
  enforcing: false,
  kill_switch: false,
  thresholds: { low: 5, medium: 10, high: 20, critical: 40 },
  audit: { decisions: 2, hash_ok: true }
} as const;

export const fleetFanoutSuccess = {
  hosts: [
    { name: "alpha", ok: true, status: 200 },
    { name: "bravo", ok: true, status: 200 }
  ]
} as const;

export const fleetPartialFailure = {
  hosts: [
    { name: "alpha", ok: true, status: 200 },
    { name: "bravo", ok: false, status: 503, error: "fleet peer unavailable" }
  ]
} as const;

export const deviceStateActive = {
  data_plane: "attached",
  links_attached: 2,
  frames_seen: 128,
  mode: "enforcing",
  enforcing: true,
  dry_run: false,
  kill_switched: false,
  counts: {
    pristine: 1,
    throttled: 1,
    tarpit: 0,
    quarantined: 1,
    severed: 0
  }
} as const;

export const deviceStateDisabled = {
  status: 503,
  error: "network device choke not enabled (start engine with -devchoke-iface)"
} as const;

export const deviceProtectedMacFailure = {
  results: [
    {
      mac: "02:00:00:00:00:01",
      ok: false,
      error: "protected device cannot be quarantined",
      state: "pristine"
    }
  ]
} as const;

export const expiredSessionResponse = {
  status: 401,
  body: { error: "unauthorized", redirect: "/login" }
} as const;

export const missingCsrfResponse = {
  status: 403,
  body: { error: "csrf token missing or invalid" }
} as const;

export const requiredFixtureNames = [
  "fake-mode event stream",
  "representative alerts",
  "representative process lineage",
  "representative decisions",
  "choke state snapshot",
  "fleet fan-out success",
  "fleet partial failure",
  "device state active",
  "device state disabled",
  "device protected MAC failure",
  "expired session",
  "missing CSRF"
] as const;
