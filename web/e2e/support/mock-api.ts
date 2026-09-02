/**
 * The mocked backend the browser suite renders against.
 *
 * WHY IT EXISTS: the console is one frontend serving TWO servers that answer
 * the same routes with DIFFERENT wire shapes — the single-tenant engine and
 * the multi-tenant control plane (see support/deployments.ts). A suite that
 * only ever renders one of them cannot see the normalisation bugs, which are
 * this codebase's most expensive recurring class.
 *
 * WHAT MAKES IT TRUSTWORTHY: every default body here was derived from a
 * response captured off the live estate (engine.adanianlabs.io and
 * console.adanianlabs.io, 2026-08-27) rather than invented. A mock that lies
 * about a field's presence or type produces green tests over a broken console,
 * which is the exact failure this project has already shipped three times.
 *
 * Keep the semantic fixture DATA stable — several specs assert on
 * "Credential file read", "fixture-laptop" and "alpha-edge" by name.
 */
import type { Page, Route } from "@playwright/test";

import { fakeModeStreamFrames } from "./fixtures";

const now = "2026-06-25T09:00:00Z";

const thresholds = {
  throttle_at: 5,
  tarpit_at: 10,
  quarantine_at: 20,
  sever_at: 40
};

const alerts = [
  {
    id: "alert-fixture-1",
    timestamp: now,
    severity: "critical",
    title: "Credential file read",
    description: "Fixture alert for panel certification",
    policy_name: "override-credential-read",
    process: "cat",
    binary: "cat",
    exec_id: "exec-fixture-1",
    pid: 4242,
    score: 44,
    message: "credential access",
    mitre_id: "T1003",
    tactic: "Credential Access"
  }
];

const events = [
  {
    id: "event-fixture-1",
    timestamp: now,
    event_type: "file_open",
    process: "cat",
    binary: "cat",
    exec_id: "exec-fixture-1",
    pid: 4242,
    parent_pid: 4100,
    policy_name: "override-credential-read",
    severity: "critical",
    path: "/etc/shadow"
  }
];

const decisions = [
  {
    id: 1,
    timestamp: now,
    exec_id: "exec-fixture-1",
    pid: 4242,
    binary: "cat",
    action: "quarantine",
    from_state: "pristine",
    to_state: "quarantined",
    state: "quarantined",
    score: 44,
    reason: "fixture decision",
    dry_run: false,
    outcome: "ok"
  }
];

const circuits = [
  {
    exec_id: "exec-fixture-1",
    pid: 4242,
    binary: "cat",
    state: "quarantined",
    score: 44,
    uid: 0,
    args: "cat /etc/shadow",
    parent_id: "exec-parent-1",
    start_time: now,
    last_seen: now,
    origin: { kind: "local", user: "root" }
  }
];

const policies = [
  {
    name: "override-credential-read",
    description: "Fixture credential access policy",
    mitre: "T1003",
    tactic: "Credential Access",
    sensors: ["file_open"],
    posts: 4,
    loaded_agents: 1,
    kernel_mode: "monitor",
    expected: true,
    yaml: "apiVersion: cilium.io/v1alpha1\nkind: TracingPolicy\nmetadata:\n  name: override-credential-read\n",
    yaml_source: "host"
  }
];

const deviceState = {
  data_plane: "attached",
  links_attached: 2,
  frames_seen: 128,
  devices_seen: 2,
  mode: "enforcing",
  enforcing: true,
  dry_run: false,
  kill_switched: false,
  tracked: 2,
  counts: {
    pristine: 1,
    throttled: 1,
    tarpit: 0,
    quarantined: 1,
    severed: 0
  }
};

const devices = [
  {
    mac: "02:00:00:00:00:10",
    device_id: "fixture-laptop",
    last_ip: "192.168.1.42",
    hostname: "fixture-laptop",
    vendor: "Fixture Labs",
    state: "quarantined",
    protected: false,
    packets: 812,
    source: "arp",
    first_seen: now,
    last_seen: now,
    bucket: { rate_per_sec: 25, burst: 50, tokens: 12, flags: 0 },
    flows: 1
  },
  {
    mac: "02:00:00:00:00:01",
    device_id: "protected-gateway",
    last_ip: "192.168.1.1",
    hostname: "protected-gateway",
    vendor: "Fixture Labs",
    state: "pristine",
    protected: true,
    packets: 1200,
    source: "dhcp",
    first_seen: now,
    last_seen: now,
    flows: 0
  }
];

const fleetHosts = [
  { name: "alpha-edge", url: "https://alpha-edge.local" },
  { name: "bravo-edge", url: "https://bravo-edge.local" }
];

const fleetEnvelope = {
  hosts: fleetHosts.map((peer, index) => ({
    name: peer.name,
    url: peer.url,
    ok: true,
    status: 200,
    data: {
      mode: index === 0 ? "enforcing" : "detect-only",
      dry_run: false,
      kill_switched: false,
      tracked: 2 + index,
      counts: { pristine: 1, throttled: 1, tarpit: 0, quarantined: index, severed: 0 },
      thresholds,
      audit: { ok: true, total: 2 }
    }
  }))
};

/**
 * Severity histogram. Shape copied from a live /api/alert-stats response —
 * `counts`/`previous` are keyed maps, `buckets` carry an ISO `at` plus their
 * own counts, and `truncated` is what tells the executive band whether its
 * number is a floor or a total.
 */
const alertStats = {
  from: "2026-06-25T08:00:00Z",
  to: now,
  counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 },
  previous: { critical: 0, high: 0, medium: 0, low: 0, info: 0 },
  total: 1,
  buckets: [
    { at: "2026-06-25T08:00:00Z", counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 }, total: 0 },
    { at: now, counts: { critical: 1, high: 0, medium: 0, low: 0, info: 0 }, total: 1 }
  ],
  truncated: false
};

const decisionStats = {
  from: "2026-06-25T08:00:00Z",
  to: now,
  total: 1,
  previous: 0,
  actions: { quarantine: 1, sever: 0, tarpit: 0, throttle: 0 },
  dry_run: 0,
  truncated: false
};

/**
 * Sensor health. The `containment` block is the part that matters: it is what
 * the console reads to say what a host can ACTUALLY do, and it is the block
 * that was missing when the panel claimed containment it did not have.
 */
const sensorHealth = {
  generated_at: now,
  agents_total: 1,
  agents_fresh: 1,
  agents_losing: 0,
  evidence_loss_known: true,
  expected_policies: ["override-credential-read"],
  coverage_caveat: "policies are read from the kernel where the agent can see it",
  agents: [
    {
      agent_id: "agent-fixture",
      version: "0.2.0-agent",
      last_seen: now,
      last_seen_age_seconds: 4,
      fresh: true,
      tetragon: true,
      kernel_observable: true,
      kernel_read_via: "tetra",
      policies_loaded: 1,
      policies_enforce: 0,
      missing_policies: [],
      process_plane: "cgroup",
      process_links: 3,
      device_plane: "tc",
      device_links: 2,
      buffer_depth: 1,
      dropped_records: 0,
      dropped_broadcast: 0,
      thresholds,
      policy_version: "fixture-policy-version",
      status: "ok",
      issues: [],
      notes: [],
      containment: {
        verdict: "partial",
        summary: "kill and freeze land; per-PID network containment is not deployed",
        kill: "yes",
        freeze: "yes",
        resource_caps: "yes",
        net_process: "no",
        net_device: "yes",
        auto: "off (detect-only)",
        auto_device: "off (detect-only)",
        manual_lands: true
      }
    }
  ]
};

const approvals = { approvals: [], pending: 0, you: "operator" };

const approvalPolicy = {
  enabled: false,
  fleet_arming: false,
  requires_approval: [],
  never_gated: ["thaw", "throttle", "tarpit", "kill-switch", "detect-only"],
  ttl_seconds: 1800
};

const settingsSuppressions = {
  suppressions: [],
  candidates: [],
  hits_known: false,
  effect:
    "a suppression withholds the SCORE only. The event is still recorded, the chain is still in the process tree, and the binary can still be contained by hand."
};

const settingsProtected = {
  binaries: [],
  macs: [],
  floor: ["/usr/bin/sudo", "/usr/sbin/sshd", "/usr/lib/openssh/sshd-session"],
  desired_only: true,
  macs_are_add_only: true,
  process_plane: true,
  device_plane: true
};

const settingsChangeControl = {
  available: true,
  enabled: false,
  mandated: false,
  can_disable: false,
  actor: "operator",
  gated: ["quarantine", "sever", "fleet arming"],
  never_gated: ["thaw", "throttle", "tarpit", "kill-switch", "detect-only"],
  pending: 0,
  reason: "fixture",
  updated_at: now
};

const settingsRetention = {
  editable: true,
  detail:
    "decisions are never pruned, whatever this is set to — the containment audit chain has to outlive the telemetry it was made from.",
  policy: {
    deployment_event_days: 30,
    deployment_alert_days: 90,
    tenant_days: 0,
    effective_event_days: 30,
    effective_alert_days: 90,
    floor_days: 14,
    clamped: false,
    ignored: false
  }
};

const operatorAudit = {
  supported: true,
  scope: "tenant",
  viewing: "fixture-tenant",
  cross_tenant: false,
  records_kept: "90 days",
  total: 1,
  returned: 1,
  truncated: false,
  records: [
    {
      subject: "operator",
      tenant_id: "fixture-tenant",
      action: "read",
      allowed: true,
      cross_tenant: false,
      at: now
    }
  ]
};

const baseline = {
  enabled: true,
  scope: "tenant",
  anomalies_total: 1,
  status: {
    ready: true,
    observations: 4200,
    need_observations: 500,
    span_seconds: 172800,
    need_span_seconds: 86400,
    oldest: "2026-06-23T09:00:00Z",
    newest: now,
    half_life_hours: 168,
    facets: [
      {
        facet: "binary",
        keys: 12,
        total_weight: 4200.5,
        top: [{ key: "/usr/bin/cat", share: 0.42, count: 1764 }]
      }
    ]
  }
};

const baselineAnomalies = {
  findings: [
    {
      at: now,
      kind: "rare-binary",
      exec_id: "exec-fixture-1",
      pid: 4242,
      binary: "cat",
      points: 12,
      reasons: ["binary seen in 0.4% of executions"],
      agent: "agent-fixture"
    }
  ]
};

const intel = {
  matches_total: 1,
  refresh: { enabled: true, feeds: 2, interval: "6h0m0s", last_run: now },
  status: {
    loaded: true,
    indicators: 392,
    ips: 9,
    cidrs: 0,
    domains: 383,
    hashes: 0,
    allowlisted: 3,
    sources: [{ source: "feodo-c2", indicators: 5 }],
    loaded_at: now
  }
};

const intelMatches = {
  matches: [
    {
      at: now,
      indicator: "203.0.113.10",
      kind: "ip",
      source: "feodo-c2",
      exec_id: "exec-fixture-1",
      binary: "curl",
      agent: "agent-fixture"
    }
  ]
};

const assistantChats = {
  chats: [
    {
      id: "chat-fixture-1",
      tenant_id: "fixture-tenant",
      user_id: "operator",
      title: "Why did cat read /etc/shadow?",
      mode: "ask",
      model: "gpt-oss:120b",
      created_at: now,
      updated_at: now,
      pinned_at: null
    }
  ]
};

/** Read routes, keyed by exact pathname. */
function readResponse(path: string): unknown {
  switch (path) {
    case "/api/whoami":
      return { user: "operator", username: "operator", host: "mock-host", hostname: "mock-host" };
    case "/api/version":
      return { sha: "fixture-sha", started_at: now };
    case "/api/alerts":
      return alerts;
    case "/api/events":
      return events;
    case "/api/decisions":
      return decisions;
    case "/api/policies":
      return policies;
    case "/api/policy-stats":
      return [{ name: "override-credential-read", posts: 4, rate_per_min: 1.2, status: "active" }];
    case "/api/alert-stats":
      return alertStats;
    case "/api/decision-stats":
      return decisionStats;
    case "/api/sensor-health":
      return sensorHealth;
    case "/api/attacks":
      return [{ id: "credential-read", name: "Credential Read", severity: "critical" }];
    case "/api/honeypots":
      return [{ path: "/srv/decoy", hits: 2, last_seen: now }];
    case "/api/system-health":
      return { status: "ok", host: "mock-host", tetragon: "running", choke: "running", kernel: "6.8" };
    case "/api/approvals":
      return approvals;
    case "/api/approvals/policy":
      return approvalPolicy;
    case "/api/settings/suppressions":
      return settingsSuppressions;
    case "/api/settings/protected":
      return settingsProtected;
    case "/api/settings/change-control":
      return settingsChangeControl;
    case "/api/settings/retention":
      return settingsRetention;
    case "/api/operator-audit":
      return operatorAudit;
    case "/api/baseline":
      return baseline;
    case "/api/baseline/anomalies":
      return baselineAnomalies;
    case "/api/intel":
      return intel;
    case "/api/intel/matches":
      return intelMatches;
    case "/api/platform-doc":
      return { doc: "# Platform\n\nFixture platform documentation.\n" };
    case "/api/assistant":
      // Off by default: the assistant is opt-in and ships disabled, so the
      // unconfigured deployment is the COMMON case and must be what the suite
      // renders unless a spec says otherwise (see assistant.spec.ts).
      //
      // `agents: []` is not decoration. Both servers always send the key
      // (no `omitempty` on the field — engine/internal/api/assistant.go and
      // internal/controlplane/assistant.go), and the console dereferences it
      // without a guard, so a mock that omitted it would be testing a wire
      // shape neither server produces. resilience.spec.ts covers what happens
      // when a server DOES omit it.
      return { enabled: false, agents: [], reason: "no model configured on this fixture" };
    case "/api/assistant/chats":
      return assistantChats;
    case "/api/choke/state":
      return {
        mode: "enforcing",
        dry_run: false,
        kill_switched: false,
        tracked: 2,
        counts: { pristine: 1, throttled: 1, tarpit: 0, quarantined: 1, severed: 0 },
        thresholds,
        audit: { ok: true, total: 2 }
      };
    case "/api/choke/circuits":
      return circuits;
    case "/api/choke/buckets":
      return [{ pid: 4242, rate_per_sec: 25, burst: 50, tokens: 12, flags: 0 }];
    case "/api/choke/cgroups":
      return { "/sys/fs/cgroup/choke/quarantined": [4242], "/sys/fs/cgroup/choke/throttled": [3131] };
    case "/api/choke/processes":
      return [{ pid: 4242, ppid: 4100, uid: 0, comm: "cat", exe: "/usr/bin/cat", tracked: true }];
    case "/api/verify-chain":
      return { ok: true, total: 2 };
    case "/api/choke/device-state":
      return deviceState;
    case "/api/choke/devices":
      return devices;
    case "/api/choke/device-flows":
      return {
        mac: "02:00:00:00:00:10",
        flows: [{ dest_ip: "10.0.0.25", dest_port: 443, proto: "tcp", packets: 12, bytes: 4096 }]
      };
    case "/api/fleet/hosts":
      return { hosts: fleetHosts };
    case "/api/fleet/state":
      return fleetEnvelope;
    case "/api/fleet/cgroups":
      return {
        hosts: fleetHosts.map((peer) => ({
          name: peer.name,
          url: peer.url,
          ok: true,
          status: 200,
          data: { "/sys/fs/cgroup/choke/quarantined": [4242] }
        }))
      };
    case "/api/fleet/decisions":
      return {
        hosts: fleetHosts.map((peer) => ({ name: peer.name, url: peer.url, ok: true, status: 200, data: decisions }))
      };
    case "/api/fleet/alerts":
      return {
        hosts: fleetHosts.map((peer) => ({ name: peer.name, url: peer.url, ok: true, status: 200, data: alerts }))
      };
    case "/api/fleet/devices":
      return {
        hosts: fleetHosts.map((peer) => ({ name: peer.name, url: peer.url, ok: true, status: 200, data: devices }))
      };
    default:
      if (path.startsWith("/api/process/") || path.startsWith("/api/choke/process/")) {
        return {
          entry: circuits[0],
          chain: [
            { exec_id: "exec-parent-1", pid: 4100, binary: "bash" },
            { exec_id: "exec-fixture-1", pid: 4242, binary: "cat" }
          ],
          events,
          decisions,
          origin: { kind: "local", user: "root" }
        };
      }
      if (path.startsWith("/api/choke/proc/")) {
        return { pid: 4242, comm: "cat", exe: "/usr/bin/cat", cmdline: "cat /etc/shadow" };
      }
      if (path.startsWith("/api/assistant/chats/")) {
        return {
          chat: assistantChats.chats[0],
          messages: [
            { role: "user", content: "Why did cat read /etc/shadow?", at: now },
            { role: "assistant", content: "A shell started cat against the shadow file.", at: now }
          ]
        };
      }
      return {};
  }
}

function writeResponse(path: string): unknown {
  // NB: /api/choke/policy/preview is intentionally NOT handled. Both servers
  // removed the route with the console surface that used it, so a mock that
  // still answered it would let a resurrected caller pass its tests.
  if (path.includes("device-jail") || path.includes("device-thaw")) {
    return { action: "throttle", reason: "fixture", results: [{ mac: devices[0].mac, ok: true, state: "throttled" }] };
  }
  if (path.includes("fleet/")) {
    return { hosts: fleetHosts.map((peer) => ({ name: peer.name, url: peer.url, ok: true, status: 200 })) };
  }
  return { ok: true, audit: { ok: true, total: 3 } };
}

// ── The installable mock ───────────────────────────────────────────────────

/** A canned response: a JSON body, or a body with a non-200 status. */
export type MockRouteBody =
  | unknown
  | { status: number; body?: unknown; contentType?: string };

/**
 * An override is either a fixed body, or a function of the request.
 *
 * The function form exists because several endpoints answer the QUERY, not just
 * the path — `/api/assistant/chats?q=` is a server-side search, and a fixed
 * body would make a search test pass while searching nothing.
 */
export type MockRouteResponse =
  | MockRouteBody
  | ((request: RecordedRequest) => MockRouteBody);

/**
 * What the mocked EventSource does.
 *
 *  - "open"   — connects and replays the frames (the healthy case).
 *  - "silent" — connects and never says anything. This is NOT the same as
 *               "down": the console must notice a stream that is open and mute,
 *               which is what a wedged proxy looks like from the browser.
 *  - "error"  — fails to connect, so the reconnect path is what is under test.
 */
export type MockStreamBehaviour = "open" | "silent" | "error";

export interface MockApiOptions {
  /**
   * Per-pathname overrides, consulted BEFORE the defaults. Keys are exact
   * pathnames ("/api/assistant"); a key ending in "/" matches by prefix.
   */
  routes?: Record<string, MockRouteResponse>;
  /** Frames the mocked EventSource replays once it opens. */
  streamFrames?: readonly unknown[];
  /** How the mocked EventSource behaves. Defaults to "open". */
  stream?: MockStreamBehaviour;
  /** Collects every /api request the page made, for contract assertions. */
  recorder?: RequestLog;
}

export interface RecordedRequest {
  method: string;
  path: string;
  search: string;
  body?: string;
}

/**
 * Every /api call the page made.
 *
 * This exists for one assertion the DOM cannot make: that the console asks
 * only for endpoints its servers actually serve. A panel that calls a route
 * nobody implements renders empty and looks merely quiet.
 */
export class RequestLog {
  readonly requests: RecordedRequest[] = [];

  record(request: RecordedRequest): void {
    this.requests.push(request);
  }

  /** Distinct pathnames requested, sorted. */
  paths(): string[] {
    return [...new Set(this.requests.map((request) => request.path))].sort();
  }

  /** Every request whose pathname matches, in order. */
  matching(pattern: RegExp): RecordedRequest[] {
    return this.requests.filter((request) => pattern.test(request.path));
  }
}

function resolveOverride(
  routes: Record<string, MockRouteResponse> | undefined,
  path: string
): { found: boolean; value?: MockRouteResponse } {
  if (!routes) return { found: false };
  if (Object.prototype.hasOwnProperty.call(routes, path)) {
    return { found: true, value: routes[path] };
  }
  for (const key of Object.keys(routes)) {
    if (key.endsWith("/") && path.startsWith(key)) {
      return { found: true, value: routes[key] };
    }
  }
  return { found: false };
}

function isStatusEnvelope(value: unknown): value is { status: number; body?: unknown; contentType?: string } {
  return typeof value === "object" && value !== null && "status" in value &&
    typeof (value as { status: unknown }).status === "number";
}

export async function installMockApi(page: Page, options: MockApiOptions = {}): Promise<void> {
  await installMockEventSource(page, options.streamFrames ?? fakeModeStreamFrames, options.stream ?? "open");

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;

    options.recorder?.record({
      method: request.method(),
      path,
      search: url.search,
      body: request.postData() ?? undefined
    });

    const override = resolveOverride(options.routes, path);
    if (override.found) {
      const value =
        typeof override.value === "function"
          ? (override.value as (request: RecordedRequest) => MockRouteBody)({
              method: request.method(),
              path,
              search: url.search,
              body: request.postData() ?? undefined
            })
          : override.value;
      if (isStatusEnvelope(value)) {
        await route.fulfill({
          status: value.status,
          contentType: value.contentType ?? "application/json",
          body: typeof value.body === "string" ? value.body : JSON.stringify(value.body ?? {})
        });
        return;
      }
      await fulfillJson(route, value);
      return;
    }

    if (request.method() !== "GET") {
      await fulfillJson(route, writeResponse(path));
      return;
    }

    await fulfillJson(route, readResponse(path));
  });
}

async function installMockEventSource(
  page: Page,
  frames: readonly unknown[],
  behaviour: MockStreamBehaviour
): Promise<void> {
  await page.addInitScript(([frameList, mode]: [readonly unknown[], MockStreamBehaviour]) => {
    type Listener = ((event: Event) => void) | null;

    class MockEventSource {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;

      url: string;
      readyState: number = MockEventSource.CONNECTING;
      onopen: Listener = null;
      onmessage: Listener = null;
      onerror: Listener = null;

      constructor(url: string | URL) {
        this.url = String(url);
        window.setTimeout(() => {
          if (this.readyState === MockEventSource.CLOSED) return;
          if (mode === "error") {
            this.onerror?.(new Event("error"));
            return;
          }
          this.readyState = MockEventSource.OPEN;
          this.onopen?.(new Event("open"));
          if (mode === "silent") return;
          for (const frame of frameList) {
            this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(frame) }));
          }
        }, 10);
      }

      close(): void {
        this.readyState = MockEventSource.CLOSED;
      }

      addEventListener(type: string, listener: (event: Event) => void): void {
        if (type === "open") this.onopen = listener;
        if (type === "message") this.onmessage = listener;
        if (type === "error") this.onerror = listener;
      }

      removeEventListener(): undefined {
        return undefined;
      }

      dispatchEvent(): boolean {
        return true;
      }
    }

    Object.defineProperty(window, "EventSource", {
      configurable: true,
      value: MockEventSource
    });
    document.cookie = "csrf_token=mock-csrf; path=/";
  }, [frames, behaviour] as [readonly unknown[], MockStreamBehaviour]);
}

async function fulfillJson(route: Route, value: unknown): Promise<void> {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(value)
  });
}

/** Exposed so specs can assert against the same data the page rendered. */
export const mockData = {
  alerts,
  events,
  decisions,
  policies,
  circuits,
  devices,
  fleetHosts,
  alertStats,
  decisionStats,
  sensorHealth,
  baseline,
  intel,
  assistantChats
} as const;

/**
 * An SSE body for /api/assistant/stream.
 *
 * The assistant prefers the streaming endpoint and only falls back to
 * /api/assistant/ask when the client has no askStream — so a spec that mocks
 * only `ask` tests the fallback path and never the one operators use. That is
 * how these tests first failed: every answer came back "the assistant stream
 * ended without an answer", which is the client correctly refusing to read
 * silence as success.
 */
export function assistantStreamBody(answer: Record<string, unknown>): {
  status: number;
  contentType: string;
  body: string;
} {
  const steps = (answer.steps as unknown[]) ?? [];
  const frames = [
    ...steps.map((step) => `event: step\ndata: ${JSON.stringify(step)}\n\n`),
    `event: answer\ndata: ${JSON.stringify(answer)}\n\n`
  ];
  return { status: 200, contentType: "text/event-stream", body: frames.join("") };
}

/** An SSE body that reports a failure rather than an answer. */
export function assistantStreamError(message: string): {
  status: number;
  contentType: string;
  body: string;
} {
  return {
    status: 200,
    contentType: "text/event-stream",
    body: `event: error\ndata: ${JSON.stringify({ error: message })}\n\n`
  };
}
