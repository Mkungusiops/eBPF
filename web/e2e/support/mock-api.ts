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
    message: "credential access"
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

export async function installMockApi(page: Page): Promise<void> {
  await installMockEventSource(page);

  await page.route("**/api/**", async (route) => {
    const request = route.request();
    const url = new URL(request.url());
    const path = url.pathname;

    if (request.method() !== "GET") {
      await fulfillJson(route, writeResponse(path));
      return;
    }

    await fulfillJson(route, readResponse(path));
  });
}

async function installMockEventSource(page: Page): Promise<void> {
  await page.addInitScript((frames) => {
    class MockEventSource {
      static CONNECTING = 0;
      static OPEN = 1;
      static CLOSED = 2;

      url;
      readyState = MockEventSource.CONNECTING;
      onopen = null;
      onmessage = null;
      onerror = null;

      constructor(url) {
        this.url = String(url);
        window.setTimeout(() => {
          if (this.readyState === MockEventSource.CLOSED) return;
          this.readyState = MockEventSource.OPEN;
          this.onopen?.(new Event("open"));
          for (const frame of frames) {
            this.onmessage?.(new MessageEvent("message", { data: JSON.stringify(frame) }));
          }
        }, 10);
      }

      close() {
        this.readyState = MockEventSource.CLOSED;
      }

      addEventListener(type, listener) {
        if (type === "open") this.onopen = listener;
        if (type === "message") this.onmessage = listener;
        if (type === "error") this.onerror = listener;
      }

      removeEventListener() {
        return undefined;
      }

      dispatchEvent() {
        return true;
      }
    }

    Object.defineProperty(window, "EventSource", {
      configurable: true,
      value: MockEventSource
    });
    document.cookie = "csrf_token=mock-csrf; path=/";
  }, fakeModeStreamFrames);
}

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
      return [
        {
          name: "override-credential-read",
          description: "Fixture credential access policy",
          mitre: "T1003",
          sensors: ["file_open"]
        }
      ];
    case "/api/policy-stats":
      return [{ name: "override-credential-read", posts: 4, rate_per_min: 1.2, status: "active" }];
    case "/api/attacks":
      return [{ id: "credential-read", name: "Credential Read", severity: "critical" }];
    case "/api/honeypots":
      return [{ path: "/srv/decoy", hits: 2, last_seen: now }];
    case "/api/system-health":
      return { status: "ok", host: "mock-host", tetragon: "running", choke: "running", kernel: "6.8" };
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
      return {};
  }
}

function writeResponse(path: string): unknown {
  if (path === "/api/choke/policy/preview") {
    return {
      valid: true,
      policy: {
        metadata: {
          name: "fixture-live",
          description: "Fixture dry-run preview"
        },
        match: {
          binaries: ["/usr/bin/cat"]
        },
        buckets: [{ dimension: "egress.connect", rate_per_sec: 5, burst: 10 }]
      },
      matches: circuits,
      scanned: circuits.length
    };
  }
  if (path.includes("device-jail") || path.includes("device-thaw")) {
    return { action: "throttle", reason: "fixture", results: [{ mac: devices[0].mac, ok: true, state: "throttled" }] };
  }
  if (path.includes("fleet/")) {
    return { hosts: fleetHosts.map((peer) => ({ name: peer.name, url: peer.url, ok: true, status: 200 })) };
  }
  return { ok: true, audit: { ok: true, total: 3 } };
}

async function fulfillJson(route: Route, value: unknown): Promise<void> {
  await route.fulfill({
    status: 200,
    contentType: "application/json",
    body: JSON.stringify(value)
  });
}
