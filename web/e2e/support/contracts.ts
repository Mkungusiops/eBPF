export type AppRouteName = "login" | "soc" | "choke" | "devices" | "fleet";

export type AppRoute = {
  name: AppRouteName;
  path: "/" | "/login" | "/choke" | "/devices" | "/fleet";
  entry: "login" | "soc" | "choke" | "devices" | "fleet";
  title: RegExp;
  public: boolean;
  panelCount: number;
};

export const PAGE_ROUTES = [
  {
    name: "login",
    path: "/login",
    entry: "login",
    title: /eBPF Login/i,
    public: true,
    panelCount: 1
  },
  {
    name: "soc",
    path: "/",
    entry: "soc",
    title: /eBPF SOC/i,
    public: false,
    panelCount: 31
  },
  {
    name: "choke",
    path: "/choke",
    entry: "choke",
    title: /eBPF Choke/i,
    public: false,
    panelCount: 26
  },
  {
    name: "devices",
    path: "/devices",
    entry: "devices",
    title: /eBPF Devices/i,
    public: false,
    panelCount: 7
  },
  {
    name: "fleet",
    path: "/fleet",
    entry: "fleet",
    title: /eBPF Fleet/i,
    public: false,
    panelCount: 13
  }
] as const satisfies readonly AppRoute[];

export const PROTECTED_PAGE_ROUTES = PAGE_ROUTES.filter((route) => !route.public);

export const TOTAL_PANEL_COUNT = PAGE_ROUTES.reduce(
  (sum, route) => sum + route.panelCount,
  0
);

export const VITE_HTML_ENTRIES = [
  { route: "soc", html: "index.html", script: "/src/entries/soc.tsx" },
  { route: "choke", html: "choke.html", script: "/src/entries/choke.tsx" },
  { route: "devices", html: "devices.html", script: "/src/entries/devices.tsx" },
  { route: "fleet", html: "fleet.html", script: "/src/entries/fleet.tsx" },
  { route: "login", html: "login.html", script: "/src/entries/login.tsx" }
] as const;

export type UnsafeWriteEndpoint = {
  name: string;
  path: string;
  method: "POST" | "PUT";
  encoding: "json" | "form";
  body: Record<string, unknown>;
};

export const UNSAFE_WRITE_ENDPOINTS = [
  {
    name: "run attack",
    path: "/api/run-attack",
    method: "POST",
    encoding: "form",
    body: { id: "csrf-smoke" }
  },
  {
    name: "choke thresholds",
    path: "/api/choke/thresholds",
    method: "PUT",
    encoding: "json",
    body: { low: 5, medium: 10, high: 20, critical: 40, reason: "csrf smoke" }
  },
  {
    name: "choke manual",
    path: "/api/choke/manual",
    method: "POST",
    encoding: "json",
    body: { exec_id: "csrf-smoke", action: "throttle", reason: "csrf smoke" }
  },
  {
    name: "choke bulk manual",
    path: "/api/choke/bulk-manual",
    method: "POST",
    encoding: "json",
    body: { exec_ids: ["csrf-smoke"], action: "throttle", reason: "csrf smoke" }
  },
  {
    name: "choke kill switch",
    path: "/api/choke/kill-switch",
    method: "POST",
    encoding: "json",
    body: { on: false, reason: "csrf smoke" }
  },
  {
    name: "choke policy preview",
    path: "/api/choke/policy/preview",
    method: "POST",
    encoding: "json",
    body: { yaml: "apiVersion: cilium.io/v1alpha1\nkind: ChokePolicy\n" }
  },
  {
    name: "choke preset",
    path: "/api/choke/preset",
    method: "POST",
    encoding: "json",
    body: { preset: "maintenance", reason: "csrf smoke" }
  },
  {
    name: "choke mode",
    path: "/api/choke/mode",
    method: "POST",
    encoding: "json",
    body: { enforcing: false, reason: "csrf smoke" }
  },
  {
    name: "choke forget",
    path: "/api/choke/forget",
    method: "POST",
    encoding: "json",
    body: { exec_ids: ["csrf-smoke"], reason: "csrf smoke" }
  },
  {
    name: "choke thaw",
    path: "/api/choke/thaw",
    method: "POST",
    encoding: "json",
    body: { exec_ids: ["csrf-smoke"], reason: "csrf smoke" }
  },
  {
    name: "choke annotate",
    path: "/api/choke/annotate",
    method: "POST",
    encoding: "json",
    body: { exec_id: "csrf-smoke", note: "csrf smoke" }
  },
  {
    name: "choke jail",
    path: "/api/choke/jail",
    method: "POST",
    encoding: "json",
    body: { pid: 1, action: "throttle", reason: "csrf smoke" }
  },
  {
    name: "device jail",
    path: "/api/choke/device-jail",
    method: "POST",
    encoding: "json",
    body: {
      macs: ["02:00:00:00:00:01"],
      action: "throttle",
      reason: "csrf smoke"
    }
  },
  {
    name: "device thaw",
    path: "/api/choke/device-thaw",
    method: "POST",
    encoding: "json",
    body: { macs: ["02:00:00:00:00:01"], reason: "csrf smoke" }
  },
  {
    name: "device mode",
    path: "/api/choke/device-mode",
    method: "POST",
    encoding: "json",
    body: { enforcing: false, reason: "csrf smoke" }
  },
  {
    name: "device kill switch",
    path: "/api/choke/device-kill-switch",
    method: "POST",
    encoding: "json",
    body: { on: false }
  },
  {
    name: "fleet probe",
    path: "/api/fleet/probe",
    method: "POST",
    encoding: "json",
    body: { urls: ["https://peer.invalid"] }
  },
  {
    name: "fleet preset",
    path: "/api/fleet/preset",
    method: "POST",
    encoding: "json",
    body: { preset: "maintenance", targets: null, reason: "csrf smoke" }
  },
  {
    name: "fleet thresholds",
    path: "/api/fleet/thresholds",
    method: "PUT",
    encoding: "json",
    body: {
      low: 5,
      medium: 10,
      high: 20,
      critical: 40,
      targets: null,
      reason: "csrf smoke"
    }
  },
  {
    name: "fleet kill switch",
    path: "/api/fleet/kill-switch",
    method: "POST",
    encoding: "json",
    body: { on: false, targets: null, reason: "csrf smoke" }
  },
  {
    name: "fleet thaw",
    path: "/api/fleet/thaw",
    method: "POST",
    encoding: "json",
    body: { targets: null, reason: "csrf smoke" }
  },
  {
    name: "fleet device jail",
    path: "/api/fleet/device-jail",
    method: "POST",
    encoding: "json",
    body: {
      mac: "02:00:00:00:00:01",
      action: "throttle",
      targets: null,
      reason: "csrf smoke"
    }
  }
] as const satisfies readonly UnsafeWriteEndpoint[];

export const FORM_ENCODED_WRITE_PATHS = ["/api/run-attack"] as const;

export const SSE_CONTRACT = {
  endpoint: "/api/stream",
  consumers: ["soc", "choke"],
  pollOnlyRoutes: ["devices", "fleet"],
  heartbeatType: "heartbeat",
  staleAfterMs: 30_000,
  watchdogAfterMs: 45_000,
  maxReconnectDelayMs: 30_000
} as const;

export const RUNTIME_CDN_PATTERNS = [
  /cdn\.tailwindcss\.com/i,
  /cdnjs\.cloudflare\.com/i,
  /cdn\.jsdelivr\.net/i,
  /unpkg\.com/i,
  /esm\.sh/i
] as const;
