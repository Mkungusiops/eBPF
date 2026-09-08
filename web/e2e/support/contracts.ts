export type AppRouteName = "login" | "soc" | "choke" | "devices" | "fleet";

export type AppRoute = {
  name: AppRouteName;
  path: "/" | "/login" | "/choke" | "/devices" | "/fleet";
  entry: "login" | "soc" | "choke" | "devices" | "fleet";
  /**
   * The document title once the address has SETTLED. For a redirect that is the
   * title of the page it lands on, which is why /fleet now carries the SOC
   * console's.
   */
  title: RegExp;
  public: boolean;
  /**
   * Certified panels reachable at this address, and the four route counts sum
   * to the release scope. It is not `SOC_PANEL_INVENTORY.length` and never was
   * — that is one console's self-description; this is the release tally.
   */
  panelCount: number;
  /**
   * Set when the address is a signpost rather than a page: the console it
   * redirects into, fragment included. /fleet is the only one — the fleet view
   * is a surface of the SOC console now, and the URL was kept because bookmarks,
   * the live probe suite and the command palette all still use it.
   */
  redirectsTo?: string;
};

/**
 * The URL fragment that names the fleet surface.
 *
 * Stated here as well as in src/features/fleet/address.ts, deliberately: this
 * file is the contract the browser suite asserts AGAINST, so it has to say what
 * the address is rather than import the implementation's opinion of it. The two
 * are held together by e2e/fleet.spec.ts, which reaches the surface through
 * this constant and then checks the redirect actually lands on it.
 */
export const FLEET_SURFACE_HASH = "#fleet";

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
    // 31 + the fleet console's 13. The thirteen did not disappear and no new
    // one was certified: the fleet view moved in from its own address as a
    // surface, so the panels an operator reaches at "/" grew by exactly what
    // /fleet stopped serving. TOTAL_PANEL_COUNT is unchanged, which is the
    // point — the release scope was conserved, not re-tallied.
    panelCount: 44
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
    // KEPT, AND STILL PROTECTED. /fleet is no longer a console: the entry's
    // only job is to redirect into the SOC console with the fleet surface open
    // (src/entries/fleet.tsx). The row stays because the address stays — the
    // server still serves and still auth-gates it, operators still have it
    // bookmarked, and e2e/probe/console.probe.spec.ts still signs in AT it.
    //
    // Zero panels, because it renders none: what an operator sees a moment
    // later is the SOC route's, counted there. Counting the fleet surface here
    // as well would tally the same thirteen panels twice.
    name: "fleet",
    path: "/fleet",
    entry: "fleet",
    title: /eBPF SOC/i,
    public: false,
    panelCount: 0,
    // Kept literal rather than built from FLEET_SURFACE_HASH: `as const` on the
    // array is what gives every other field its literal type, and a template
    // literal would widen this one to `string`.
    redirectsTo: "/#fleet"
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

/**
 * Every state-changing route the console can reach, used to prove that each
 * one is stopped by the CSRF middleware.
 *
 * `/api/choke/policy/preview` was removed from this list on 2026-08-27: BOTH
 * servers deliberately deleted the route along with the console surface that
 * called it (see the note in engine/internal/api/http.go). Leaving it here made
 * the CSRF suite assert against a path nothing routes — an assertion that can
 * only pass, because the middleware rejects an unsafe method before routing
 * ever happens. A test that cannot fail for the right reason is worse than one
 * fewer test.
 */
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
  /**
   * Routes that open no stream at all. "fleet" left this list when /fleet
   * stopped being a console: the address now lands on the SOC route, which IS
   * an SSE consumer. The fleet VIEW is still poll-only — see pollOnlySurfaces.
   */
  pollOnlyRoutes: ["devices"],
  /**
   * Surfaces inside an SSE-consuming route that read by polling anyway. The
   * fleet surface fans six requests across every configured peer every five
   * seconds and has no stream behind it, which is why it stops polling the
   * moment it is closed and why it carries its own poll-health readout rather
   * than borrowing the shell's live pill.
   */
  pollOnlySurfaces: ["fleet-console-modal"],
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

// ── SOC surfaces ───────────────────────────────────────────────────────────

/**
 * Every overlay surface the SOC route can open, and how an operator reaches it.
 *
 * This is a CONTRACT, not a convenience: the console's sidebar advertises a
 * fixed set of tools and its own footer counts them ("N SOC panels"). A tool
 * that is advertised and cannot be opened, or opens onto a body that throws, is
 * the failure this list exists to make impossible to ship quietly.
 *
 * `labOnly` surfaces are hidden unless the server reports lab_mode — the demo
 * injectors write fabricated findings into a tenant's real evidence store, so
 * they are off on every customer deployment and their absence is correct.
 */
export type SocSurface = {
  /** The sidebar control's accessible name. */
  nav: string;
  /** The data-panel the surface's shell carries once open. */
  panel: string;
  /** Text that must appear inside the opened surface — proves the BODY rendered,
   *  not merely that an empty shell was un-hidden. */
  contains: RegExp;
  labOnly?: boolean;
  /** Reachable from the sidebar only when no assistant is configured. */
  assistantFallbackOnly?: boolean;
  /**
   * The rail control is an ANCHOR, not a button: the surface has an address of
   * its own that must keep working (a bookmark, the live probe's sign-in
   * target, the command palette's route entry), and a plain click opens it in
   * place instead of paying for the round trip. A harness that reaches surfaces
   * with `socNavItem` (getByRole("button")) will not find these — use
   * `socNavLink`. Only the fleet console is one.
   */
  navIsLink?: boolean;
};

export const SOC_SURFACES: readonly SocSurface[] = [
  // First, as it is in the rail: the fleet view sits in Respond beside the two
  // choke gateways, because it answers the same question they do. It was a
  // console at /fleet until the two were merged, which is why this list did not
  // carry it.
  {
    nav: "Fleet Console",
    panel: "fleet-console-modal",
    contains: /host|fleet|threshold|kill-switch/i,
    navIsLink: true
  },
  { nav: "MITRE Coverage", panel: "mitre-navigator-modal", contains: /technique|ATT&CK|coverage/i },
  { nav: "Correlation Graph", panel: "process-correlation-graph-modal", contains: /graph|process|correlat/i },
  { nav: "Time Machine", panel: "time-machine-modal", contains: /snapshot|replay|window|time/i },
  {
    nav: "Behaviour & Intel",
    panel: "behaviour-modal",
    contains: /baseline|anomal|intel|normal/i,
    assistantFallbackOnly: true
  },
  { nav: "Watchlist", panel: "watchlist-modal", contains: /watchlist|path|binar/i },
  { nav: "Policies", panel: "detections-modal", contains: /detection|policy|policies/i },
  { nav: "Peer Consoles", panel: "fleet-modal", contains: /host|peer|fleet/i },
  { nav: "Sensor Health", panel: "sensor-health-modal", contains: /agent|sensor|policies|kernel/i },
  { nav: "Settings", panel: "settings-modal", contains: /noise|response|guardrails|evidence/i },
  { nav: "Reports", panel: "export-confirm-modal", contains: /export|report|csv|pdf/i },
  { nav: "Notifications", panel: "notifications-center-modal", contains: /notification|channel|read/i },
  { nav: "Help", panel: "help-modal", contains: /command palette|focus search|close modal/i },
  { nav: "Rule Simulator", panel: "rule-simulator-modal", contains: /threshold|severity|simulat/i, labOnly: true },
  { nav: "Attack Sim", panel: "quick-fire-attacks-modal", contains: /attack|run|engine host/i, labOnly: true },
  { nav: "Honeypots", panel: "honeypots-modal", contains: /honeypot|decoy|hits/i, labOnly: true }
];

export const SOC_SURFACES_ALWAYS_AVAILABLE = SOC_SURFACES.filter(
  (surface) => !surface.labOnly && !surface.assistantFallbackOnly
);

export const SOC_LAB_SURFACES = SOC_SURFACES.filter((surface) => surface.labOnly);

/**
 * Every /api path the console is allowed to request.
 *
 * Both servers were enumerated to build this (engine/internal/api/http.go and
 * engine/internal/controlplane/*.go). A path the console asks for that is NOT
 * here is either a typo or a route nobody implements — and an unimplemented
 * route does not look broken in the browser, it looks like a quiet panel.
 * Entries ending in "/" match by prefix (path parameters).
 */
export const SERVED_API_PATHS = [
  "/api/alert-stats",
  "/api/alerts",
  "/api/approvals",
  "/api/approvals/decide",
  "/api/approvals/policy",
  "/api/assistant",
  "/api/assistant/ask",
  "/api/assistant/chats",
  "/api/assistant/chats/",
  "/api/assistant/stream",
  "/api/attacks",
  "/api/baseline",
  "/api/baseline/anomalies",
  "/api/choke/annotate",
  "/api/choke/buckets",
  "/api/choke/bulk-manual",
  "/api/choke/cgroups",
  "/api/choke/circuits",
  "/api/choke/device-flows",
  "/api/choke/device-jail",
  "/api/choke/device-kill-switch",
  "/api/choke/device-mode",
  "/api/choke/device-state",
  "/api/choke/device-thaw",
  "/api/choke/devices",
  "/api/choke/forensic-snapshot",
  "/api/choke/forget",
  "/api/choke/jail",
  "/api/choke/kill-switch",
  "/api/choke/manual",
  "/api/choke/mode",
  "/api/choke/policies",
  "/api/choke/preset",
  "/api/choke/proc/",
  "/api/choke/process/",
  "/api/choke/processes",
  "/api/choke/state",
  "/api/choke/thaw",
  "/api/choke/thresholds",
  "/api/decision-stats",
  "/api/decisions",
  "/api/events",
  "/api/fleet/alerts",
  "/api/fleet/cgroups",
  "/api/fleet/decisions",
  "/api/fleet/device-jail",
  "/api/fleet/devices",
  "/api/fleet/hosts",
  "/api/fleet/kill-switch",
  "/api/fleet/preset",
  "/api/fleet/probe",
  "/api/fleet/state",
  "/api/fleet/thaw",
  "/api/fleet/thresholds",
  "/api/honeypots",
  "/api/intel",
  "/api/intel/lookup",
  "/api/intel/matches",
  "/api/login",
  "/api/logout",
  "/api/operator-audit",
  "/api/origin",
  "/api/platform-doc",
  "/api/policies",
  "/api/policies/push",
  "/api/policy-stats",
  "/api/process/",
  "/api/run-attack",
  "/api/sensor-health",
  "/api/settings/change-control",
  "/api/settings/protected",
  "/api/settings/retention",
  "/api/settings/suppressions",
  "/api/stream",
  "/api/system-health",
  "/api/telemetry",
  "/api/verify-chain",
  "/api/verify-chain/repair",
  "/api/version",
  "/api/whoami"
] as const;

export function isServedApiPath(path: string): boolean {
  return SERVED_API_PATHS.some((served) =>
    served.endsWith("/") ? path.startsWith(served) : path === served
  );
}
