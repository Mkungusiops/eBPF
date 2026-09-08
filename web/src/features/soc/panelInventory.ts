import type { SocPanelInventoryItem } from "./types";

export const SOC_PANEL_INVENTORY: SocPanelInventoryItem[] = [
  {
    id: "left-sidebar",
    title: "Left sidebar",
    risk: "M",
    mode: "local",
    description: "Persisted collapse, route links, tool launchers, and live badges.",
    // One key per collapsible nav section, plus the rail's own collapse.
    storage: ["soc.sidebarOpen", "soc.nav.v2.<section>"]
  },
  {
    id: "top-bar",
    title: "Top bar / header",
    risk: "H",
    mode: "live",
    description: "DSL search, risk, time range, host/live/theme controls, and devices link.",
    api: ["/api/whoami", "/api/decisions?limit=1"],
    // No soc.theme. Theme follows the OS (lib/theme.ts, useOSTheme) and is not
    // persisted by this console at all. The time range is one of the two things
    // the top bar keeps; the other is the customer switcher's choice, which
    // SocRoute's selectTenant hands to lib/tenantScope's setSelectedTenant and
    // that writes soc.selectedTenant. The write happens a prop-hop away from the
    // control, which is how this entry came to omit it.
    storage: ["soc.prefDefaultRange", "soc.selectedTenant"]
  },
  {
    id: "stale-data-banner",
    title: "Stale-data banner",
    risk: "L",
    mode: "live",
    description: "Shows when the SOC stream has been silent for more than 30 seconds.",
    api: ["/api/stream"]
  },
  {
    id: "version-update-toast",
    title: "Version-update toast",
    risk: "L",
    mode: "read-only",
    description: "Polls the embedded frontend version and prompts for reload on SHA changes.",
    api: ["/api/version"]
  },
  {
    id: "kpi-row",
    title: "KPI row",
    risk: "H",
    mode: "live",
    description: "Severity counts, EPS, active processes, sparklines, and KPI drill entry.",
    api: ["/api/alerts", "/api/events", "/api/stream"]
  },
  {
    id: "severity-timeline",
    title: "Severity timeline",
    risk: "H",
    mode: "live",
    description: "Stacked severity buckets with anomaly markers, range filtering, and legend toggles.",
    api: ["/api/alerts", "/api/stream"],
    storage: ["soc.timelineSevHidden"]
  },
  {
    id: "alert-triage-queue",
    title: "Alert triage queue",
    risk: "H",
    mode: "live",
    description: "Search, classification, sort, grouping, pinning, local ack state, and keyboard-ready rows.",
    api: ["/api/alerts", "/api/stream"],
    // No soc.savedViews. It was advertised here (and counted on the account
    // page's "N local preference keys" inventory) while nothing in src ever
    // read or wrote it: there is no control to save the current query/sort/chip
    // set and none to restore one. An operator told the panel keeps views goes
    // looking for a control that does not exist, so the claim is withdrawn
    // rather than left standing.
    //
    // soc.groupAlerts and soc.hideBaseline are the queue's own "Group" and
    // "Hide baseline" chips (AlertQueue's actions row); SocRoute holds the state
    // for them, so they were counted on the account page without being named
    // here.
    storage: ["soc.alertStates", "soc.pinnedAlerts", "soc.groupAlerts", "soc.hideBaseline"]
  },
  {
    id: "drill-down-slide-over",
    title: "Drill-down slide-over",
    risk: "H",
    mode: "live",
    description: "Lineage, replay, origin, notes, indicators, and CSRF-protected Choke action controls.",
    api: ["/api/process/{exec_id}", "/api/choke/jail"],
    storage: ["soc.alertNotes"]
  },
  {
    id: "mitre-coverage",
    title: "MITRE ATT&CK coverage",
    risk: "L",
    mode: "read-only",
    description:
      "Which ATT&CK techniques this estate detects, and how many alerts each raised in the selected window. A technique whose probe is live but which raised nothing reads as covered, not as a gap.",
    api: ["/api/policies", "/api/alerts"]
  },
  {
    id: "top-processes",
    title: "Top processes by score",
    risk: "M",
    mode: "read-only",
    description: "Highest aggregate process scores with drill entry and lazy process detail support.",
    api: ["/api/alerts", "/api/process/{exec_id}"]
  },
  {
    id: "iocs-observed",
    title: "IOCs observed",
    risk: "L",
    mode: "read-only",
    description: "File paths from event arguments, and remote addresses the sensor observed on connection events.",
    api: ["/api/events", "/api/alerts"]
  },
  {
    id: "network-connections",
    title: "Network connections",
    risk: "L",
    mode: "read-only",
    description: "Outbound destinations the sensor observed on connection events, with the processes that opened them. Addresses appearing only in command arguments are excluded — those are intent, not traffic.",
    api: ["/api/events"]
  },
  {
    id: "live-event-stream",
    title: "Live event stream",
    risk: "M",
    mode: "live",
    description: "SSE-backed event list with pause, regex filtering, self-noise filter, and list cap.",
    api: ["/api/events", "/api/stream"]
  },
  {
    id: "detections-modal",
    title: "Detections",
    risk: "H",
    // No longer read-only: it can dispatch a signed detection-policy change to
    // every agent in the tenant.
    mode: "write",
    description: "Kernel-loaded detection policies per host, missing and enforcing ones named, and a signed push.",
    api: ["/api/policies", "/api/policies/push"]
  },
  {
    id: "quick-fire-attacks-modal",
    title: "Quick-fire attacks",
    risk: "L",
    mode: "live",
    description: "Attack catalog and CSRF-protected run controls.",
    api: ["/api/attacks", "/api/run-attack"]
  },
  {
    id: "process-correlation-graph-modal",
    title: "Process correlation graph",
    risk: "H",
    mode: "live",
    description: "D3 force graph built from alert, policy, file, and peer correlations.",
    api: ["/api/alerts", "/api/events"]
  },
  {
    id: "rule-simulator-modal",
    title: "Rule simulator",
    risk: "M",
    mode: "local",
    description: "Local score-threshold preview against the current alert buffer.",
    api: ["/api/alerts"],
    storage: ["soc.simThresholds"]
  },
  {
    id: "mitre-navigator-modal",
    title: "MITRE Navigator",
    risk: "H",
    mode: "live",
    description: "Navigator coverage table with PDF export.",
    api: ["/api/policies", "/api/alerts"]
  },
  {
    id: "fleet-console-modal",
    title: "Fleet Console",
    risk: "H",
    mode: "write",
    // The HOSTS rung of the drill: estate, then customer, then hosts, then
    // process. It was a console of its own at /fleet — which is why this entry
    // did not exist and the sidebar's panel count did not include it.
    description:
      "Every enrolled host's mode, enforcement ladder, kill-switch state and drift from the fleet majority — " +
      "and the presets, thresholds, kill-switch and thaw, scoped to all peers or to a named subset of them.",
    api: [
      "/api/fleet/hosts",
      "/api/fleet/state",
      "/api/fleet/cgroups",
      "/api/fleet/decisions",
      "/api/fleet/alerts",
      "/api/fleet/devices",
      "/api/fleet/preset",
      "/api/fleet/thresholds",
      "/api/fleet/kill-switch",
      "/api/fleet/thaw"
    ],
    // Nothing. The host selection, the apply mode and the threshold draft are
    // component state and are gone when the surface closes — which is correct
    // for a target set: a remembered selection is a blast radius an operator
    // did not choose this time.
    storage: []
  },
  {
    id: "fleet-modal",
    // Not the Fleet Console surface above. The rail entry is "Peer Consoles" and
    // this title has to agree with it, or the account page's panel inventory
    // names a surface the operator cannot find in the nav.
    title: "Peer Consoles",
    risk: "H",
    mode: "local",
    description:
      "Operator-maintained directory of OTHER consoles in soc.fleet.hosts; reachability is probed server-side via /api/fleet/probe. It does not enumerate enrolled agents — the Fleet Console surface above does that.",
    storage: ["soc.fleet.hosts"]
  },
  {
    id: "watchlist-modal",
    title: "Watchlist",
    risk: "M",
    mode: "local",
    description: "LocalStorage-compatible watchlist summary for paths, IPs, and binaries.",
    storage: ["soc.watchlist"]
  },
  {
    id: "honeypots-modal",
    title: "Honeypots",
    risk: "H",
    mode: "read-only",
    description: "Decoy status, hit counts, and last-seen data.",
    api: ["/api/honeypots"],
    // No soc.hpUI.* keys. HoneypotsBody holds its search, filter and sort in
    // component state (useState) — they are gone on close, and advertising them
    // as browser storage both misled the operator and over-counted the account
    // page's key inventory.
    storage: []
  },
  {
    id: "behaviour-modal",
    title: "Behaviour & Reputation",
    risk: "H",
    mode: "read-only",
    description:
      "What this deployment has learned is normal, what departed from it, and what matched a threat-intelligence feed.",
    api: ["/api/baseline", "/api/baseline/anomalies", "/api/intel", "/api/intel/matches", "/api/intel/lookup"],
    storage: []
  },
  {
    id: "settings-modal",
    title: "Settings",
    risk: "H",
    mode: "write",
    // What an operator tunes AFTER deployment, as opposed to what the deploy
    // decides. The dividing line is deliberate: anything the deploy rewrites
    // wholesale (engine.yaml, agent.yaml, controlplane.env are whole-file
    // heredocs on every run) is shown here only as an effective value, never
    // as an editable field — a console that edited them would be lying by the
    // next deploy. Secrets are absent entirely.
    description:
      "Tune the platform to this estate. Suppressions stop expected local behaviour from scoring; " +
      "everything the deploy owns is shown read-only.",
    api: ["/api/settings/suppressions"],
    storage: []
  },
  {
    id: "sensor-health-modal",
    title: "Sensor Health & Coverage",
    risk: "H",
    mode: "read-only",
    // Was "Kprobe performance", described here as "rate placeholders" — which
    // undersold it (the rate was real, just derived in the browser) and
    // oversold it (throughput is not performance). The question it answers now
    // is whether detection is running, everywhere it should be, and whether
    // evidence is being lost.
    description: "Agent liveness, kernel policy load state, data-plane attachment, and evidence loss.",
    api: ["/api/sensor-health", "/api/policy-stats"],
    storage: []
  },
  {
    id: "time-machine-modal",
    title: "Time Machine",
    risk: "H",
    mode: "local",
    description: "Snapshot/live source switch shell and local bookmark summary.",
    storage: ["soc.tmBookmarks"]
  },
  {
    id: "command-palette",
    title: "Command palette",
    risk: "M",
    mode: "local",
    description: "Ctrl+K command surface for opening SOC panels and applying local filters."
  },
  {
    id: "notifications-center-modal",
    title: "Notifications center",
    risk: "H",
    mode: "local",
    description: "Local notification history and preferences shell.",
    // The channel toggles, throttle and quiet hours are NotificationsBody's own
    // controls (soc.notifyChannels is held by SocRoute and passed in as
    // channels/onChannelsChange; the other three are written in the body).
    storage: [
      "soc.notifications",
      "soc.notifyHistory",
      "soc.notifyMinSeverity",
      "soc.notifyChannels",
      "soc.notifyThrottleMin",
      "soc.notifyQuietStart",
      "soc.notifyQuietEnd"
    ]
  },
  {
    id: "account-profile-modal",
    title: "Account / profile",
    risk: "H",
    mode: "local",
    // Neither the avatar nor the theme is stored: the avatar is initials derived
    // from the user name, and the theme follows the OS. What this surface has is
    // the identity read and the count of keys below.
    description: "Current user, initials avatar, OS-derived theme, and local SOC storage inventory.",
    api: ["/api/whoami"],
    storage: []
  },
  {
    id: "kpi-drill-modal",
    title: "KPI drill",
    risk: "M",
    mode: "live",
    description: "Severity, EPS, and process drill variants based on current buffers.",
    api: ["/api/alerts", "/api/events"]
  },
  {
    id: "pill-popovers",
    title: "Pill popovers",
    risk: "H",
    mode: "read-only",
    description: "Live, host, and risk popovers with endpoint probes and risk breakdown.",
    api: ["/api/whoami", "/api/alerts", "/api/events", "/api/decisions?limit=1"]
  },
  {
    id: "help-modal",
    title: "Help",
    risk: "L",
    mode: "local",
    description: "Operator help and redesigned shortcut reference."
  },
  {
    id: "export-confirm-modal",
    title: "Export studio",
    risk: "H",
    mode: "live",
    description: "Assemble an incident report, shift handoff, or threat-intel bundle — pick sections, format (PDF/CSV/JSON), and preview before export.",
    api: ["/api/alerts", "/api/events"]
  },
  {
    id: "alert-hover-preview-context-menu",
    title: "Alert hover preview + context menu",
    risk: "M",
    mode: "local",
    description: "Viewport-clamped preview and right-click action surface for alert rows."
  }
];

// EVERY KEY THIS CONSOLE ACTUALLY WRITES, AND NOTHING ELSE. The account surface
// prints this length as "N local preference keys stored in this browser", so a
// key listed here that nothing writes is a lie told with a number. It has been
// one twice: soc.savedViews (no saved-view control was ever built) and, when the
// kprobe board was replaced by SensorHealthBody, its soc.kprobeThreshold and
// soc.kprobeUI.* keys, whose only writer went with it. Withdrawn with them:
// soc.theme (persisted by the console's own toggle until lib/theme.ts made the
// theme follow the OS, and left advertised after its writer went), soc.hpUI.*
// (the honeypot toolbar is component state), soc.graphFilters/Layout/TTL,
// soc.refreshInterval, soc.notifySoundEnabled, soc.prefGroupAlerts and
// soc.prefHideNoise — seventeen keys in all, none of which any writer in src
// produces today. residueStorageKeys.test.ts holds this list to the console's
// real writes in both directions, and holds every panel entry above to it too:
// a key here that no panel claims must be named in that test's
// NOT_A_PANEL_KEY set with a reason, so the next panel-owned key cannot be
// counted on the account page without being attributed to a surface.
// Add a key here only when a writer exists. One entry with a
// <placeholder> stands for the family the writer produces — Sidebar.tsx writes
// one soc.nav.v2.* key per collapsible section — so the count below is families,
// not raw keys.
export const SOC_STORAGE_KEYS = [
  "soc.alertStates",
  "soc.alertNotes",
  "soc.pinnedAlerts",
  "soc.groupAlerts",
  "soc.hideBaseline",
  "soc.timelineSevHidden",
  "soc.prefDefaultRange",
  "soc.execBand",
  "soc.briefingMode",
  "soc.sidebarOpen",
  "soc.nav.v2.<section>",
  "soc.notifications",
  "soc.notifyChannels",
  "soc.notifyHistory",
  "soc.notifyMinSeverity",
  "soc.notifyThrottleMin",
  "soc.notifyQuietStart",
  "soc.notifyQuietEnd",
  "soc.watchlist",
  "soc.fleet.hosts",
  "soc.tmBookmarks",
  "soc.simThresholds",
  "soc.selectedTenant"
] as const;
