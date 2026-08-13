import type { SocPanelInventoryItem } from "./types";

export const SOC_PANEL_INVENTORY: SocPanelInventoryItem[] = [
  {
    id: "left-sidebar",
    title: "Left sidebar",
    risk: "M",
    mode: "local",
    description: "Persisted collapse, route links, tool launchers, and live badges.",
    storage: ["soc.sidebarOpen"]
  },
  {
    id: "top-bar",
    title: "Top bar / header",
    risk: "H",
    mode: "live",
    description: "DSL search, risk, time range, host/live/theme controls, and devices link.",
    api: ["/api/whoami", "/api/decisions?limit=1"],
    storage: ["soc.theme"]
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
    storage: ["soc.alertStates", "soc.pinnedAlerts", "soc.savedViews"]
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
    description: "Technique and tactic counts derived from alerts and policy metadata.",
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
    description: "File paths, remote addresses, and peers extracted from events and alert text.",
    api: ["/api/events", "/api/alerts"]
  },
  {
    id: "network-connections",
    title: "Network connections",
    risk: "L",
    mode: "read-only",
    description: "Outbound TCP peers and source processes seen in the current event window.",
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
    id: "policy-viewer-modal",
    title: "Policy viewer",
    risk: "M",
    mode: "read-only",
    description: "Read-only policy and policy-stat viewer.",
    api: ["/api/policies", "/api/policy-stats"]
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
    api: ["/api/alerts"]
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
    id: "fleet-modal",
    title: "Fleet",
    risk: "H",
    mode: "local",
    description: "Operator-maintained peer directory in soc.fleet.hosts; reachability is probed server-side via /api/fleet/probe.",
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
    storage: ["soc.hpUI.search", "soc.hpUI.filter", "soc.hpUI.sortBy", "soc.hpUI.sortDir"]
  },
  {
    id: "kprobe-performance-modal",
    title: "Kprobe performance",
    risk: "H",
    mode: "read-only",
    description: "Policy post counts and rate placeholders from policy stats.",
    api: ["/api/policy-stats"],
    storage: ["soc.kprobeThreshold", "soc.kprobeUI.search", "soc.kprobeUI.filter"]
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
    storage: ["soc.notifications", "soc.notifyHistory", "soc.notifyMinSeverity"]
  },
  {
    id: "account-profile-modal",
    title: "Account / profile",
    risk: "H",
    mode: "local",
    description: "Current user, shared avatar key, theme, and local SOC storage inventory.",
    api: ["/api/whoami"],
    storage: ["soc.avatar.<user>", "soc.theme"]
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

export const SOC_STORAGE_KEYS = [
  "soc.alertStates",
  "soc.groupAlerts",
  "soc.hideBaseline",
  "soc.timelineSevHidden",
  "soc.notifications",
  "soc.notifyMinSeverity",
  "soc.notifyChannels",
  "soc.notifySoundEnabled",
  "soc.notifyThrottleMin",
  "soc.notifyQuietStart",
  "soc.notifyQuietEnd",
  "soc.notifyHistory",
  "soc.pinnedAlerts",
  "soc.alertNotes",
  "soc.savedViews",
  "soc.refreshInterval",
  "soc.prefDefaultRange",
  "soc.prefGroupAlerts",
  "soc.prefHideNoise",
  "soc.watchlist",
  "soc.fleet.hosts",
  "soc.hpUI.search",
  "soc.hpUI.filter",
  "soc.hpUI.sortBy",
  "soc.hpUI.sortDir",
  "soc.kprobeUI.search",
  "soc.kprobeUI.filter",
  "soc.kprobeUI.sortBy",
  "soc.kprobeUI.sortDir",
  "soc.kprobeThreshold",
  "soc.tmBookmarks",
  "soc.graphFilters",
  "soc.graphLayout",
  "soc.graphTTL",
  "soc.sidebarOpen",
  "soc.theme"
] as const;
