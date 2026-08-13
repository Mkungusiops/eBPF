export interface PanelSpec {
  title: string;
  testId: string;
  risk?: "L" | "M" | "H";
  body: string;
}

export const socPanels: PanelSpec[] = [
  ["Left sidebar", "soc-left-sidebar", "M", "Persisted navigation rail, live badges, and operator shortcuts."],
  ["Top bar / header", "soc-topbar", "H", "Search DSL, risk gauge, range, host, live state, refresh, theme, and device link."],
  ["Stale-data banner", "soc-stale-banner", "L", "Silent stream detection and force reconnect control."],
  ["Version-update toast", "soc-version-toast", "L", "Reload prompt when /api/version SHA changes."],
  ["KPI row", "soc-kpi-row", "H", "Severity counts, deltas, sparklines, and KPI drill entry."],
  ["Severity timeline", "soc-severity-timeline", "H", "Stacked bars, anomalies, bucket click, brush, and legend toggles."],
  ["Alert triage queue", "soc-alert-triage", "H", "DSL filter, classification, grouping, bulk actions, saved views, keyboard nav."],
  ["Drill-down slide-over", "soc-drill", "H", "Lineage, replay, inline Choke action, origin, and notes."],
  ["MITRE ATT&CK coverage", "soc-mitre-coverage", "L", "Per-policy technique bars."],
  ["Top processes by score", "soc-top-processes", "M", "Lazy origin lookup via /api/process."],
  ["IOCs observed", "soc-iocs", "L", "File and network indicators from events."],
  ["Network connections", "soc-network", "L", "Outbound TCP peers."],
  ["Live event stream", "soc-live-events", "M", "SSE stream, cap 200, pause, regex filter, virtualization."],
  ["Policy viewer modal", "soc-policy-modal", "M", "/api/policies and /api/policy-stats."],
  ["Quick-fire attacks modal", "soc-attacks-modal", "L", "/api/attacks and form-encoded /api/run-attack."],
  ["Process correlation graph modal", "soc-graph-modal", "H", "D3 island with TTL fade, zoom, pan, drag, Live vs Forensic."],
  ["Rule simulator modal", "soc-rule-simulator", "M", "Rule simulation workflow."],
  ["MITRE Navigator modal", "soc-mitre-navigator", "H", "Navigator export and PDF generation."],
  ["Fleet modal", "soc-fleet-modal", "H", "Cross-host probes with credentials included."],
  ["Watchlist modal", "soc-watchlist", "M", "LocalStorage-compatible watchlist."],
  ["Honeypots modal", "soc-honeypots", "H", "/api/honeypots polling."],
  ["Kprobe performance modal", "soc-kprobes", "H", "/api/policy-stats polling."],
  ["Time Machine modal", "soc-time-machine", "H", "Snapshot/live source switch."],
  ["Command palette", "soc-command-palette", "M", "cmdk operator commands."],
  ["Notifications center modal", "soc-notifications", "H", "Read/clear notification center."],
  ["Account / profile modal", "soc-profile", "H", "Avatar shared with Choke."],
  ["KPI drill modal", "soc-kpi-drill", "M", "Severity, EPS, and process variants."],
  ["Pill popovers", "soc-pill-popovers", "H", "Live, host, and risk popovers."],
  ["Help modal", "soc-help", "L", "Operator help surface."],
  ["Export confirm modal + PDF/CSV", "soc-export", "H", "Dynamic jsPDF and CSV export."],
  ["Alert hover preview + context menu", "soc-alert-preview", "M", "Viewport-clamped hover and right-click actions."]
].map(([title, testId, risk, body]) => ({ title, testId, risk: risk as PanelSpec["risk"], body }));

export const chokePanels: PanelSpec[] = [
  ["Topbar Row 1", "choke-topbar-1", "M", "Identity, search, status, user, and devices link."],
  ["Topbar Row 2", "choke-topbar-2", "H", "Range, KPIs, refresh, scope, and action cluster."],
  ["IR Presets trail bar", "choke-presets", "L", "Mode and preset status."],
  ["Stale-stream banner", "choke-stale-banner", "L", "Decision-stream freshness and reconnect."],
  ["Active filter strip", "choke-filter-strip", "L", "DSL chips and clear behavior."],
  ["Threat-Intelligence ribbon", "choke-threat-ribbon", "M", "Derived local threat intelligence cards."],
  ["Engine Stack panel", "choke-engine-stack", "L", "/api/system-health."],
  ["State Ladder panel", "choke-state-ladder", "L", "/api/choke/state."],
  ["Thresholds panel", "choke-thresholds", "H", "Four-handle slider, blast radius, threshold write."],
  ["Cgroup Tiers panel", "choke-cgroup-tiers", "L", "/api/choke/cgroups."],
  ["Choke Map / BPF mirror", "choke-map", "L", "/api/choke/buckets."],
  ["Tracked Processes list", "choke-process-list", "H", "Virtualized circuits, actions, alert chips, origin."],
  ["Decision Tape", "choke-decision-tape", "H", "SSE decisions, cap 400, burst banner, auto-scroll."],
  ["Policy Workbench", "choke-policy-workbench", "M", "Policy preview."],
  ["Process Drill-in slide-over", "choke-drill", "H", "Tracked exec and untracked jail PID variants."],
  ["Jail Process picker modal", "choke-jail-picker", "H", "Process polling, inspect drawer, reason-required jail."],
  ["Host reachability popover", "choke-host-popover", "M", "Endpoint health and latency."],
  ["Live data stream popover", "choke-live-popover", "M", "Stream state and reconnect controls."],
  ["Audit chain popover", "choke-audit-popover", "M", "/api/verify-chain."],
  ["Enforcement mode popover", "choke-mode-popover", "M", "Mode, preset, kill-switch."],
  ["Notifications panel", "choke-notifications", "M", "Operational notices."],
  ["Admin profile dropdown + avatar", "choke-profile", "M", "Avatar shared with SOC."],
  ["Command palette", "choke-command-palette", "M", "cmdk commands."],
  ["Confirm modal", "choke-confirm", "L", "Audit reason and auto-revert."],
  ["Help modal", "choke-help", "L", "Operator help."],
  ["Operations status bar", "choke-status-bar", "L", "Sticky status and clock."]
].map(([title, testId, risk, body]) => ({ title, testId, risk: risk as PanelSpec["risk"], body }));
