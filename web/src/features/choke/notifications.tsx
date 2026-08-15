// The alerts surface. Choke has no separate alert feed to render — a decision
// that constrained a process IS the alert — so this derives one from the same
// decision tape the route already holds, deduplicated so a burst reads as one
// row rather than dozens of repeats.
import { useMemo, useState } from "react";
import { X } from "lucide-react";
import type { Decision } from "./types";
import { DECISION_CAP } from "./constants";
import { basename, formatRelative } from "./utils";
import { EmptyState, StateBadge } from "./components";

// Severity ladder for the alerts feed, highest first. Drives both ordering
// and the colour of each row's StateBadge.
const ALERT_SEVERITY: Array<{ state: string; label: string }> = [
  { state: "severed", label: "Critical" },
  { state: "quarantined", label: "High" },
  { state: "tarpit", label: "Medium" },
  { state: "throttled", label: "Low" },
];
const ALERT_RANK: Record<string, number> = { severed: 4, quarantined: 3, tarpit: 2, throttled: 1 };

// A decision's effective severity state: prefer the state it moved to, else
// derive it from the action verb.
function decisionState(decision: Decision): string {
  if (decision.to_state && decision.to_state !== "pristine") return decision.to_state;
  const fromAction: Record<string, string> = {
    sever: "severed",
    quarantine: "quarantined",
    tarpit: "tarpit",
    throttle: "throttled",
  };
  return fromAction[decision.action || ""] || decision.to_state || "pristine";
}

interface AlertGroup {
  key: string;
  state: string;
  binary: string;
  reason: string;
  count: number;
  ids: number[];
  unread: number;
  latestTs: number;
  execId?: string;
}

export function NotificationsPanel({
  decisions,
  acked,
  clearedAt,
  alertsActive,
  badgeEnabled,
  onClose,
  onToggleAlerts,
  onToggleBadge,
  onAck,
  onClear,
  onOpenDrill,
}: {
  decisions: Decision[];
  acked: Set<number>;
  clearedAt: number;
  alertsActive: boolean;
  badgeEnabled: boolean;
  onClose: () => void;
  onToggleAlerts: () => void;
  onToggleBadge: () => void;
  onAck: (ids: number[]) => void;
  onClear: () => void;
  onOpenDrill: (execId: string) => void;
}) {
  const [query, setQuery] = useState("");
  const [sevFilter, setSevFilter] = useState<Set<string>>(new Set());

  // Collapse the raw decision tape into deduplicated alert groups keyed by
  // severity + binary + reason, so a burst of identical severs reads as one
  // row with a ×N count instead of dozens of repeats.
  const groups = useMemo<AlertGroup[]>(() => {
    const map = new Map<string, AlertGroup>();
    for (const decision of decisions) {
      const ts = new Date(decision.timestamp || 0).getTime();
      if (clearedAt && ts <= clearedAt) continue;
      const state = decisionState(decision);
      if (!ALERT_RANK[state]) continue; // only constraining escalations are alerts
      const binary = decision.binary || "";
      const reason = decision.reason || basename(decision.binary) || "decision";
      const key = `${state}|${binary}|${reason}`;
      let group = map.get(key);
      if (!group) {
        group = { key, state, binary, reason, count: 0, ids: [], unread: 0, latestTs: 0, execId: decision.exec_id };
        map.set(key, group);
      }
      group.count += 1;
      if (ts >= group.latestTs) {
        group.latestTs = ts;
        if (decision.exec_id) group.execId = decision.exec_id;
      }
      if (decision.id) {
        group.ids.push(decision.id);
        if (!acked.has(decision.id)) group.unread += 1;
      }
    }
    return [...map.values()].sort(
      (a, b) => (ALERT_RANK[b.state] || 0) - (ALERT_RANK[a.state] || 0) || b.latestTs - a.latestTs,
    );
  }, [decisions, clearedAt, acked]);

  const sevCounts = useMemo(() => {
    const counts = new Map<string, number>();
    for (const group of groups) counts.set(group.state, (counts.get(group.state) || 0) + group.count);
    return counts;
  }, [groups]);

  const q = query.trim().toLowerCase();
  const visible = groups.filter(
    (group) =>
      (sevFilter.size === 0 || sevFilter.has(group.state)) &&
      (!q || group.reason.toLowerCase().includes(q) || group.binary.toLowerCase().includes(q)),
  );
  const totalUnread = groups.reduce((sum, group) => sum + group.unread, 0);
  const visibleIds = visible.flatMap((group) => group.ids);

  function toggleSeverity(state: string): void {
    setSevFilter((prev) => {
      const next = new Set(prev);
      if (next.has(state)) next.delete(state);
      else next.add(state);
      return next;
    });
  }

  return (
    <aside className="choke-floating-panel alerts" data-panel="notifications-panel">
      <header>
        <h3>Alerts</h3>
        <span className="choke-notif-count">
          {alertsActive ? `${totalUnread} unread · ${groups.length} grouped` : "silenced"}
        </span>
        <button type="button" className="choke-popover-close" onClick={onClose} aria-label="Close alerts">
          <X size={15} aria-hidden="true" />
        </button>
      </header>

      <div className="choke-alert-controlbar">
        <button type="button" className={!alertsActive ? "active" : ""} onClick={onToggleAlerts}>
          {alertsActive ? "Silence alerts" : "Resume alerts"}
        </button>
        <button type="button" className={!badgeEnabled ? "active" : ""} disabled={!alertsActive} onClick={onToggleBadge}>
          {badgeEnabled ? "Hide 400 badge" : "Show badge"}
        </button>
      </div>

      <div className="choke-alert-sevbar">
        {ALERT_SEVERITY.filter(({ state }) => sevCounts.get(state)).map(({ state, label }) => (
          <button
            key={state}
            type="button"
            className={`choke-alert-sevchip state-${state} ${sevFilter.has(state) ? "active" : ""}`}
            onClick={() => toggleSeverity(state)}
            title={`${label} (${state})`}
          >
            {label} <strong>{sevCounts.get(state)}</strong>
          </button>
        ))}
      </div>

      <input
        className="choke-alert-search"
        type="search"
        value={query}
        placeholder="filter by reason or binary"
        onChange={(event) => setQuery(event.target.value)}
      />

      <div className="choke-alert-list">
        {visible.length === 0 ? (
          <EmptyState
            title={groups.length === 0 ? "No alerts" : "No alerts match"}
            body={groups.length === 0 ? "Constraining decisions (throttle → sever) appear here, grouped by cause." : "Adjust the severity chips or search."}
          />
        ) : null}
        {visible.slice(0, 120).map((group) => (
          <button
            key={group.key}
            type="button"
            className={`choke-alert-row ${group.unread > 0 ? "unread" : "read"}`}
            onClick={() => group.execId && onOpenDrill(group.execId)}
            title={group.execId ? "Open process detail" : "No linked process"}
          >
            <StateBadge state={group.state} />
            <span className="choke-alert-reason">{group.reason}</span>
            <span className="choke-alert-meta">
              {group.binary ? <code className="truncate">{basename(group.binary)}</code> : null}
              <em>{formatRelative(group.latestTs)}</em>
            </span>
            {group.count > 1 ? <span className="choke-alert-count">×{group.count}</span> : null}
          </button>
        ))}
      </div>

      <footer>
        <button type="button" disabled={!totalUnread} onClick={() => onAck(visibleIds)}>
          Mark all read
        </button>
        <button type="button" className="danger" disabled={groups.length === 0} onClick={onClear}>
          Clear all
        </button>
      </footer>
    </aside>
  );
}

export function NotificationDot({
  decisions,
  acked,
  clearedAt,
  enabled,
}: {
  decisions: Decision[];
  acked: Set<number>;
  clearedAt: number;
  enabled: boolean;
}) {
  if (!enabled) return null;
  const unread = decisions.filter((decision) => {
    const ts = new Date(decision.timestamp || 0).getTime();
    if (clearedAt && ts <= clearedAt) return false;
    if (!ALERT_RANK[decisionState(decision)]) return false;
    return !acked.has(decision.id || 0);
  }).length;
  return unread > 0 ? <span className="choke-notif-dot">{unread >= DECISION_CAP ? `${DECISION_CAP}` : unread}</span> : null;
}
