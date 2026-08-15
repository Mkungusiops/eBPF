// Alert-side maths for the dashboard: what the triage queue shows, how the
// severity timeline is bucketed, and how a raw alert becomes a scored, sorted,
// classified row.
//
// Pure functions over the buffers — no React, no fetching — so the same
// derivation can be re-used by the KPI drill-downs, the export studio and the
// tests without dragging a component along with it.
import type { AlertStats } from "./api";
import { SEVERITIES, SEVERITY_WEIGHT, type AlertGroup, type SortField, type TimelineBucket } from "./dashboard";
import type { AlertClassification, Severity, SocAlert, SocEvent } from "./types";

// How many columns the severity timeline draws. Shared with the server request
// so the buckets it returns line up with what the chart expects.
export const TIMELINE_BUCKETS = 30;

// serverTimeline adapts server buckets to the chart's shape, applying the
// legend's severity toggles client-side (they are a view filter, not a query).
// Anomaly marking uses the same mean+2σ rule as the client-side builder.
export function serverTimeline(stats: AlertStats, hidden: Set<Severity>): TimelineBucket[] {
  const buckets = stats.buckets.map((bucket) => {
    const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
    let total = 0;
    for (const severity of SEVERITIES) {
      if (hidden.has(severity)) continue;
      counts[severity] = bucket.counts[severity] || 0;
      total += counts[severity];
    }
    const at = new Date(bucket.at);
    const label = Number.isNaN(at.getTime())
      ? ""
      : `${String(at.getHours()).padStart(2, "0")}:${String(at.getMinutes()).padStart(2, "0")}`;
    return { label, total, anomaly: false, counts };
  });
  const totals = buckets.map((b) => b.total);
  const avg = totals.reduce((sum, v) => sum + v, 0) / Math.max(1, totals.length);
  const variance = totals.reduce((sum, v) => sum + (v - avg) ** 2, 0) / Math.max(1, totals.length);
  const std = Math.sqrt(variance);
  return buckets.map((b) => ({ ...b, anomaly: b.total > avg + std * 2 && b.total > 2 }));
}

export function countSeverities(alerts: SocAlert[]): Record<Severity, number> {
  return alerts.reduce(
    (acc, alert) => {
      acc[alert.severity] += 1;
      return acc;
    },
    { critical: 0, high: 0, medium: 0, low: 0, info: 0 }
  );
}

export function buildTimeline(
  alerts: SocAlert[],
  rangeMin: number,
  now: number,
  hidden: Set<Severity>,
  bucketCount = 30
): TimelineBucket[] {
  const rangeMs = rangeMin * 60_000;
  const bucketMs = Math.max(1, rangeMs / bucketCount);
  const buckets = Array.from({ length: bucketCount }, (_, index) => {
    const bucketTime = new Date(now - rangeMs + bucketMs * index);
    return {
      label: `${String(bucketTime.getHours()).padStart(2, "0")}:${String(bucketTime.getMinutes()).padStart(2, "0")}`,
      total: 0,
      anomaly: false,
      counts: { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>
    };
  });

  for (const alert of alerts) {
    if (hidden.has(alert.severity)) continue;
    const offset = Date.parse(alert.timestamp) - (now - rangeMs);
    const index = Math.max(0, Math.min(bucketCount - 1, Math.floor(offset / bucketMs)));
    buckets[index].counts[alert.severity] += 1;
    buckets[index].total += 1;
  }

  const totals = buckets.map((bucket) => bucket.total);
  const avg = totals.reduce((sum, value) => sum + value, 0) / Math.max(1, totals.length);
  const variance = totals.reduce((sum, value) => sum + (value - avg) ** 2, 0) / Math.max(1, totals.length);
  const std = Math.sqrt(variance);
  return buckets.map((bucket) => ({ ...bucket, anomaly: bucket.total > avg + std * 2 && bucket.total > 2 }));
}

export function groupAlertList(alerts: SocAlert[]): AlertGroup[] {
  const groups = new Map<string, SocAlert[]>();
  for (const alert of alerts) {
    const key = `${alert.severity}:${alert.policyName || ""}:${alert.process || ""}:${alert.title}`;
    groups.set(key, [...(groups.get(key) || []), alert]);
  }
  return [...groups.values()].map((members) => ({ ...members[0], groupCount: members.length, members }));
}

export function compareAlerts(a: SocAlert, b: SocAlert, sortField: SortField, pinned: Set<string>) {
  const ap = pinned.has(a.id) ? 1 : 0;
  const bp = pinned.has(b.id) ? 1 : 0;
  if (ap !== bp) return bp - ap;
  if (sortField === "severity") return SEVERITY_WEIGHT[b.severity] - SEVERITY_WEIGHT[a.severity];
  if (sortField === "score") return b.score - a.score;
  return Date.parse(b.timestamp) - Date.parse(a.timestamp);
}

export function matchesQuery(alert: SocAlert, query: string): boolean {
  const raw = query.trim();
  if (!raw) return true;
  const haystack = [alert.title, alert.description, alert.policyName, alert.process, alert.execId, alert.pid, alert.severity, alert.score]
    .filter(Boolean)
    .join(" ")
    .toLowerCase();

  return raw
    .split(/\s+/)
    .filter(Boolean)
    .every((token) => {
      const lower = token.toLowerCase();
      if (lower.startsWith("severity:")) return alert.severity === lower.slice("severity:".length);
      if (lower.startsWith("policy:")) return (alert.policyName || "").toLowerCase().includes(lower.slice("policy:".length));
      if (lower.startsWith("process:")) return (alert.process || "").toLowerCase().includes(lower.slice("process:".length));
      if (lower.startsWith("exec:")) return (alert.execId || "").toLowerCase().includes(lower.slice("exec:".length));
      if (lower.startsWith("pid:")) return String(alert.pid || "").includes(lower.slice("pid:".length));
      if (lower.startsWith("score:>")) return alert.score > Number(lower.slice("score:>".length));
      if (lower.startsWith("score:<")) return alert.score < Number(lower.slice("score:<".length));
      if (lower.startsWith("/") && lower.endsWith("/") && lower.length > 2) {
        try {
          return new RegExp(lower.slice(1, -1), "i").test(haystack);
        } catch {
          return false;
        }
      }
      return haystack.includes(lower);
    });
}

export function classifyAlert(alert: SocAlert): AlertClassification {
  const text = `${alert.title} ${alert.description} ${alert.process || ""} ${alert.policyName || ""}`.toLowerCase();
  if (/attack|credential|reverse|shell|exfil|privilege|t1003|t1059|t1105/.test(text) || alert.score >= 70) return "attack";
  if (/cron|systemd|motd|apt|snapd|journald|dbus/.test(text) && alert.score < 35) return "baseline";
  if (alert.score >= 20 || alert.severity === "critical" || alert.severity === "high") return "threat";
  return "unknown";
}

export function classificationLabel(classification: AlertClassification): string {
  if (classification === "attack") return "attack path";
  if (classification === "threat") return "threat";
  if (classification === "baseline") return "baseline";
  return "unknown origin";
}

export function classifyScore(score: number, low: number, medium: number, high: number, critical: number): Severity {
  if (score >= critical) return "critical";
  if (score >= high) return "high";
  if (score >= medium) return "medium";
  if (score >= low) return "low";
  return "info";
}

export function processSummary(alerts: SocAlert[], events: SocEvent[]) {
  const ids = new Set<string>();
  const scores = new Map<string, number>();
  for (const alert of alerts) {
    const id = alert.execId || alert.process || alert.id;
    const label = readableProcessLabel(alert);
    ids.add(id);
    scores.set(label, (scores.get(label) || 0) + alert.score);
  }
  for (const event of events) {
    if (event.execId || event.process) ids.add(event.execId || event.process || event.id);
  }
  const top = [...scores.entries()].sort((a, b) => b[1] - a[1])[0]?.[0];
  return { count: ids.size, top };
}

export function topProcessRows(alerts: SocAlert[]) {
  const rows = new Map<string, { process: string; score: number; count: number; execId?: string; pid?: number }>();
  for (const alert of alerts) {
    // Prefer a readable binary (the leaf of the alert's chain title) over the
    // opaque base64 exec_id, then fall back to the PID — so rows are always
    // human-legible instead of "ZDJlMjUwYjE…".
    const label = readableProcessLabel(alert);
    const key = alert.execId || label;
    const row = rows.get(key) || { process: label, score: 0, count: 0, execId: alert.execId, pid: alert.pid };
    row.score += alert.score;
    row.count += 1;
    if (row.pid === undefined) row.pid = alert.pid;
    rows.set(key, row);
  }
  return [...rows.values()].sort((a, b) => b.score - a.score).slice(0, 10);
}

export function readableProcessLabel(alert: SocAlert) {
  const chain = processChainFromAlert(alert);
  return (
    chain.at(-1) ||
    (alert.process && alert.process.startsWith("/") ? alert.process : undefined) ||
    (alert.pid ? `pid ${alert.pid}` : alert.process || alert.execId || "unknown")
  );
}

// Pull the ordered binary chain out of an alert title such as
// "Suspicious chain: /usr/sbin/runc → /bin/sh → /usr/local/bin/pg_isready (score 17)".
export function processChainFromAlert(alert: SocAlert): string[] {
  if (alert.process && alert.process.startsWith("/")) return [alert.process];
  return alert.title.match(/\/[^\s→()]+/g) ?? [];
}
