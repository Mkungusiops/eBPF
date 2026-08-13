import type { Alert, Severity } from "./types";

const severityOrder: Severity[] = ["critical", "high", "medium", "low", "info"];

export function severityOf(alert: Alert): Severity {
  const value = String(alert.severity ?? "").toLowerCase();
  return severityOrder.includes(value as Severity) ? (value as Severity) : "info";
}

export function classifyAlert(alert: Alert): "attack" | "threat" | "baseline" {
  const text = `${alert.policy_name ?? ""} ${alert.binary ?? ""} ${alert.reason ?? ""} ${alert.message ?? ""}`.toLowerCase();
  if (/(attack|reverse shell|credential|crypto|exfil|privilege|mitre)/.test(text)) return "attack";
  if ((alert.score ?? 0) >= 20 || ["critical", "high"].includes(severityOf(alert))) return "threat";
  return "baseline";
}

export function riskScore(alerts: Alert[]): number {
  const weights: Record<Severity, number> = { critical: 8, high: 3, medium: 1, low: 0, info: 0 };
  return Math.min(
    100,
    alerts.reduce((sum, alert) => sum + weights[severityOf(alert)], 0)
  );
}
