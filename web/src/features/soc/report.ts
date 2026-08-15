// The shape of an exported report and the plumbing that hands a file to the
// browser. The MODEL BUILDER lives with the export studio in SocRoute.tsx,
// because what a report is allowed to claim is a product decision, not a
// serialisation detail — see buildExportModel and coverageLabel there.
import type { Severity } from "./types";

export type ExportFormat = "pdf" | "csv" | "json";
export type ExportSection = "summary" | "alerts" | "events" | "decisions" | "iocs" | "mitre";
export const EXPORT_SECTIONS: ExportSection[] = ["summary", "alerts", "events", "decisions", "iocs", "mitre"];

export interface ExportModel {
  meta: { generated: string; host: string; user: string; sha: string; scope: string; rangeFrom: string; rangeTo: string };
  summary: { risk: number; total: number; counts: Record<Severity, number>; events: number; decisions: number; iocs: number; coveragePct: number; coverageMeasurable: boolean };
  alerts: Array<{ severity: string; score: number; title: string; process: string; policy: string; timestamp: string }>;
  events: Array<{ type: string; process: string; policy: string; detail: string; timestamp: string }>;
  decisions: Array<{ action: string; state: string; target: string; reason: string; outcome: string; timestamp: string }>;
  iocs: { ips: Array<[string, number]>; files: Array<[string, number]>; binaries: Array<[string, number]> };
  mitre: {
    coveragePct: number; coverageMeasurable: boolean; coveredCount: number; total: number; observedCount: number; gapCount: number;
    observed: Array<{ id: string; name: string; hits: number; policy: string }>;
    gaps: Array<{ id: string; name: string; tactic: string }>;
    tactics: Array<{ name: string; covered: number; observed: number; total: number }>;
  };
}

export const EXPORT_PRESETS: Array<{ key: string; label: string; hint: string; format: ExportFormat; sections: ExportSection[] }> = [
  { key: "incident", label: "Incident report", hint: "IR / board-ready PDF", format: "pdf", sections: ["summary", "alerts", "iocs", "decisions", "mitre"] },
  { key: "handoff", label: "Shift handoff", hint: "What happened this shift", format: "pdf", sections: ["summary", "alerts", "decisions"] },
  { key: "intel", label: "Threat intel", hint: "IOCs to share / ingest", format: "json", sections: ["iocs"] },
  { key: "raw", label: "Raw bundle", hint: "Machine-readable telemetry", format: "json", sections: ["alerts", "events", "decisions"] }
];

export function triggerDownload(blob: Blob, filename: string) {
  const url = URL.createObjectURL(blob);
  const link = document.createElement("a");
  link.href = url;
  link.download = filename;
  link.click();
  URL.revokeObjectURL(url);
}

export function exportJson(model: ExportModel, sections: Set<ExportSection>) {
  const out: Record<string, unknown> = { meta: model.meta };
  for (const s of EXPORT_SECTIONS) if (sections.has(s)) out[s] = model[s];
  triggerDownload(new Blob([JSON.stringify(out, null, 2)], { type: "application/json" }), "soc-export.json");
}

export function csvBlock(title: string, header: string[], rows: Array<Array<string | number>>): string {
  const esc = (v: string | number) => `"${String(v).replaceAll('"', '""')}"`;
  return `# ${title}\n${[header, ...rows].map((r) => r.map(esc).join(",")).join("\n")}\n`;
}
