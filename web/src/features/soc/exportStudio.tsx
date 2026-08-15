// The export pipeline: build a model of the current SOC window, then render it
// as JSON, CSV or PDF.
//
// Split out of SocRoute because none of it participates in rendering the
// console - it turns state into a file an analyst hands to someone else. The
// jsPDF import stays dynamic (scripts/lint.mjs enforces that) so the console's
// first paint never pays for a library used by one button.
function coverageLabel(m: { coveragePct: number; coverageMeasurable: boolean }): string {
  return m.coverageMeasurable ? `${m.coveragePct}%` : "n/a";
}

import { Braces, Check, Copy, Download, FileText } from "lucide-react";
import { useMemo, useState } from "react";
import { decisionOutcome } from "./api";
import { cx } from "./components";
import { MITRE_MATRIX, buildMitreCoverageModel } from "./panels";
import { extractIocs, peerFromEvent } from "./telemetry";
import { EXPORT_PRESETS, csvBlock, exportJson, triggerDownload, type ExportFormat, type ExportModel, type ExportSection } from "./report";
import { loadPdfTools } from "./pdf";
import { type AlertGroup } from "./dashboard";
import type { Severity, SocAlert, SocDecision, SocEvent, SocPolicy, SocSnapshot, SocWhoami } from "./types";
import "./soc.css";

function buildExportModel(
  scopeLabel: string,
  scopeAlerts: SocAlert[],
  events: SocEvent[],
  decisions: SocDecision[],
  policies: SocPolicy[],
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>,
  whoami: SocWhoami,
  version: SocSnapshot["version"]
): ExportModel {
  const counts = { critical: 0, high: 0, medium: 0, low: 0, info: 0 } as Record<Severity, number>;
  for (const a of scopeAlerts) counts[a.severity] += 1;
  const risk = Math.min(100, counts.critical * 8 + counts.high * 3 + counts.medium);

  const iocsRaw = extractIocs(scopeAlerts, events);
  const bins = new Map<string, number>();
  for (const e of events) { if (e.process) bins.set(e.process, (bins.get(e.process) || 0) + 1); }
  const ips = iocsRaw.peers.filter(([v]) => /\d+\.\d+\.\d+\.\d+/.test(v));
  const files = iocsRaw.files;
  const binaries = [...bins.entries()].sort((a, b) => b[1] - a[1]).slice(0, 40);

  const model = buildMitreCoverageModel(mitreRows, scopeAlerts, policies);
  const nameOf = (id: string) => {
    for (const t of MITRE_MATRIX) { const h = t.techniques.find((x) => x.id === id); if (h) return h.name; }
    return "";
  };
  const observed = [...model.observed.entries()].filter(([, n]) => n > 0).sort((a, b) => b[1] - a[1]).map(([id, hits]) => ({
    id, name: nameOf(id), hits, policy: (model.policiesByTech.get(id) ?? []).map((p) => p.name).join(", ") || "—"
  }));
  const gaps = model.gapIds.map((id) => ({ id, name: nameOf(id), tactic: MITRE_MATRIX.find((t) => t.techniques.some((x) => x.id === id))?.name ?? "" }));
  const tactics = MITRE_MATRIX.map((t) => ({
    name: t.name,
    covered: t.techniques.filter((x) => model.stateOf(x.id) !== "gap").length,
    observed: t.techniques.filter((x) => model.stateOf(x.id) === "observed").length,
    total: t.techniques.length
  }));

  const times = scopeAlerts.map((a) => Date.parse(a.timestamp)).filter((n) => !Number.isNaN(n));
  const rangeFrom = times.length ? new Date(Math.min(...times)).toLocaleString() : "—";
  const rangeTo = times.length ? new Date(Math.max(...times)).toLocaleString() : "—";

  return {
    meta: { generated: new Date().toLocaleString(), host: whoami.host || "—", user: whoami.user || "—", sha: version.sha || "n/a", scope: scopeLabel, rangeFrom, rangeTo },
    summary: { risk, total: scopeAlerts.length, counts, events: events.length, decisions: decisions.length, iocs: ips.length + files.length + binaries.length, coveragePct: model.coveragePct, coverageMeasurable: model.mappingAvailable },
    alerts: scopeAlerts.map((a) => ({ severity: a.severity, score: a.score, title: a.title, process: a.process || "", policy: a.policyName || "", timestamp: a.timestamp })),
    events: events.slice(0, 500).map((e) => ({ type: e.eventType, process: e.process || "", policy: e.policyName || "", detail: e.path || e.args || peerFromEvent(e) || "", timestamp: e.timestamp })),
    // `ok: d.ok !== false` exported EVERY decision as successful, because no
    // backend sends a boolean `ok` — they send `outcome`. Rows whose outcome
    // read "skipped: system-critical chain" were exported as ok:true. Carry the
    // engine's own words instead of manufacturing a verdict.
    decisions: decisions.map((d) => ({ action: d.action, state: d.state || "", target: d.target || "", reason: d.reason || "", outcome: decisionOutcome(d), timestamp: d.timestamp })),
    iocs: { ips, files, binaries },
    mitre: { coveragePct: model.coveragePct, coverageMeasurable: model.mappingAvailable, coveredCount: model.coveredCount, total: model.total, observedCount: model.observedCount, gapCount: model.gapCount, observed, gaps, tactics }
  };
}

function exportCsv(model: ExportModel, sections: Set<ExportSection>) {
  const blocks: string[] = [];
  if (sections.has("summary")) {
    const c = model.summary.counts;
    blocks.push(csvBlock("SUMMARY", ["metric", "value"], [
      ["generated", model.meta.generated], ["host", model.meta.host], ["scope", model.meta.scope],
      ["risk", model.summary.risk], ["alerts", model.summary.total],
      ["critical", c.critical], ["high", c.high], ["medium", c.medium], ["low", c.low], ["info", c.info],
      ["mitre_coverage_pct", coverageLabel(model.summary)]
    ]));
  }
  if (sections.has("alerts")) blocks.push(csvBlock("ALERTS", ["severity", "score", "title", "process", "policy", "timestamp"], model.alerts.map((a) => [a.severity, a.score, a.title, a.process, a.policy, a.timestamp])));
  if (sections.has("events")) blocks.push(csvBlock("EVENTS", ["type", "process", "policy", "detail", "timestamp"], model.events.map((e) => [e.type, e.process, e.policy, e.detail, e.timestamp])));
  if (sections.has("decisions")) blocks.push(csvBlock("DECISIONS", ["action", "state", "target", "reason", "outcome", "timestamp"], model.decisions.map((d) => [d.action, d.state, d.target, d.reason, d.outcome, d.timestamp])));
  if (sections.has("iocs")) blocks.push(csvBlock("IOCS", ["type", "value", "count"], [
    ...model.iocs.ips.map(([v, n]) => ["ip", v, n] as Array<string | number>),
    ...model.iocs.files.map(([v, n]) => ["file", v, n] as Array<string | number>),
    ...model.iocs.binaries.map(([v, n]) => ["binary", v, n] as Array<string | number>)
  ]));
  if (sections.has("mitre")) blocks.push(csvBlock("MITRE_OBSERVED", ["technique", "name", "hits", "detected_by"], model.mitre.observed.map((m) => [m.id, m.name, m.hits, m.policy])));
  triggerDownload(new Blob([blocks.join("\n")], { type: "text/csv;charset=utf-8" }), "soc-export.csv");
}

async function exportPdf(model: ExportModel, sections: Set<ExportSection>) {
  const { jsPDF, autoTable } = await loadPdfTools();
  const doc = new jsPDF({ orientation: "portrait", unit: "pt" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;
  const NAVY: [number, number, number] = [20, 31, 48];
  const RED: [number, number, number] = [240, 85, 107];
  const BLUE: [number, number, number] = [47, 129, 247];
  const AMBER: [number, number, number] = [225, 181, 62];
  const GREY: [number, number, number] = [140, 148, 158];

  doc.setFillColor(...NAVY);
  doc.rect(0, 0, W, 76, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("eBPF SOC — Incident Report", M, 34);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  doc.text(`${model.meta.host} · ${model.meta.user}   ·   ${model.meta.scope}   ·   Generated ${model.meta.generated}`, M, 52);
  doc.text(`Window: ${model.meta.rangeFrom} → ${model.meta.rangeTo}   ·   build ${model.meta.sha}`, M, 65);

  let y = 96;
  if (sections.has("summary")) {
    const tiles: Array<[string, string, [number, number, number]]> = [
      [`${model.summary.risk}`, "Risk score / 100", model.summary.risk >= 45 ? RED : BLUE],
      [`${model.summary.total}`, `Alerts · ${model.summary.counts.critical} crit`, RED],
      [coverageLabel(model.summary), "ATT&CK coverage", BLUE],
      [`${model.summary.iocs}`, "IOCs extracted", AMBER]
    ];
    const tileW = (W - M * 2 - 30) / 4;
    tiles.forEach(([big, small, color], i) => {
      const x = M + i * (tileW + 10);
      doc.setDrawColor(225); doc.setFillColor(248, 249, 251);
      doc.roundedRect(x, y, tileW, 50, 5, 5, "FD");
      doc.setTextColor(...color); doc.setFont("helvetica", "bold"); doc.setFontSize(20);
      doc.text(big, x + 10, y + 26);
      doc.setTextColor(90, 98, 110); doc.setFont("helvetica", "normal"); doc.setFontSize(7.5);
      doc.text(small, x + 10, y + 40);
    });
    y += 74;
  }

  const finalY = () => {
    // @ts-expect-error autoTable augments doc at runtime
    return (doc.lastAutoTable?.finalY ?? y) as number;
  };
  const heading = (text: string, color: [number, number, number] = NAVY) => {
    if (finalY() > doc.internal.pageSize.getHeight() - 90) doc.addPage();
    const at = Math.max(y, finalY() + 22);
    doc.setTextColor(...color); doc.setFont("helvetica", "bold"); doc.setFontSize(12);
    doc.text(text, M, at);
    return at + 8;
  };

  if (sections.has("mitre")) {
    let ty = heading("Coverage by tactic");
    doc.setFontSize(8); doc.setFont("helvetica", "normal");
    for (const t of model.mitre.tactics) {
      const frac = t.covered / t.total;
      doc.setTextColor(60, 68, 80); doc.text(t.name, M, ty + 8);
      const barX = M + 150, barW = W - M - barX - 46;
      doc.setFillColor(235, 237, 240); doc.roundedRect(barX, ty, barW, 9, 2, 2, "F");
      if (frac > 0) { doc.setFillColor(...(t.observed > 0 ? RED : BLUE)); doc.roundedRect(barX, ty, Math.max(3, barW * frac), 9, 2, 2, "F"); }
      doc.setTextColor(...GREY); doc.text(`${t.covered}/${t.total}`, barX + barW + 8, ty + 8);
      ty += 16;
    }
    y = ty + 4;
  }

  if (sections.has("alerts")) {
    autoTable(doc, {
      startY: heading("Alerts"),
      head: [["Sev", "Score", "Title", "Process", "Policy", "Time"]],
      body: (model.alerts.length ? model.alerts.slice(0, 200) : [{ severity: "—", score: 0, title: "No alerts in scope", process: "", policy: "", timestamp: "" }]).map((a) => [a.severity, String(a.score), a.title, a.process, a.policy, a.timestamp]),
      styles: { fontSize: 7.5, cellPadding: 4, textColor: [40, 48, 60] }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] },
      columnStyles: { 1: { halign: "right", cellWidth: 34 } }, margin: { left: M, right: M }
    });
  }
  if (sections.has("iocs")) {
    const rows = [
      ...model.iocs.ips.map(([v, n]) => ["ip", v, String(n)]),
      ...model.iocs.files.slice(0, 20).map(([v, n]) => ["file", v, String(n)]),
      ...model.iocs.binaries.slice(0, 20).map(([v, n]) => ["binary", v, String(n)])
    ];
    autoTable(doc, {
      startY: heading("Indicators of compromise", AMBER),
      head: [["Type", "Indicator", "Hits"]],
      body: rows.length ? rows : [["—", "none observed", "0"]],
      styles: { fontSize: 8, cellPadding: 4 }, headStyles: { fillColor: AMBER, textColor: NAVY },
      columnStyles: { 2: { halign: "right", cellWidth: 40 } }, margin: { left: M, right: M }
    });
  }
  if (sections.has("decisions")) {
    autoTable(doc, {
      startY: heading("Enforcement decisions"),
      head: [["Action", "State", "Target", "Reason", "Time"]],
      body: (model.decisions.length ? model.decisions.slice(0, 120) : [{ action: "—", state: "", target: "no decisions logged", reason: "", ok: true, timestamp: "" }]).map((d) => [d.action, d.state, d.target, d.reason, d.timestamp]),
      styles: { fontSize: 7.5, cellPadding: 4 }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] }, margin: { left: M, right: M }
    });
  }
  if (sections.has("events")) {
    autoTable(doc, {
      startY: heading("Events"),
      head: [["Type", "Process", "Policy", "Detail", "Time"]],
      body: model.events.slice(0, 150).map((e) => [e.type, e.process, e.policy, e.detail, e.timestamp]),
      styles: { fontSize: 7, cellPadding: 3 }, headStyles: { fillColor: NAVY, textColor: [255, 255, 255] }, margin: { left: M, right: M }
    });
  }

  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setTextColor(...GREY); doc.setFontSize(8);
    doc.text("eBPF SOC · incident report", M, doc.internal.pageSize.getHeight() - 20);
    doc.text(`Page ${p} of ${pages}`, W - M - 60, doc.internal.pageSize.getHeight() - 20);
  }
  doc.save("soc-incident-report.pdf");
}

/**
 * Export studio — assemble a report instead of blindly downloading a flat alert
 * dump. The operator picks the SECTIONS (summary, alerts, events, decisions,
 * IOCs, ATT&CK coverage), the FORMAT (a board-ready PDF, a per-section CSV, or a
 * machine-readable JSON bundle), and a SCOPE (what's on screen vs the whole
 * window), sees a live preview of exactly what the file will contain, and can
 * copy the IOCs or a Markdown summary straight into a ticket. Presets snap it to
 * an incident report, a shift handoff, a threat-intel bundle, or raw telemetry.
 */
export function ExportStudioBody({
  filteredAlerts,
  rangeAlerts,
  events,
  decisions,
  policies,
  mitreRows,
  whoami,
  version
}: {
  filteredAlerts: AlertGroup[];
  rangeAlerts: SocAlert[];
  events: SocEvent[];
  decisions: SocDecision[];
  policies: SocPolicy[];
  mitreRows: Array<{ label: string; value: number; meta?: string; id?: string }>;
  whoami: SocWhoami;
  version: SocSnapshot["version"];
}) {
  const [format, setFormat] = useState<ExportFormat>("pdf");
  const [scope, setScope] = useState<"filtered" | "range">("filtered");
  const [sections, setSections] = useState<Set<ExportSection>>(() => new Set<ExportSection>(["summary", "alerts", "iocs", "mitre"]));
  const [copied, setCopied] = useState<string | null>(null);

  const scopeAlerts = scope === "filtered" ? filteredAlerts : rangeAlerts;
  const model = useMemo(
    () => buildExportModel(scope === "filtered" ? "filtered (on screen)" : "full range", scopeAlerts, events, decisions, policies, mitreRows, whoami, version),
    [scope, scopeAlerts, events, decisions, policies, mitreRows, whoami, version]
  );

  const sectionMeta: Array<{ key: ExportSection; label: string; count: number; note: string }> = [
    { key: "summary", label: "Executive summary", count: 1, note: `risk ${model.summary.risk} · ${coverageLabel(model.summary)} coverage` },
    { key: "alerts", label: "Alerts", count: model.summary.total, note: `${model.summary.counts.critical} critical` },
    { key: "events", label: "Events", count: model.events.length, note: "raw telemetry" },
    { key: "decisions", label: "Enforcement decisions", count: model.decisions.length, note: "audit trail" },
    { key: "iocs", label: "Indicators (IOCs)", count: model.summary.iocs, note: `${model.iocs.ips.length} ip · ${model.iocs.files.length} file · ${model.iocs.binaries.length} bin` },
    { key: "mitre", label: "ATT&CK coverage", count: model.mitre.observedCount, note: `${model.mitre.gapCount} blind spots` }
  ];

  const toggle = (s: ExportSection) => setSections((prev) => { const next = new Set(prev); if (next.has(s)) next.delete(s); else next.add(s); return next; });
  const activePreset = EXPORT_PRESETS.find((p) => p.format === format && p.sections.length === sections.size && p.sections.every((s) => sections.has(s)));

  const runExport = () => {
    if (!sections.size) return;
    if (format === "json") exportJson(model, sections);
    else if (format === "csv") exportCsv(model, sections);
    else void exportPdf(model, sections);
  };

  const copy = async (kind: "iocs" | "summary") => {
    let text = "";
    if (kind === "iocs") {
      text = [
        ...model.iocs.ips.map(([v]) => v),
        ...model.iocs.files.map(([v]) => v),
        ...model.iocs.binaries.map(([v]) => v)
      ].join("\n");
    } else {
      const c = model.summary.counts;
      text = [
        `## eBPF SOC summary — ${model.meta.generated}`,
        `- Host: ${model.meta.host} · Scope: ${model.meta.scope}`,
        `- Risk: **${model.summary.risk}/100**`,
        `- Alerts: ${model.summary.total} (${c.critical} critical, ${c.high} high, ${c.medium} medium)`,
        `- ATT&CK coverage: ${coverageLabel(model.summary)} · ${model.mitre.gapCount} blind spots`,
        `- IOCs: ${model.iocs.ips.length} IP, ${model.iocs.files.length} file, ${model.iocs.binaries.length} binary`,
        model.mitre.observed.length ? `- Top technique: ${model.mitre.observed[0].id} ${model.mitre.observed[0].name} (${model.mitre.observed[0].hits} hits)` : ""
      ].filter(Boolean).join("\n");
    }
    try { await navigator.clipboard.writeText(text); setCopied(kind); window.setTimeout(() => setCopied(null), 1500); } catch { /* clipboard unavailable */ }
  };

  return (
    <div className="soc-export">
      <div className="soc-export-presets">
        <span className="soc-stat-label">Template</span>
        {EXPORT_PRESETS.map((p) => (
          <button
            key={p.key}
            type="button"
            className={cx("soc-export-preset", activePreset?.key === p.key && "is-active")}
            onClick={() => { setFormat(p.format); setSections(new Set(p.sections)); }}
            title={p.hint}
          >
            {p.label}
          </button>
        ))}
      </div>

      <div className="soc-export-cols">
        <div className="soc-export-build">
          <div className="soc-export-row">
            <span className="soc-stat-label">Format</span>
            <div className="soc-export-format">
              {([["pdf", "PDF report", FileText], ["csv", "CSV", Download], ["json", "JSON", Braces]] as const).map(([f, label, Icon]) => (
                <button key={f} type="button" className={cx("soc-export-fmt", format === f && "is-active")} onClick={() => setFormat(f)}>
                  <Icon size={13} aria-hidden="true" /> {label}
                </button>
              ))}
            </div>
          </div>

          <div className="soc-export-row">
            <span className="soc-stat-label">Scope</span>
            <div className="soc-export-format">
              <button type="button" className={cx("soc-export-fmt", scope === "filtered" && "is-active")} onClick={() => setScope("filtered")}>On screen ({filteredAlerts.length})</button>
              <button type="button" className={cx("soc-export-fmt", scope === "range" && "is-active")} onClick={() => setScope("range")}>Full range ({rangeAlerts.length})</button>
            </div>
          </div>

          <div className="soc-export-sections">
            <span className="soc-stat-label">Include</span>
            {sectionMeta.map((s) => (
              <button key={s.key} type="button" className={cx("soc-export-section", sections.has(s.key) && "is-on")} onClick={() => toggle(s.key)}>
                <span className="soc-export-check">{sections.has(s.key) ? <Check size={12} /> : null}</span>
                <span className="soc-export-section-label">{s.label}</span>
                <span className="soc-export-section-count">{s.count}<em>{s.note}</em></span>
              </button>
            ))}
          </div>
        </div>

        <div className="soc-export-preview">
          <span className="soc-stat-label">Preview</span>
          <div className="soc-export-preview-file">
            <FileText size={26} aria-hidden="true" />
            <div>
              <strong>soc-{format === "pdf" ? "incident-report.pdf" : format === "csv" ? "export.csv" : "export.json"}</strong>
              <em>{sections.size} section{sections.size === 1 ? "" : "s"} · {model.meta.scope}</em>
            </div>
          </div>
          <ul className="soc-export-preview-list">
            {sectionMeta.filter((s) => sections.has(s.key)).map((s) => (
              <li key={s.key}><b>{s.count}</b> {s.label.toLowerCase()}</li>
            ))}
            {!sections.size ? <li className="soc-export-preview-empty">Select at least one section</li> : null}
          </ul>
          <div className="soc-export-preview-meta">
            {model.meta.host} · {model.meta.user}<br />
            {model.meta.rangeFrom} → {model.meta.rangeTo}
          </div>
        </div>
      </div>

      <div className="soc-export-actions">
        <button type="button" className="soc-export-run" disabled={!sections.size} onClick={runExport}>
          <Download size={14} aria-hidden="true" /> Export {format.toUpperCase()}
        </button>
        <button type="button" className="soc-export-copy" onClick={() => void copy("iocs")}>
          {copied === "iocs" ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy IOCs</>}
        </button>
        <button type="button" className="soc-export-copy" onClick={() => void copy("summary")}>
          {copied === "summary" ? <><Check size={13} /> Copied</> : <><Copy size={13} /> Copy summary</>}
        </button>
      </div>
    </div>
  );
}

/* ──────────────────────────────────────────────────── D3 correlation graph */
