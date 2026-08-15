// PDF generation, kept off the initial bundle.
//
// jspdf + jspdf-autotable are ~400KB together and are needed only when an
// operator actually asks for a document, so they are loaded on demand — the
// architectural lint (scripts/lint.mjs) enforces that these stay dynamic
// imports.
import { MITRE_MATRIX, buildMitreCoverageModel } from "./panels";
import type { SocAlert, SocSnapshot } from "./types";

export async function loadPdfTools() {
  const [{ default: jsPDF }, { default: autoTable }] = await Promise.all([
    import("jspdf"),
    import("jspdf-autotable")
  ]);
  return { jsPDF, autoTable };
}

// A board-ready MITRE ATT&CK posture report — not a flat dump of the two
// techniques that happened to fire. It mirrors the in-app Navigator: an
// executive summary (coverage vs the whole matrix), per-tactic coverage bars,
// the full technique grid coloured by state, the observed techniques with the
// policy that detected them, and — the actionable part — a blind-spot list.
export async function downloadMitrePdf(
  rows: Array<{ label: string; value: number; meta?: string; id?: string }>,
  alerts: SocAlert[],
  policies: SocSnapshot["policies"],
  whoami: SocSnapshot["whoami"]
) {
  const { jsPDF, autoTable } = await loadPdfTools();
  const model = buildMitreCoverageModel(rows, alerts, policies);
  const doc = new jsPDF({ orientation: "portrait", unit: "pt" });
  const W = doc.internal.pageSize.getWidth();
  const M = 40;
  const NAVY: [number, number, number] = [20, 31, 48];
  const RED: [number, number, number] = [240, 85, 107];
  const BLUE: [number, number, number] = [47, 129, 247];
  const AMBER: [number, number, number] = [225, 181, 62];
  const GREY: [number, number, number] = [140, 148, 158];

  // ── Branded header band ──────────────────────────────────────────────────
  doc.setFillColor(...NAVY);
  doc.rect(0, 0, W, 74, "F");
  doc.setTextColor(255, 255, 255);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(18);
  doc.text("eBPF SOC — MITRE ATT&CK Coverage", M, 34);
  doc.setFont("helvetica", "normal");
  doc.setFontSize(9);
  const scope = whoami?.host ? `${whoami.host}${whoami.user ? ` · ${whoami.user}` : ""}` : (whoami?.user ?? "");
  doc.text(
    `${scope ? scope + "   ·   " : ""}Generated ${new Date().toLocaleString()}`,
    M,
    52
  );
  doc.text("Detection posture across the ATT&CK matrix — observed, covered, and blind spots.", M, 65);

  // ── Executive summary tiles ──────────────────────────────────────────────
  const tiles: Array<[string, string, [number, number, number]]> = [
    [
      model.mappingAvailable ? `${model.coveragePct}%` : "n/a",
      model.mappingAvailable
        ? `Coverage · ${model.coveredCount}/${model.total} techniques`
        : "Coverage · no ATT&CK mapping published",
      BLUE
    ],
    [`${model.observedCount}`, `Observed · ${model.hitTotal.toLocaleString()} hits`, RED],
    [`${model.gapCount}`, "Blind spots · no policy", AMBER]
  ];
  const tileW = (W - M * 2 - 20) / 3;
  tiles.forEach(([big, small, color], i) => {
    const x = M + i * (tileW + 10);
    doc.setDrawColor(225);
    doc.setFillColor(248, 249, 251);
    doc.roundedRect(x, 92, tileW, 54, 5, 5, "FD");
    doc.setTextColor(...color);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(22);
    doc.text(big, x + 12, 122);
    doc.setTextColor(90, 98, 110);
    doc.setFont("helvetica", "normal");
    doc.setFontSize(8.5);
    doc.text(small, x + 12, 138);
  });

  // ── Per-tactic coverage bars ─────────────────────────────────────────────
  let y = 176;
  doc.setTextColor(...NAVY);
  doc.setFont("helvetica", "bold");
  doc.setFontSize(12);
  doc.text("Coverage by tactic", M, y);
  y += 14;
  doc.setFontSize(8);
  doc.setFont("helvetica", "normal");
  for (const tactic of MITRE_MATRIX) {
    const covered = tactic.techniques.filter((t) => model.stateOf(t.id) !== "gap").length;
    const observed = tactic.techniques.filter((t) => model.stateOf(t.id) === "observed").length;
    const frac = covered / tactic.techniques.length;
    doc.setTextColor(60, 68, 80);
    doc.text(tactic.name, M, y + 8);
    const barX = M + 150;
    const barW = W - M - barX - 46;
    doc.setFillColor(235, 237, 240);
    doc.roundedRect(barX, y, barW, 9, 2, 2, "F");
    if (frac > 0) {
      doc.setFillColor(...(observed > 0 ? RED : BLUE));
      doc.roundedRect(barX, y, Math.max(3, barW * frac), 9, 2, 2, "F");
    }
    doc.setTextColor(...GREY);
    doc.text(`${covered}/${tactic.techniques.length}`, barX + barW + 8, y + 8);
    y += 16;
  }

  // ── Observed techniques (what fired + the detecting policy) ───────────────
  const observedRows = [...model.observed.entries()]
    .filter(([id]) => (model.observed.get(id) || 0) > 0)
    .sort((a, b) => b[1] - a[1])
    .map(([id, count]) => {
      const name = MITRE_MATRIX.flatMap((t) => t.techniques).find((t) => t.id === id)?.name ?? "";
      const pols = (model.policiesByTech.get(id) ?? []).map((p) => p.name).join(", ") || "—";
      return [`${id}  ${name}`, String(count), pols];
    });
  autoTable(doc, {
    startY: y + 8,
    head: [["Observed technique", "Hits", "Detected by"]],
    body: observedRows.length ? observedRows : [["No techniques observed in this range", "0", "—"]],
    styles: { fontSize: 8.5, cellPadding: 5, textColor: [40, 48, 60] },
    headStyles: { fillColor: NAVY, textColor: [255, 255, 255] },
    columnStyles: { 1: { halign: "right", cellWidth: 44 } },
    margin: { left: M, right: M }
  });

  // ── Blind spots (actionable gap analysis) ────────────────────────────────
  const gapRows = model.gapIds.map((id) => {
    const tactic = MITRE_MATRIX.find((t) => t.techniques.some((x) => x.id === id));
    const name = tactic?.techniques.find((x) => x.id === id)?.name ?? "";
    return [`${id}  ${name}`, tactic?.name ?? ""];
  });
  if (gapRows.length) {
    // @ts-expect-error autoTable augments doc with lastAutoTable at runtime
    const afterY = (doc.lastAutoTable?.finalY ?? y) + 22;
    doc.setTextColor(...AMBER);
    doc.setFont("helvetica", "bold");
    doc.setFontSize(12);
    doc.text(`Blind spots — ${gapRows.length} techniques with no detection policy`, M, afterY);
    autoTable(doc, {
      startY: afterY + 8,
      head: [["Uncovered technique", "Tactic"]],
      body: gapRows,
      styles: { fontSize: 8.5, cellPadding: 5, textColor: [90, 74, 30] },
      headStyles: { fillColor: AMBER, textColor: NAVY },
      margin: { left: M, right: M }
    });
  }

  // ── Footer page numbers ──────────────────────────────────────────────────
  const pages = doc.getNumberOfPages();
  for (let p = 1; p <= pages; p++) {
    doc.setPage(p);
    doc.setTextColor(...GREY);
    doc.setFontSize(8);
    doc.text(`eBPF SOC · ATT&CK coverage report`, M, doc.internal.pageSize.getHeight() - 20);
    doc.text(`Page ${p} of ${pages}`, W - M - 60, doc.internal.pageSize.getHeight() - 20);
  }

  doc.save("mitre-coverage.pdf");
}
