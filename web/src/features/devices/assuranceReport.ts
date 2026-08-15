/**
 * The two artefacts the assurance lens can hand to someone outside the SOC: a
 * printable board report and a machine-readable evidence bundle.
 *
 * Both are point-in-time snapshots that leave the console and may end up in an
 * audit file or an insurance claim, which is why they are built here rather than
 * inline in the view — the honesty rules below are easier to hold to when the
 * whole artefact is one function you can read top to bottom.
 */
import type { CommandMetrics } from "../common/ContainmentCommand";
import { LADDER } from "../common/enforcement";
import type { DeviceDataPlaneState, DeviceEntry } from "./types";

export interface DeviceEvidenceInput {
  metrics: CommandMetrics;
  countsByRung: Record<string, number>;
  state: DeviceDataPlaneState | null;
  planeHealthy: boolean;
  protectedCount: number;
  devices: DeviceEntry[];
  when: Date;
}

export function buildDeviceEvidenceBundle({
  metrics,
  countsByRung,
  state,
  planeHealthy,
  protectedCount,
  devices,
  when
}: DeviceEvidenceInput) {
  return {
    generated_at: when.toISOString(),
    subject: "devices",
    posture: metrics.posture,
    mode: metrics.mode,
    kill_switch: metrics.killSwitched ? "engaged" : "standby",
    // Both: the verdict AND what it was derived from. An evidence bundle
    // that flattens "noop" to "offline" is honest but lossy — a reader
    // cannot tell an unattached plane from a broken one.
    data_plane: planeHealthy ? "active" : "offline",
    data_plane_reported: state?.data_plane ?? "unknown",
    links_attached: state?.links_attached ?? 0,
    frames_seen: state?.frames_seen ?? 0,
    contained: metrics.contained,
    tracked: metrics.tracked,
    protected_assets: protectedCount,
    containment_ladder: LADDER.reduce<Record<string, number>>((acc, r) => ({ ...acc, [r]: countsByRung[r] || 0 }), {}),
    devices: devices.map((d) => ({
      mac: d.mac,
      ip: d.last_ip || null,
      hostname: d.hostname || null,
      vendor: d.vendor || null,
      state: d.state,
      protected: Boolean(d.protected)
    }))
  };
}

/** Hand the browser a JSON file, then release the object URL. */
export function downloadJson(filename: string, value: unknown): void {
  const blob = new Blob([JSON.stringify(value, null, 2)], { type: "application/json" });
  const url = URL.createObjectURL(blob);
  const anchor = document.createElement("a");
  anchor.href = url;
  anchor.download = filename;
  document.body.appendChild(anchor);
  anchor.click();
  anchor.remove();
  URL.revokeObjectURL(url);
}

export function buildDeviceAssuranceHtml(args: {
  metrics: CommandMetrics;
  counts: Record<string, number>;
  links: number;
  frames: number;
  protectedCount: number;
  devices: DeviceEntry[];
  when: Date;
}): string {
  const { metrics: m, counts, links, frames, protectedCount, devices, when } = args;
  const esc = (s: string) =>
    String(s).replace(/[&<>"]/g, (c) => ({ "&": "&amp;", "<": "&lt;", ">": "&gt;", '"': "&quot;" }[c] as string));
  const needing = m.activeThreats + m.contained;
  const coverage = needing === 0 ? 100 : Math.round((m.contained / needing) * 100);
  const tone = m.posture >= 80 ? "#2f9e5e" : m.posture >= 55 ? "#c9871f" : "#d23a4f";
  const rung = (r: string) => counts[r] || 0;
  const deviceRows =
    devices.length === 0
      ? `<tr><td colspan="4" style="color:#888">no devices observed</td></tr>`
      : devices
          .map(
            (d) =>
              `<tr><td class="mono">${esc(d.mac)}</td><td>${esc(d.last_ip || "—")}</td><td>${esc(d.hostname || d.vendor || "—")}</td><td style="text-align:right">${esc(String(d.state))}${d.protected ? " · protected" : ""}</td></tr>`
          )
          .join("");
  return `<!doctype html><html><head><meta charset="utf-8">
<title>Network Containment Assurance Report</title>
<style>
  * { box-sizing: border-box; }
  body { font: 13px/1.5 -apple-system, Segoe UI, Roboto, sans-serif; color: #1a2230; margin: 0; padding: 40px; background: #fff; }
  .head { display: flex; justify-content: space-between; align-items: flex-start; border-bottom: 3px solid #1a2230; padding-bottom: 14px; }
  .head h1 { margin: 0; font-size: 22px; }
  .head .sub { color: #667085; font-size: 12px; margin-top: 4px; }
  .posture { text-align: center; }
  .posture .num { font-size: 44px; font-weight: 800; color: ${tone}; line-height: 1; }
  .posture .lbl { font-size: 10px; letter-spacing: 0.12em; text-transform: uppercase; color: #667085; }
  .tiles { display: grid; grid-template-columns: repeat(4, 1fr); gap: 12px; margin: 22px 0; }
  .tile { border: 1px solid #e3e7ee; border-radius: 8px; padding: 14px; }
  .tile .v { font-size: 24px; font-weight: 700; }
  .tile .l { font-size: 10px; letter-spacing: 0.09em; text-transform: uppercase; color: #667085; margin-top: 4px; }
  h2 { font-size: 13px; letter-spacing: 0.08em; text-transform: uppercase; color: #667085; border-bottom: 1px solid #e3e7ee; padding-bottom: 6px; margin: 26px 0 12px; }
  table { width: 100%; border-collapse: collapse; }
  td, th { padding: 7px 8px; border-bottom: 1px solid #eef1f5; text-align: left; }
  .ladder { display: grid; grid-template-columns: repeat(5, 1fr); gap: 8px; }
  .ladder .cell { border: 1px solid #e3e7ee; border-radius: 8px; padding: 12px; text-align: center; }
  .ladder .cell .c { font-size: 22px; font-weight: 700; }
  .ladder .cell .n { font-size: 10px; text-transform: uppercase; letter-spacing: 0.08em; color: #667085; }
  .mono { font-family: ui-monospace, Menlo, monospace; font-size: 11px; }
  .foot { margin-top: 30px; padding-top: 12px; border-top: 1px solid #e3e7ee; color: #98a2b3; font-size: 11px; }
  @media print { body { padding: 0; } }
</style></head><body>
<div class="head">
  <div>
    <h1>Network Containment Assurance Report</h1>
    <div class="sub">Device enforcement plane · generated ${esc(when.toLocaleString())}</div>
  </div>
  <div class="posture"><div class="num">${m.posture}</div><div class="lbl">Posture / 100</div></div>
</div>
<div class="tiles">
  <div class="tile"><div class="v">${m.tracked.toLocaleString()}</div><div class="l">Devices tracked</div></div>
  <div class="tile"><div class="v">${m.contained}</div><div class="l">Contained</div></div>
  <div class="tile"><div class="v">${coverage}%</div><div class="l">Coverage</div></div>
  <div class="tile"><div class="v">${protectedCount}</div><div class="l">Protected assets</div></div>
</div>
<h2>Containment ladder</h2>
<div class="ladder">
  <div class="cell"><div class="c">${rung("pristine")}</div><div class="n">Pristine</div></div>
  <div class="cell"><div class="c">${rung("throttled")}</div><div class="n">Throttled</div></div>
  <div class="cell"><div class="c">${rung("tarpit")}</div><div class="n">Tarpit</div></div>
  <div class="cell"><div class="c">${rung("quarantined")}</div><div class="n">Quarantined</div></div>
  <div class="cell"><div class="c">${rung("severed")}</div><div class="n">Severed</div></div>
</div>
<h2>Data plane</h2>
<table>
  <tr><td>Mode</td><td style="text-align:right">${m.mode === "enforcing" ? "Enforcing" : "Detect-only"}</td></tr>
  <tr><td>Kill-switch</td><td style="text-align:right">${m.killSwitched ? "Engaged" : "Standby"}</td></tr>
  <tr><td>Links attached</td><td style="text-align:right">${links}</td></tr>
  <tr><td>Frames forwarded</td><td style="text-align:right">${frames.toLocaleString()}</td></tr>
</table>
<h2>Device inventory</h2>
<table><tr><th>MAC</th><th>IP</th><th>Host / vendor</th><th style="text-align:right">State</th></tr>${deviceRows}</table>
<div class="foot">This report is a point-in-time summary of live network-enforcement state. Device identity is the MAC address, stable across DHCP and IP changes. Every choke is a reversible, audited drop/throttle rule.</div>
<script>window.onload=function(){setTimeout(function(){window.print();},250);};</script>
</body></html>`;
}
