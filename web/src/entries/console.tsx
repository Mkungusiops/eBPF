import { StrictMode, useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { createRoot } from "react-dom/client";

import { ConsoleShell } from "../app/ConsoleShell";
import { useTenantStore } from "../stores/tenant";
import {
  fetchAlerts,
  fetchChoke,
  fetchDevices,
  fetchFleet,
  fetchTelemetry,
  jailProcess,
  thawProcess,
  type AlertRow,
  type ChokeRow,
  type ChokeTier
} from "../lib/console";
import { ApiError } from "../lib/api";
import { registerServiceWorker } from "../lib/pwa";

function bootstrapTheme() {
  try {
    const raw = localStorage.getItem("soc.theme");
    const parsed = raw ? (JSON.parse(raw) as unknown) : null;
    const theme = parsed === "light" || raw === "light" ? "light" : "dark";
    document.documentElement.classList.toggle("theme-light", theme === "light");
    document.body.classList.toggle("theme-light", theme === "light");
  } catch {
    document.documentElement.classList.remove("theme-light");
  }
}

type LoadState = "loading" | "ready" | "empty" | "error";

function relativeTime(unixNanos: number): string {
  const secs = Math.max(0, Math.round((Date.now() - unixNanos / 1e6) / 1000));
  if (secs < 60) return `${secs}s ago`;
  if (secs < 3600) return `${Math.round(secs / 60)}m ago`;
  return `${Math.round(secs / 3600)}h ago`;
}

// Stable module-level loaders — passing an inline arrow would re-fire the effect
// every render and thrash the 5s refresh timer.
const loadSoc = (t: string) => fetchTelemetry(t, 50);
const loadAlerts = (t: string) => fetchAlerts(t, 200);
const loadChoke = (t: string) => fetchChoke(t);
const loadDevices = (t: string) => fetchDevices(t);
const loadFleet = (t: string) => fetchFleet(t);

// Severity is domain-standard: red → orange → amber → blue → grey.
const SEVERITIES = ["critical", "high", "medium", "low", "info"] as const;
const SEV_COLOR: Record<string, string> = {
  critical: "#f43f5e",
  high: "#fb923c",
  medium: "#fbbf24",
  low: "#38bdf8",
  info: "#94a3b8"
};
function sevColor(s: string): string {
  return SEV_COLOR[s.toLowerCase()] ?? SEV_COLOR.info;
}
function SeverityChip({ sev }: { sev: string }) {
  const c = sevColor(sev);
  return (
    <span style={{ color: c, border: `1px solid ${c}`, borderRadius: 999, padding: "1px 8px", fontSize: "0.7rem", fontWeight: 700, textTransform: "uppercase", whiteSpace: "nowrap" }}>
      {sev || "info"}
    </span>
  );
}

// useTenantResource loads a tenant-scoped resource and refreshes it every 5s
// while the tab is mounted. Authorization is server-side; a 404 surfaces as an
// error state.
function useTenantResource<R extends { count: number }>(
  load: (tenant: string) => Promise<R>,
  active: string | undefined
): { data: R | null; state: LoadState } {
  const [data, setData] = useState<R | null>(null);
  const [state, setState] = useState<LoadState>("loading");
  useEffect(() => {
    if (!active) return;
    let cancelled = false;
    const run = () =>
      load(active)
        .then((res) => {
          if (cancelled) return;
          setData(res);
          setState(res.count > 0 ? "ready" : "empty");
        })
        .catch(() => {
          if (!cancelled) setState("error");
        });
    setState("loading");
    void run();
    const id = window.setInterval(() => void run(), 5000);
    return () => {
      cancelled = true;
      window.clearInterval(id);
    };
  }, [load, active]);
  return { data, state };
}

const cell: CSSProperties = { padding: "6px 10px", whiteSpace: "nowrap" };
const mono: CSSProperties = { ...cell, fontFamily: "ui-monospace, monospace", whiteSpace: "normal" };

function DataTable({ head, rows }: { head: string[]; rows: ReactNode[][] }) {
  return (
    <div style={{ overflowX: "auto" }}>
      <table style={{ width: "100%", borderCollapse: "collapse", fontSize: "0.85rem" }}>
        <thead>
          <tr style={{ textAlign: "left", opacity: 0.7 }}>
            {head.map((h) => (
              <th key={h} style={cell}>{h}</th>
            ))}
          </tr>
        </thead>
        <tbody>
          {rows.map((cells, i) => (
            <tr key={i} style={{ borderTop: "1px solid rgba(148,163,184,0.18)" }}>
              {cells.map((c, j) => (
                <td key={j} style={j === 0 ? { ...cell, opacity: 0.85 } : cell}>{c}</td>
              ))}
            </tr>
          ))}
        </tbody>
      </table>
    </div>
  );
}

function View({
  title,
  blurb,
  state,
  count,
  countLabel,
  emptyText,
  children
}: {
  title: string;
  blurb: string;
  state: LoadState;
  count: number;
  countLabel: string;
  emptyText: string;
  children: ReactNode;
}) {
  return (
    <section style={{ padding: "1rem 1.25rem", maxWidth: "68rem" }}>
      <header style={{ display: "flex", alignItems: "baseline", gap: "0.75rem", flexWrap: "wrap" }}>
        <h1 style={{ margin: 0, fontSize: "1.4rem" }}>{title}</h1>
        <span style={{ opacity: 0.7, fontSize: "0.85rem" }}>
          {state === "ready" ? `${count} ${countLabel} · live` : ""}
        </span>
      </header>
      <p style={{ opacity: 0.7, margin: "0.25rem 0 0.9rem" }}>{blurb}</p>
      {state === "loading" && <p>Loading…</p>}
      {state === "error" && <p style={{ color: "#f43f5e" }}>Could not load this view for the current tenant.</p>}
      {state === "empty" && <p style={{ opacity: 0.7 }}>{emptyText}</p>}
      {state === "ready" && children}
    </section>
  );
}

function SocView() {
  const active = useTenantStore((s) => s.activeTenant);
  const { data, state } = useTenantResource(loadSoc, active);
  const rows = data?.records ?? [];
  return (
    <View
      title={`SOC · ${active ?? "—"}`}
      blurb="Tenant-scoped runtime telemetry from the control plane. Authorization is enforced server-side."
      state={state}
      count={data?.count ?? 0}
      countLabel="recent events"
      emptyText={`No telemetry reported yet for ${active ?? "this tenant"}.`}
    >
      <DataTable
        head={["When", "Kind", "Binary", "Agent"]}
        rows={rows.map((r) => [relativeTime(r.at), r.kind, <span style={mono}>{r.binary || "—"}</span>, <span style={{ ...mono, opacity: 0.7 }}>{r.agent.slice(0, 20)}</span>])}
      />
    </View>
  );
}

// SeverityTimeline stacks alert counts by severity across ~40 time buckets —
// the console's "severity over time" strip, derived from the alert list.
function SeverityTimeline({ alerts }: { alerts: AlertRow[] }) {
  const rects: ReactNode[] = [];
  if (alerts.length > 0) {
    const N = 40;
    const H = 60;
    const times = alerts.map((a) => a.at / 1e6);
    const min = Math.min(...times);
    const span = Math.max(1, Math.max(...times) - min);
    const buckets = Array.from({ length: N }, () => ({}) as Record<string, number>);
    for (const a of alerts) {
      const i = Math.min(N - 1, Math.max(0, Math.floor(((a.at / 1e6 - min) / span) * N)));
      const sev = a.severity.toLowerCase();
      buckets[i][sev] = (buckets[i][sev] ?? 0) + 1;
    }
    const maxCount = Math.max(1, ...buckets.map((b) => Object.values(b).reduce((s, n) => s + n, 0)));
    const bw = 100 / N;
    buckets.forEach((b, i) => { 
      let y = H;
      for (const sev of SEVERITIES) {
        const c = b[sev] ?? 0; 
        if (!c) continue;
        const h = (c / maxCount) * H;
        y -= h;
        rects.push(<rect key={`${i}-${sev}`} x={i * bw + 0.12} y={y} width={bw * 0.78} height={h} fill={sevColor(sev)} />);
      }
    });
  }
  return (
    <svg viewBox="0 0 100 60" preserveAspectRatio="none" role="img" aria-label="Alert severity over time"
      style={{ width: "100%", height: 84, display: "block", borderRadius: 6, background: "rgba(148,163,184,0.06)" }}>
      {rects}
    </svg>
  );
}

// AlertItem is one triage row; clicking it drills into the description + exec id.
const alertGrid: CSSProperties = { display: "grid", gridTemplateColumns: "88px 52px 1fr 150px 78px", gap: 10, alignItems: "center" };
function AlertItem({ a }: { a: AlertRow }) {
  const [open, setOpen] = useState(false);
  return (
    <div style={{ borderTop: "1px solid rgba(148,163,184,0.18)" }}>
      <button type="button" onClick={() => setOpen((o) => !o)}
        style={{ appearance: "none", background: "transparent", border: 0, color: "inherit", font: "inherit", cursor: "pointer", width: "100%", textAlign: "left", padding: "8px 6px", ...alertGrid }}>
        <SeverityChip sev={a.severity} />
        <span style={{ fontVariantNumeric: "tabular-nums" }}>{a.score}</span>
        <span style={{ overflow: "hidden", textOverflow: "ellipsis", whiteSpace: "nowrap" }}>{a.title || "—"}</span>
        <span style={{ ...mono, opacity: 0.7, fontSize: "0.78rem" }}>{a.agent.slice(0, 18)}</span>
        <span style={{ opacity: 0.7, fontSize: "0.8rem" }}>{relativeTime(a.at)}</span>
      </button>
      {open && (
        <div style={{ padding: "0 6px 12px", fontSize: "0.82rem" }}>
          <div style={{ opacity: 0.9, marginBottom: 5 }}>{a.description || a.title}</div>
          <div style={{ ...mono, fontSize: "0.72rem", opacity: 0.6 }}>exec_id: {a.exec_id || "—"}</div>
        </div>
      )}
    </div>
  );
}

function AlertsView() {
  const active = useTenantStore((s) => s.activeTenant);
  const { data, state } = useTenantResource(loadAlerts, active);
  const alerts = data?.alerts ?? [];
  const counts = SEVERITIES.map((sev) => ({ sev, n: alerts.filter((a) => a.severity.toLowerCase() === sev).length })).filter((c) => c.n > 0);
  return (
    <View
      title={`Alerts · ${active ?? "—"}`}
      blurb="Tenant-scoped alert triage from the control plane. Click a row to drill into the chain and exec id."
      state={state}
      count={data?.count ?? 0}
      countLabel="alerts"
      emptyText={`No alerts reported yet for ${active ?? "this tenant"}.`}
    >
      <div style={{ display: "flex", gap: 14, flexWrap: "wrap", marginBottom: 10, alignItems: "center" }}>
        {counts.map((c) => (
          <span key={c.sev} style={{ display: "inline-flex", gap: 6, alignItems: "center" }}>
            <SeverityChip sev={c.sev} />
            <b style={{ fontVariantNumeric: "tabular-nums" }}>{c.n}</b>
          </span>
        ))}
      </div>
      <SeverityTimeline alerts={alerts} />
      <div style={{ marginTop: 12 }}>
        <div style={{ ...alertGrid, opacity: 0.7, fontSize: "0.78rem", padding: "0 6px 4px" }}>
          <span>Severity</span>
          <span>Score</span>
          <span>Alert</span>
          <span>Agent</span>
          <span>When</span>
        </div>
        {alerts.map((a, i) => (
          <AlertItem key={a.exec_id ? `${a.exec_id}-${i}` : i} a={a} />
        ))}
      </div>
    </View>
  );
}

// ChokeActions dispatches a signed jail/thaw command for one process. Rendered
// only when the operator can respond; the server re-authorizes per tenant.
function ChokeActions({ tenant, row }: { tenant: string; row: ChokeRow }) {
  const [tier, setTier] = useState<ChokeTier>("tarpit");
  const [busy, setBusy] = useState(false);
  const [msg, setMsg] = useState("");
  const run = (fn: () => Promise<{ status: string }>) => {
    setBusy(true);
    setMsg("");
    fn()
      .then((r) => setMsg(r.status === "STATUS_APPLIED" ? "✓ applied" : r.status.replace("STATUS_", "").toLowerCase()))
      .catch((e) => setMsg(e instanceof ApiError && e.status === 404 ? "not authorized" : "failed"))
      .finally(() => setBusy(false));
  };
  const ctl: CSSProperties = {
    appearance: "none", font: "inherit", fontSize: "0.75rem", padding: "2px 7px", borderRadius: 5,
    border: "1px solid rgba(148,163,184,0.3)", background: "transparent", color: "inherit", cursor: "pointer"
  };
  return (
    <span style={{ display: "inline-flex", gap: 5, alignItems: "center", flexWrap: "wrap" }}>
      <select value={tier} onChange={(e) => setTier(e.target.value as ChokeTier)} disabled={busy} style={ctl}>
        <option value="throttle">throttle</option>
        <option value="tarpit">tarpit</option>
        <option value="quarantine">quarantine</option>
        <option value="sever">sever</option>
      </select>
      <button type="button" disabled={busy} style={ctl} onClick={() => run(() => jailProcess(tenant, row.agent, row.exec_id, row.pid, tier))}>Jail</button>
      <button type="button" disabled={busy} style={ctl} onClick={() => run(() => thawProcess(tenant, row.agent, row.exec_id, row.pid))}>Thaw</button>
      {msg && <span style={{ fontSize: "0.72rem", opacity: 0.8 }}>{msg}</span>}
    </span>
  );
}

function ChokeView() {
  const active = useTenantStore((s) => s.activeTenant);
  const canRespond = useTenantStore((s) => s.identity?.canRespond) ?? false;
  const { data, state } = useTenantResource(loadChoke, active);
  const rows = data?.chokes ?? [];
  const head = canRespond ? ["State", "Score", "Binary", "PID", "Agent", "Action"] : ["State", "Score", "Binary", "PID", "Agent"];
  return (
    <View
      title="Choke"
      blurb={
        canRespond
          ? "Processes the tenant's agents are choking or watching. Jail moves a process to a tier; Thaw releases it (signed, RBAC-gated)."
          : "Processes the tenant's agents are choking or watching, aggregated fleet-wide (highest score first)."
      }
      state={state}
      count={data?.count ?? 0}
      countLabel="tracked processes"
      emptyText="No processes are being choked or watched right now."
    >
      <DataTable
        head={head}
        rows={rows.map((c) => {
          const base = [c.state, c.score, <span style={mono}>{c.binary || "—"}</span>, c.pid, <span style={{ ...mono, opacity: 0.7 }}>{c.agent.slice(0, 20)}</span>];
          return active && canRespond ? [...base, <ChokeActions tenant={active} row={c} />] : base;
        })}
      />
    </View>
  );
}

function DevicesView() {
  const active = useTenantStore((s) => s.activeTenant);
  const { data, state } = useTenantResource(loadDevices, active);
  const rows = data?.devices ?? [];
  return (
    <View
      title="Devices"
      blurb="Devices under the tenant's MAC gateway (empty unless the network device data plane is active)."
      state={state}
      count={data?.count ?? 0}
      countLabel="devices"
      emptyText="No devices reported — the network device gateway is not active on this tenant's agents."
    >
      <DataTable
        head={["MAC", "State", "Label", "Agent"]}
        rows={rows.map((d) => [<span style={mono}>{d.mac}</span>, d.state, d.label || "—", <span style={{ ...mono, opacity: 0.7 }}>{d.agent.slice(0, 20)}</span>])}
      />
    </View>
  );
}

function FleetView() {
  const active = useTenantStore((s) => s.activeTenant);
  const { data, state } = useTenantResource(loadFleet, active);
  const rows = data?.agents ?? [];
  return (
    <View
      title="Fleet"
      blurb="Agents enrolled in this tenant, from the control-plane registry (liveness, mode, and reported data-plane state)."
      state={state}
      count={data?.count ?? 0}
      countLabel="agents"
      emptyText="No agents have reported for this tenant yet."
    >
      <DataTable
        head={["Agent", "Version", "Mode", "Last seen", "Chokes", "Buffer"]}
        rows={rows.map((a) => [
          <span style={mono}>{a.agent_id.slice(0, 24)}</span>,
          a.version || "—",
          a.mode.replace(/_/g, " ").toLowerCase(),
          relativeTime(a.last_seen),
          a.choke_count,
          a.buffer_depth
        ])}
      />
    </View>
  );
}

const TABS = [
  { id: "soc", label: "SOC", node: <SocView /> },
  { id: "alerts", label: "Alerts", node: <AlertsView /> },
  { id: "choke", label: "Choke", node: <ChokeView /> },
  { id: "devices", label: "Devices", node: <DevicesView /> },
  { id: "fleet", label: "Fleet", node: <FleetView /> }
] as const;

function ConsoleApp() {
  const [tab, setTab] = useState<(typeof TABS)[number]["id"]>("soc");
  return (
    <div>
      <nav style={{ display: "flex", gap: "0.4rem", padding: "0.75rem 1.25rem 0", flexWrap: "wrap" }}>
        {TABS.map((t) => {
          const activeTab = t.id === tab;
          return (
            <button
              key={t.id}
              type="button"
              onClick={() => setTab(t.id)}
              aria-current={activeTab ? "page" : undefined}
              style={{
                appearance: "none",
                cursor: "pointer",
                font: "inherit",
                fontSize: "0.85rem",
                fontWeight: 600,
                padding: "0.4rem 0.9rem",
                borderRadius: "7px 7px 0 0",
                border: "1px solid rgba(148,163,184,0.25)",
                borderBottom: activeTab ? "1px solid transparent" : "1px solid rgba(148,163,184,0.25)",
                background: activeTab ? "rgba(34,211,238,0.10)" : "transparent",
                color: activeTab ? "var(--accent, #22d3ee)" : "inherit"
              }}
            >
              {t.label}
            </button>
          );
        })}
      </nav>
      <div style={{ borderTop: "1px solid rgba(148,163,184,0.25)" }}>{TABS.find((t) => t.id === tab)?.node}</div>
    </div>
  );
}

bootstrapTheme();

const root = document.getElementById("root");
if (!root) {
  throw new Error("Console root element was not found");
}

createRoot(root).render(
  <StrictMode>
    <ConsoleShell>
      <ConsoleApp />
    </ConsoleShell>
  </StrictMode>
);

registerServiceWorker();
