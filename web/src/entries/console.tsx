import { StrictMode, useEffect, useState, type CSSProperties, type ReactNode } from "react";
import { createRoot } from "react-dom/client";

import { ConsoleShell } from "../app/ConsoleShell";
import { useTenantStore } from "../stores/tenant";
import { fetchChoke, fetchDevices, fetchFleet, fetchTelemetry } from "../lib/console";
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
const loadChoke = (t: string) => fetchChoke(t);
const loadDevices = (t: string) => fetchDevices(t);
const loadFleet = (t: string) => fetchFleet(t);

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

function ChokeView() {
  const active = useTenantStore((s) => s.activeTenant);
  const { data, state } = useTenantResource(loadChoke, active);
  const rows = data?.chokes ?? [];
  return (
    <View
      title="Choke"
      blurb="Processes the tenant's agents are choking or watching, aggregated fleet-wide (highest score first)."
      state={state}
      count={data?.count ?? 0}
      countLabel="tracked processes"
      emptyText="No processes are being choked or watched right now."
    >
      <DataTable
        head={["State", "Score", "Binary", "PID", "Agent"]}
        rows={rows.map((c) => [c.state, c.score, <span style={mono}>{c.binary || "—"}</span>, c.pid, <span style={{ ...mono, opacity: 0.7 }}>{c.agent.slice(0, 20)}</span>])}
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
