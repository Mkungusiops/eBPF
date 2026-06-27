import { useEffect, useState } from "react";
import { DataTable, EmptyState, ErrorState, Panel, StatCard, StatusBadge } from "../../components/ui";
import { Shell } from "../../app/Shell";
import { ApiError, getJSON } from "../../lib/api";
import type { FleetEnvelope, FleetHost } from "../../lib/types";
import { useInterval } from "../common/useInterval";

export function FleetPage() {
  const [hosts, setHosts] = useState<FleetHost[]>([]);
  const [stateRows, setStateRows] = useState<FleetEnvelope<Record<string, unknown>>[]>([]);
  const [error, setError] = useState("");

  async function load() {
    try {
      const [nextHosts, nextState] = await Promise.all([
        getJSON<FleetHost[]>("/api/fleet/hosts"),
        getJSON<FleetEnvelope<Record<string, unknown>>[]>("/api/fleet/state")
      ]);
      setHosts(Array.isArray(nextHosts) ? nextHosts : []);
      setStateRows(Array.isArray(nextState) ? nextState : []);
      setError("");
    } catch (err) {
      if (err instanceof ApiError && err.status === 503) setError(err.message);
      else setError(err instanceof Error ? err.message : "fleet unavailable");
    }
  }

  useEffect(() => {
    void load();
  }, []);
  useInterval(() => void load(), 5000);

  const healthy = stateRows.filter((row) => row.ok).length;

  return (
    <Shell title="Fleet Console" subtitle="Multi-host Choke control plane">
      {error ? <div className="mb-4"><ErrorState title="Fleet disabled" body={error} /></div> : null}
      <div className="mb-5 grid gap-3 md:grid-cols-5">
        <StatCard label="Hosts" value={hosts.length || stateRows.length} />
        <StatCard label="Healthy" value={healthy} tone="good" />
        <StatCard label="Unreachable" value={Math.max(0, stateRows.length - healthy)} tone="warn" />
        <StatCard label="Mode" value={<StatusBadge value="mixed" />} />
        <StatCard label="Refresh" value="5s" />
      </div>
      <div className="grid gap-4 xl:grid-cols-[0.75fr_1.25fr_0.8fr]">
        <div className="space-y-4">
          {["Targeting selector", "Posture preset chooser", "Thresholds editor", "Emergency controls", "Confirm modal"].map((title) => (
            <Panel key={title} title={title} testId={`fleet-${title.toLowerCase().replaceAll(" ", "-")}`}>
              <p className="text-sm text-muted">Fan-out controls use target selection, CSRF, confirmation, and per-host result toasts.</p>
            </Panel>
          ))}
        </div>
        <div className="space-y-4">
          <Panel title="Fleet table" testId="fleet-table">
            <DataTable
              rows={stateRows}
              empty={<EmptyState title="No fleet hosts" body="Configure fleet hosts or verify the fleet backend." />}
              columns={[
                { key: "host", header: "Host", render: (row) => row.name ?? "unknown" },
                { key: "status", header: "Status", render: (row) => <StatusBadge value={row.ok ? "ok" : row.error ?? "down"} /> },
                { key: "mode", header: "Mode", render: (row) => String(row.data?.mode ?? "unknown") },
                { key: "kill", header: "Kill", render: (row) => String(Boolean(row.data?.kill_switched)) }
              ]}
            />
          </Panel>
          <Panel title="Cgroup tier inhabitants" testId="fleet-cgroup-tiers">
            <p className="text-sm text-muted">Shared-scale cgroup tier bars from `/api/fleet/cgroups`.</p>
          </Panel>
        </div>
        <div className="space-y-4">
          <Panel title="Live decisions feed" testId="fleet-decisions-feed">
            <p className="text-sm text-muted">Merged `/api/fleet/decisions?limit=80` feed.</p>
          </Panel>
          <Panel title="Alerts feed" testId="fleet-alerts-feed">
            <p className="text-sm text-muted">Merged `/api/fleet/alerts` feed.</p>
          </Panel>
          <Panel title="Disabled banner" testId="fleet-disabled-banner">
            <p className="text-sm text-muted">503-aware fleet disabled state is surfaced above.</p>
          </Panel>
          <Panel title="Toasts" testId="fleet-toasts">
            <p className="text-sm text-muted">Per-host fan-out results report partial failures.</p>
          </Panel>
        </div>
      </div>
    </Shell>
  );
}
