/**
 * Live cgroup tier inhabitants per host — how many PIDs are actually sitting in
 * choke-throttled, choke-tarpit and choke-quarantined right now.
 *
 * This is the ground truth behind the ladder counts: the engine reports what it
 * decided, the cgroups report what the kernel is holding. Bars are scaled to a
 * shared maximum across the whole fleet so one host's spike stays visible next
 * to a quiet one, and a host whose cgroup read failed says so rather than
 * rendering as three empty bars — which would read as "nothing contained".
 */
import { PanelTitle } from "./PanelTitle";
import type { CgroupSnapshot } from "./types";

function cgroupCount(snapshot: CgroupSnapshot | undefined, key: string): number {
  const value = snapshot?.[key];
  return Array.isArray(value) ? value.length : 0;
}

export function FleetCgroupPanel({
  peers,
  cgroupByHost
}: {
  peers: Array<{ name: string }>;
  cgroupByHost: Map<string, { ok: boolean; data?: CgroupSnapshot; error?: string }>;
}) {
  return (
    <section className="fleet-panel">
      <div className="fleet-panel__head">
        <PanelTitle title="Cgroup Tier Inhabitants" />
        <span className="fleet-muted">live PID counts</span>
      </div>
      <CgroupBars peers={peers} cgroupByHost={cgroupByHost} />
    </section>
  );
}

function CgroupBars({
  peers,
  cgroupByHost
}: {
  peers: Array<{ name: string }>;
  cgroupByHost: Map<string, { ok: boolean; data?: CgroupSnapshot; error?: string }>;
}) {
  const rows = peers.map((peer) => {
    const result = cgroupByHost.get(peer.name);
    return {
      name: peer.name,
      ok: Boolean(result?.ok && result.data),
      throttled: cgroupCount(result?.data, "choke-throttled"),
      tarpit: cgroupCount(result?.data, "choke-tarpit"),
      quarantined: cgroupCount(result?.data, "choke-quarantined"),
      error: result?.error
    };
  });
  const max = Math.max(1, ...rows.flatMap((row) => [row.throttled, row.tarpit, row.quarantined]));

  if (rows.length === 0) {
    return <div className="fleet-empty">No cgroup data.</div>;
  }

  return (
    <div className="fleet-cgroups">
      {rows.map((row) =>
        row.ok ? (
          <div className="fleet-cgroup-row" key={row.name}>
            <strong>{row.name}</strong>
            <TierBar label="throttle" value={row.throttled} max={max} tone="warn" />
            <TierBar label="tarpit" value={row.tarpit} max={max} tone="danger" />
            <TierBar label="quarantine" value={row.quarantined} max={max} tone="purple" />
          </div>
        ) : (
          <div className="fleet-cgroup-row fleet-cgroup-row--down" key={row.name}>
            <strong>{row.name}</strong>
            <span>{row.error ?? "unreachable"}</span>
          </div>
        )
      )}
    </div>
  );
}

function TierBar({ label, value, max, tone }: { label: string; value: number; max: number; tone: "warn" | "danger" | "purple" }) {
  return (
    <div className="fleet-tier">
      <span>{label}</span>
      <div className="fleet-tier__track">
        <div className={`fleet-tier__bar fleet-tier__bar--${tone}`} style={{ width: `${Math.max(0, (value / max) * 100)}%` }} />
      </div>
      <em>{value}</em>
    </div>
  );
}
