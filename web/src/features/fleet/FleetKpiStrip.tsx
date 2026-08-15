/**
 * The six numbers an operator reads before anything else.
 *
 * Two of the six carry incident history in their labels — see the comments
 * inline. Both were cases of a tile claiming more than the underlying count
 * supports, which on a fleet console is worse than showing nothing: it sends
 * someone to investigate an estate that is fine, or reassures them about one
 * that is not.
 */
import { Server } from "lucide-react";
import type { ReactNode } from "react";

import type { FleetKpis } from "./types";

export function FleetKpiStrip({ kpis }: { kpis: FleetKpis }) {
  return (
    <section className="fleet-kpis" aria-label="Fleet KPI strip">
      <KpiTile label="Fleet size" value={kpis.total} sub={`${kpis.devices} fleet devices`} icon={<Server size={17} />} />
      {/* "Reachable", because that is what is counted — a host answers or it
          does not. It was labelled "Healthy", which claims something about
          the host's condition that this number does not measure: a reachable
          host can be kill-switched, drifted, or sitting on a broken chain. */}
      <KpiTile label="Reachable" value={kpis.healthy} sub={`of ${kpis.total} configured`} tone="good" />
      <KpiTile label="Enforcing" value={kpis.enforcing} sub={`${kpis.tracked} tracked processes`} />
      <KpiTile label="Kill-switched" value={kpis.killed} sub="enforcement bypass" tone="danger" />
      <KpiTile
        label="Drift"
        value={kpis.drift}
        sub={kpis.drift === 0 ? "fleet aligned" : "investigate highlighted rows"}
        tone="warn"
      />
      {/* The denominator is hosts that actually MAINTAIN a chain, not every
          reachable host. Dividing by reachable counted a host that does not
          chain centrally as a missing chain, and the caption then read
          "broken chain on a host" — a false alarm about tamper-evidence on a
          fleet where nothing was wrong. */}
      <KpiTile
        label="Audit chain"
        value={
          kpis.auditOk + kpis.auditBroken === 0
            ? "—"
            : `${kpis.auditOk}/${kpis.auditOk + kpis.auditBroken}`
        }
        sub={
          kpis.auditBroken > 0
            ? `broken on ${kpis.auditBroken} host${kpis.auditBroken === 1 ? "" : "s"}`
            : kpis.auditOk + kpis.auditBroken === 0
              ? kpis.auditUnsupported > 0
                ? "not maintained on these hosts"
                : "no data"
              : kpis.auditUnsupported > 0
                ? `all intact · ${kpis.auditUnsupported} not maintained here`
                : "all chains intact"
        }
      />
    </section>
  );
}

function KpiTile({
  label,
  value,
  sub,
  tone = "default",
  icon
}: {
  label: string;
  value: string | number;
  sub: string;
  tone?: "default" | "good" | "warn" | "danger";
  icon?: ReactNode;
}) {
  return (
    <article className={`fleet-kpi fleet-kpi--${tone}`}>
      <div className="fleet-kpi__label">
        {icon}
        {label}
      </div>
      <div className="fleet-kpi__value">{value}</div>
      <div className="fleet-kpi__sub">{sub}</div>
    </article>
  );
}
