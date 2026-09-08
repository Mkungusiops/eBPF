/**
 * The numbers an operator reads before anything else.
 *
 * Several of the captions carry incident history — see the comments inline.
 * Every one of them was a tile claiming more than the underlying count
 * supports, which on a fleet console is worse than showing nothing: it sends
 * someone to investigate an estate that is fine, or reassures them about one
 * that is not.
 *
 * TWO RULES GOVERN THIS STRIP.
 *  1. A tile says what its number COUNTS. "Fleet size 1" over "5 fleet
 *     devices" was two different denominators in one tile, and nothing on it
 *     said which was which.
 *  2. A comparative tile is only rendered when there is something to compare.
 *     Drift over one host is a host disagreeing with itself; it can only ever
 *     read zero, and a zero an operator reads as "the fleet is aligned" is a
 *     reassurance nothing measured.
 */
import { Server } from "lucide-react";
import type { ReactNode } from "react";

import type { FleetKpis } from "./types";

export function FleetKpiStrip({ kpis }: { kpis: FleetKpis }) {
  // Hosts that ANSWERED with state, which is the only population a majority or
  // a drift count can be computed over.
  const comparable = kpis.healthy >= 2;
  // Whether any reachable host maintains a hash chain at all. When none does —
  // the whole multi-tenant fleet, where each agent chains its own decisions —
  // the tile has no fact to report in either direction.
  const chained = kpis.auditOk + kpis.auditBroken;

  return (
    <section className="fleet-kpis" aria-label="Fleet KPI strip">
      {/* Both numbers named. The value counts HOSTS (configured peers); the
          caption's other number counts network devices seen by those hosts,
          which on a single-host tenant read as "5 fleet devices" under
          "FLEET SIZE 1" with nothing to say they were different things. */}
      <KpiTile
        label="Fleet size"
        value={kpis.total}
        sub={
          kpis.deviceHosts === 0
            ? `host${kpis.total === 1 ? "" : "s"} · no device inventory reported`
            : `host${kpis.total === 1 ? "" : "s"} · ${kpis.devices} network device${kpis.devices === 1 ? "" : "s"} seen on ${kpis.deviceHosts}`
        }
        icon={<Server size={17} />}
      />
      {/* "Reachable", because that is what is counted — a host answers or it
          does not. It was labelled "Healthy", which claims something about
          the host's condition that this number does not measure: a reachable
          host can be kill-switched, drifted, or sitting on a broken chain. */}
      <KpiTile label="Reachable" value={kpis.healthy} sub={`of ${kpis.total} configured`} tone="good" />
      <KpiTile label="Enforcing" value={kpis.enforcing} sub={`${kpis.tracked} tracked processes`} />
      {/* The count is of hosts that SAID the switch is engaged. Hosts that did
          not report one are named in the caption rather than folded into the
          zero — on the control plane, which cannot read the field at all, that
          fold turned "nobody knows" into "nothing is bypassed". */}
      <KpiTile
        label="Kill-switched"
        value={kpis.killed}
        sub={
          kpis.killUnknown > 0
            ? `${kpis.killUnknown} host${kpis.killUnknown === 1 ? "" : "s"} did not report`
            : "enforcement bypass"
        }
        tone={kpis.killed > 0 ? "danger" : kpis.killUnknown > 0 ? "warn" : "default"}
      />
      {comparable ? (
        <KpiTile
          label="Drift"
          value={kpis.drift}
          sub={kpis.drift === 0 ? "fleet aligned" : "investigate highlighted rows"}
          tone="warn"
        />
      ) : null}
      {/* Rendered only when some reachable host actually maintains a chain.
          The denominator is those hosts, not every reachable one: dividing by
          reachable counted a host that does not chain centrally as a missing
          chain, and the caption then read "broken chain on a host" — a false
          alarm about tamper-evidence on a fleet where nothing was wrong.
          Where NO host chains, the tile rendered "—" over "not maintained on
          these hosts" forever: a permanent blank in a KPI slot, which reads as
          a gap in coverage rather than as a check this deployment does not run.
          The fact itself is not lost — the Audit column on each host row says
          "not maintained" per host, where it belongs. */}
      {chained > 0 ? (
        <KpiTile
          label="Audit chain"
          value={`${kpis.auditOk}/${chained}`}
          sub={
            kpis.auditBroken > 0
              ? `broken on ${kpis.auditBroken} host${kpis.auditBroken === 1 ? "" : "s"}`
              : kpis.auditUnsupported > 0
                ? `all intact · ${kpis.auditUnsupported} not maintained here`
                : "all chains intact"
          }
        />
      ) : null}
      {/* Said plainly rather than left to be inferred from a missing tile. A
          single-agent tenant is a normal deployment, not a broken fleet, and
          an operator who cannot see why Drift disappeared will look for the
          fault instead. */}
      {!comparable && kpis.total > 0 ? (
        <p className="fleet-kpis__note">
          {kpis.healthy === 0
            ? "No host reported its state, so drift and the majority-ladder reading are not shown."
            : kpis.total === 1
              ? "This tenant has one host, so there is nothing to compare: drift and the majority-ladder reading are not shown."
              : `Only 1 of ${kpis.total} configured hosts reported, so there is nothing to compare: drift and the majority-ladder reading are not shown.`}
        </p>
      ) : null}
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
