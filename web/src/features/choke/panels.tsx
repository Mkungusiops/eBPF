// Left-rail diagnostic panels: what the engine's own subsystems report, the
// score thresholds that drive the containment ladder, and the two kernel-side
// mirrors (cgroup tiers, BPF token buckets) that show enforcement actually
// landed. Each one reads a snapshot the route already fetched.
import { useEffect, useMemo, useState } from "react";
import type { BucketEntry, CgroupMap, CircuitEntry, Thresholds } from "./types";
import { shortAgent,
  STATE_ORDER,
  bucketFlagsLabel,
  countByState,
  getCgroupPids,
  sortBuckets,
  stateForScore,
  thresholdsAscending,
} from "./utils";
import { EmptyState, ErrorState, LoadingState, Panel, StateBadge } from "./components";

type EngineFactStatus = "ok" | "warn" | "danger" | "neutral";
interface EngineFact {
  label: string;
  value: string;
  hint?: string;
  status: EngineFactStatus;
}

// Translate the raw /api/system-health object into plain-language facts a SOC
// lead can read at a glance — no JSON blobs. Each fact carries a status colour.
export function buildEngineFacts(health: Record<string, unknown>): EngineFact[] {
  const obj = (v: unknown): Record<string, unknown> =>
    v && typeof v === "object" ? (v as Record<string, unknown>) : {};
  const str = (v: unknown): string => (typeof v === "string" ? v : v == null ? "" : String(v));

  const tetra = obj(health.tetragon);
  const bpf = obj(health.bpf);
  const store = obj(health.store);
  const auth = obj(health.auth);
  const obs = obj(health.observability);

  // The kernel sensor lives on the agent. The single-tenant engine inspects it
  // directly and answers `tetragon: {connected}`; the control plane cannot see
  // it at all and says so via `kernel_sensor`. Treating a missing field as
  // `false` painted a red "Disconnected" on every multi-tenant console — a
  // claim about a host this server never probed. Absent is now its own state.
  const sensorKnown = "connected" in tetra;
  const connected = tetra.connected === true;
  const sensorNote = str(health.kernel_sensor);
  const bpfBackend = str(bpf.backend);
  const isNoop = bpfBackend === "" || bpfBackend === "noop";
  const attached = Number(bpf.attached_links ?? 0);
  const expected = Number(bpf.expected_links ?? 0);
  const storeBackend = str(store.backend).toLowerCase();
  const storeTarget = str(store.target);
  const metricsOn = obs.metrics_enabled === true;

  // The control plane states outright that it cannot observe agent kernel
  // sensors. Rendering a row whose only content is that disclaimer spends the
  // most prominent line of the panel on a non-answer; Sensor Health per host
  // is where that question is actually answered.
  const facts: EngineFact[] = [];
  if (sensorKnown || !sensorNote) {
    facts.push({
      label: "Kernel sensor",
      value: !sensorKnown ? "Not reported" : connected ? "Connected" : "Disconnected",
      hint: !sensorKnown
        ? sensorNote || "This server does not observe agent kernel sensors — check Sensor Health per host"
        : connected
          ? "Tetragon eBPF event feed is live"
          : "No live syscall/exec events from the kernel",
      status: !sensorKnown ? "neutral" : connected ? "ok" : "danger"
    });
  }
  facts.push(
    {
      label: "Enforcement plane",
      value: isNoop ? "Detect-only" : `eBPF · ${attached}/${expected || attached} attached`,
      hint: isNoop ? "Decisions are logged, not applied to the kernel" : "Choke actions enforced in-kernel",
      status: isNoop ? "warn" : bpf.healthy === true ? "ok" : "warn"
    },
    {
      label: "Event store",
      // A control plane reports store health as {ok}, not a backend name, and
      // rendering "—" beside a store that is reporting itself healthy is the
      // panel discarding the one fact it was given.
      value: storeBackend === "postgres" ? "PostgreSQL"
        : storeBackend === "sqlite" ? "SQLite"
        : storeBackend ? storeBackend
        : store.ok === true ? "Reachable"
        : store.ok === false ? "Unreachable"
        : "—",
      hint: storeTarget ? storeTarget.replace(/^.*\//, "…/")
        : str(store.error) || "decision + audit chain persistence",
      status: store.ok === false ? "danger" : "neutral"
    },
    {
      // Telemetry is CONFIGURATION, not health, and is marked neutral so it
      // never contributes a colour to a panel an operator scans for trouble.
      // It stays because "metrics are off" explains an absent dashboard
      // elsewhere; it does not stay as a status.
      label: "Telemetry",
      value: metricsOn ? "Metrics on" : "Metrics off",
      hint: `${str(obs.log_format) || "text"} logs · ${str(obs.log_level) || "info"} level · configuration, not health`,
      status: "neutral"
    }
  );

  // Sign-in security is deliberately NOT a row here.
  //
  // It rendered a hardcoded "bcrypt · CSRF · sessions" with status "ok",
  // permanently. It could not change and could not report a problem: if
  // authentication broke tomorrow it would still show a green dot reading
  // "hardened auth". That is a reassurance label occupying a status position,
  // in the one panel an operator scans to find out what is wrong — the same
  // defect as the four unanswerable rows removed from this panel, and worse,
  // because those at least admitted they did not know.
  //
  // The rate limit it used to mention is real configuration and belongs with
  // the rest of the deployment's shape, not in a health readout.
  if (str(auth.rate_limit)) {
    facts.push({
      label: "Sign-in rate limit",
      value: str(auth.rate_limit),
      hint: "configuration, not health",
      status: "neutral"
    });
  }

  // Rows this plane can actually answer, appended rather than shown as blanks.
  //
  // The control plane has no kernel sensor, no uptime and no engine build to
  // report, so those rows rendered "Not reported", "—", "—" and "v?" — four of
  // seven saying nothing. A panel that mostly answers "unknown" trains people
  // to skip the place where "is my platform healthy" belongs, and it was
  // occupying exactly that place. What the control plane DOES know — how many
  // agents it has, how many are fresh, and how long since the quietest one
  // called home — was in the payload and unrendered.
  if (typeof health.agents === "number") {
    const total = Number(health.agents);
    const fresh = Number(health.agents_fresh ?? 0);
    facts.push({
      label: "Agents",
      value: `${fresh}/${total} reporting`,
      hint: total === 0 ? "no agents enrolled in this tenant"
        : fresh < total ? "a stale agent is not being protected — check Fleet"
        : "all enrolled agents are current",
      status: total === 0 ? "warn" : fresh < total ? "warn" : "ok"
    });
    const age = Number(health.last_seen_age_seconds ?? -1);
    if (age >= 0) {
      facts.push({
        label: "Last heartbeat",
        value: age < 90 ? `${age}s ago` : `${Math.floor(age / 60)}m ago`,
        hint: "the most recent agent check-in this server has seen",
        status: age > 300 ? "warn" : "ok"
      });
    }
  }

  // Uptime and build only when this plane reports them. "—" and "v?" are not
  // readings; they are the panel filling space with a shrug.
  if (str(health.uptime)) {
    facts.push({ label: "Uptime", value: str(health.uptime), status: "neutral" });
  }
  if (str(health.version)) {
    facts.push({ label: "Build", value: str(health.version), status: "neutral" });
  }
  return facts;
}

export function EngineStack({ health, disabled }: { health: Record<string, unknown> | null; disabled: boolean }) {
  if (disabled) return <EmptyState title="Gateway disabled" body="Subsystem health is unavailable until the choke gateway is enabled." />;
  if (!health) return <LoadingState label="loading subsystem health" />;
  if (Object.keys(health).length === 0) return <EmptyState title="No subsystem data" body="The health endpoint returned an empty object." />;
  const facts = buildEngineFacts(health);
  return (
    <div className="choke-facts">
      {facts.map((fact) => (
        <div key={fact.label} className="choke-fact">
          <span className={`choke-fact-dot status-${fact.status}`} aria-hidden="true" />
          <div className="choke-fact-body">
            <span className="choke-fact-label">{fact.label}</span>
            <strong className="choke-fact-value">{fact.value}</strong>
            {fact.hint ? <span className="choke-fact-hint">{fact.hint}</span> : null}
          </div>
        </div>
      ))}
    </div>
  );
}

// Thresholds are edited against a live blast radius: the same tracked snapshot
// re-bucketed under the draft, so an operator sees how many processes each
// slider moves BEFORE committing a rung change to the whole host.
export function ThresholdPanel({
  thresholds,
  circuits,
  disabled,
  disabledReason = "",
  onCommit,
  dataPanel,
}: {
  thresholds: Thresholds;
  circuits: CircuitEntry[];
  disabled: boolean;
  /**
   * Why the ladder cannot be COMMITTED, when the reason is the operator —
   * refused by the server, or not yet answered for. Empty for every other kind
   * of disable: those already have their own banner, and repeating them here
   * would name a second cause for one effect.
   *
   * It says nothing about the sliders above, which stay live for everyone.
   */
  disabledReason?: string;
  onCommit: (thresholds: Thresholds) => Promise<void>;
  dataPanel: string;
}) {
  const [draft, setDraft] = useState<Thresholds>(thresholds);
  const [saving, setSaving] = useState(false);
  useEffect(() => setDraft(thresholds), [thresholds]);

  const blast = useMemo(() => {
    const before = countByState(circuits, thresholds);
    const after: Record<string, number> = { pristine: 0, throttled: 0, tarpit: 0, quarantined: 0, severed: 0 };
    circuits.forEach((entry) => {
      after[stateForScore(entry.score || 0, draft)] += 1;
    });
    return STATE_ORDER.map((state) => ({ state, before: before[state], after: after[state] || 0 }));
  }, [circuits, draft, thresholds]);

  function patch(key: keyof Thresholds, value: number): void {
    setDraft((prev) => {
      const next = { ...prev, [key]: value };
      if (next.throttle_at >= next.tarpit_at) next.tarpit_at = next.throttle_at + 1;
      if (next.tarpit_at >= next.quarantine_at) next.quarantine_at = next.tarpit_at + 1;
      if (next.quarantine_at >= next.sever_at) next.sever_at = next.quarantine_at + 1;
      return next;
    });
  }

  return (
    <Panel dataPanel={dataPanel} title="Thresholds" actions={<span className={thresholdsAscending(draft) ? "choke-ok" : "choke-danger"}>{thresholdsAscending(draft) ? "ascending" : "invalid"}</span>}>
      {/* THE SLIDERS ARE NOT THE WRITE. Moving one re-buckets the tracked
          snapshot in this browser and changes the blast-radius table below;
          nothing leaves the page until "Commit thresholds" is pressed, and that
          button is what the permission gate belongs on.
          They were disabled for a read-only account, which took the SIMULATION
          away from the one role that exists to read the estate: an analyst who
          may not move the ladder still has to be able to answer "how many
          processes would a sever-at-70 catch?" before asking someone who can.
          So: gate the write, never the thinking. */}
      <div className="choke-threshold-track">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <input
            key={key}
            type="range"
            min={1}
            max={120}
            value={draft[key]}
            onChange={(event) => patch(key, Number(event.target.value))}
            aria-label={key}
          />
        ))}
      </div>
      <div className="choke-threshold-inputs">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <label key={key}>
            <span>{key.replace("_at", "")}</span>
            <input type="number" min={1} value={draft[key]} onChange={(event) => patch(key, Number(event.target.value))} />
          </label>
        ))}
      </div>
      <div className="choke-blast">
        {blast.map((row) => (
          <div key={row.state}>
            <StateBadge state={row.state} />
            <span>{row.before} -&gt; {row.after}</span>
            <strong className={row.after - row.before > 0 ? "warn" : ""}>{row.after - row.before > 0 ? "+" : ""}{row.after - row.before}</strong>
          </div>
        ))}
      </div>
      {disabledReason ? <p className="choke-permission-note">{disabledReason}</p> : null}
      <div className="choke-panel-footer">
        <button className="choke-inline-button" type="button" onClick={() => setDraft(thresholds)}>Cancel</button>
        <button
          className="choke-action-button warn"
          type="button"
          title={disabledReason || undefined}
          disabled={disabled || saving || !thresholdsAscending(draft)}
          onClick={async () => {
            setSaving(true);
            try {
              await onCommit(draft);
            } finally {
              setSaving(false);
            }
          }}
        >
          {saving ? "Saving" : "Commit thresholds"}
        </button>
      </div>
    </Panel>
  );
}

export function CgroupTiers({ cgroups }: { cgroups: CgroupMap }) {
  const tiers = [
    { key: "choke-throttled", state: "throttled" },
    { key: "choke-tarpit", state: "tarpit" },
    { key: "choke-quarantined", state: "quarantined" },
  ];
  const max = Math.max(1, ...tiers.map((tier) => getCgroupPids(cgroups[tier.key]).length));
  return (
    <div className="choke-cgroup-list">
      {tiers.map((tier) => {
        const pids = getCgroupPids(cgroups[tier.key]);
        return (
          <div key={tier.key}>
            <StateBadge state={tier.state} />
            <span className="choke-meter"><span style={{ width: `${(pids.length / max) * 100}%` }} /></span>
            <strong>{pids.length}</strong>
            <small>{pids.slice(0, 8).join(", ") || "empty"}</small>
          </div>
        );
      })}
    </div>
  );
}

export function BucketList({ buckets }: { buckets: BucketEntry[] }) {
  const sorted = sortBuckets(buckets);
  const rows = sorted.slice(0, 80);
  const totalRate = sorted.reduce((sum, bucket) => sum + Number(bucket.rate_per_sec || 0), 0);
  const depleted = sorted.filter((bucket) => Number(bucket.tokens || 0) <= 0).length;
  const stateCounts = sorted.reduce<Record<string, number>>((acc, bucket) => {
    const state = bucketFlagsLabel(bucket.flags);
    acc[state] = (acc[state] || 0) + 1;
    return acc;
  }, {});
  const activeStates = ["sever", "quarantine", "tarpit", "throttle", "observe"].filter((state) => stateCounts[state]);

  if (rows.length === 0) return <EmptyState title="No BPF bucket rows" body="Detect-only mode or no active transitions can leave the map empty." />;
  return (
    <div className="choke-bpf-mirror">
      <div className="choke-bpf-summary" aria-label="BPF mirror summary">
        <div>
          <span>Mirrored PIDs</span>
          <strong>{sorted.length}</strong>
        </div>
        <div>
          <span>Budget</span>
          <strong>{totalRate}/s</strong>
        </div>
        <div>
          <span>Depleted</span>
          <strong>{depleted}</strong>
        </div>
      </div>

      <div className="choke-bpf-state-strip" aria-label="BPF states">
        {activeStates.map((state) => (
          <span key={state}>
            <StateBadge state={state} />
            <strong>{stateCounts[state]}</strong>
          </span>
        ))}
      </div>

      <div className="choke-bucket-list" aria-label="Kernel token buckets mirrored from BPF">
        {rows.map((bucket) => {
          const state = bucketFlagsLabel(bucket.flags);
          const burst = Math.max(1, Number(bucket.burst || 0));
          const tokens = Math.max(0, Math.min(burst, Number(bucket.tokens || 0)));
          const tokenPct = Math.round((tokens / burst) * 100);
          const tokenLabel = tokens <= 0 ? "depleted" : tokenPct < 35 ? "low headroom" : "available";
          return (
            <div
              className={`choke-bucket-row state-${state}`}
              // The agent is part of the identity. Without it two hosts
              // throttling the same PID share a key and React renders one of
              // them, dropping the other from the kernel map entirely.
              key={`${bucket.agent || "host"}-${bucket.pid}-${bucket.flags}`}
            >
              <div className="choke-bucket-title">
                <strong>PID {bucket.pid}</strong>
                <StateBadge state={state} />
                {bucket.agent ? <code className="choke-bucket-agent">{shortAgent(bucket.agent)}</code> : null}
              </div>
              <div className="choke-bucket-meter" title={`${bucket.tokens}/${bucket.burst} tokens available`}>
                <span style={{ width: `${tokenPct}%` }} />
              </div>
              <div className="choke-bucket-meta">
                <span><strong>{bucket.rate_per_sec}/s</strong> rate limit</span>
                <span><strong>{bucket.tokens}/{bucket.burst}</strong> tokens</span>
                <em>{tokenLabel}</em>
              </div>
            </div>
          );
        })}
      </div>
      {sorted.length > rows.length ? <span className="choke-muted">+{sorted.length - rows.length} more mirrored buckets</span> : null}
    </div>
  );
}

