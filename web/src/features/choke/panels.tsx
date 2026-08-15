// Left-rail diagnostic panels: what the engine's own subsystems report, the
// score thresholds that drive the containment ladder, and the two kernel-side
// mirrors (cgroup tiers, BPF token buckets) that show enforcement actually
// landed. Each one reads a snapshot the route already fetched.
import { useEffect, useMemo, useState } from "react";
import type { BucketEntry, CgroupMap, CircuitEntry, PolicyPreviewResponse, Thresholds } from "./types";
import {
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

  const facts: EngineFact[] = [
    {
      label: "Kernel sensor",
      value: !sensorKnown ? "Not reported" : connected ? "Connected" : "Disconnected",
      hint: !sensorKnown
        ? sensorNote || "This server does not observe agent kernel sensors — check Sensor Health per host"
        : connected
          ? "Tetragon eBPF event feed is live"
          : "No live syscall/exec events from the kernel",
      status: !sensorKnown ? "neutral" : connected ? "ok" : "danger"
    },
    {
      label: "Enforcement plane",
      value: isNoop ? "Detect-only" : `eBPF · ${attached}/${expected || attached} attached`,
      hint: isNoop ? "Decisions are logged, not applied to the kernel" : "Choke actions enforced in-kernel",
      status: isNoop ? "warn" : bpf.healthy === true ? "ok" : "warn"
    },
    {
      label: "Event store",
      value: storeBackend === "postgres" ? "PostgreSQL" : storeBackend === "sqlite" ? "SQLite" : storeBackend || "—",
      hint: storeTarget ? storeTarget.replace(/^.*\//, "…/") : "decision + audit chain persistence",
      status: "neutral"
    },
    {
      label: "Sign-in security",
      value: "bcrypt · CSRF · sessions",
      hint: str(auth.rate_limit) ? `rate limit ${str(auth.rate_limit)}` : "hardened auth",
      status: "ok"
    },
    {
      label: "Telemetry",
      value: metricsOn ? "Metrics on" : "Metrics off",
      hint: `${str(obs.log_format) || "text"} logs · ${str(obs.log_level) || "info"} level`,
      status: "neutral"
    },
    { label: "Uptime", value: str(health.uptime) || "—", status: "neutral" },
    { label: "Build", value: `v${str(health.version) || "?"}`, status: "neutral" }
  ];
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
  onCommit,
  dataPanel,
}: {
  thresholds: Thresholds;
  circuits: CircuitEntry[];
  disabled: boolean;
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
      <div className="choke-threshold-track">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <input
            key={key}
            type="range"
            min={1}
            max={120}
            value={draft[key]}
            onChange={(event) => patch(key, Number(event.target.value))}
            disabled={disabled}
            aria-label={key}
          />
        ))}
      </div>
      <div className="choke-threshold-inputs">
        {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as Array<keyof Thresholds>).map((key) => (
          <label key={key}>
            <span>{key.replace("_at", "")}</span>
            <input type="number" min={1} value={draft[key]} onChange={(event) => patch(key, Number(event.target.value))} disabled={disabled} />
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
      <div className="choke-panel-footer">
        <button className="choke-inline-button" type="button" onClick={() => setDraft(thresholds)}>Cancel</button>
        <button
          className="choke-action-button warn"
          type="button"
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
            <div className={`choke-bucket-row state-${state}`} key={`${bucket.pid}-${bucket.flags}`}>
              <div className="choke-bucket-title">
                <strong>PID {bucket.pid}</strong>
                <StateBadge state={state} />
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

export function PolicyPreview({
  preview,
  error,
  checking,
  circuits,
}: {
  preview: PolicyPreviewResponse | null;
  error: string;
  checking: boolean;
  circuits: CircuitEntry[];
}) {
  if (checking) return <LoadingState label="Evaluating policy" />;
  if (error) return <ErrorState title="Policy invalid" body={error} />;
  if (!preview) {
    return (
      <EmptyState
        title="No preview yet"
        body="Edit the policy and hit Preview matches to dry-run it against the live snapshot. 'Build from live' seeds one that matches what's tracked right now."
      />
    );
  }
  if (preview.valid === false) return <ErrorState title="Policy invalid" body={(preview.errors || []).join("; ")} />;

  const doc = preview.policy;
  const matches = preview.matches || [];
  const scanned = preview.scanned ?? circuits.length;
  const targetStates = doc?.match?.states && doc.match.states.length > 0 ? doc.match.states : ["any non-pristine"];
  const buckets = doc?.buckets || [];
  const denySyscalls = doc?.deny_syscalls || [];
  const denyPaths = doc?.deny_paths || [];

  // Live state distribution so an empty match set is explained, not mysterious.
  const liveStates = new Map<string, number>();
  for (const c of circuits) {
    const s = c.state || "pristine";
    liveStates.set(s, (liveStates.get(s) || 0) + 1);
  }
  const liveSummary = STATE_ORDER.map((s) => (liveStates.get(s) ? `${s}×${liveStates.get(s)}` : null))
    .filter(Boolean)
    .join(" · ");

  return (
    <div className="choke-preview">
      <div className="choke-preview-head">
        <span className="choke-preview-ok">valid</span>
        <strong>{doc?.metadata?.name || "unnamed"}</strong>
        <span className="choke-preview-count">{matches.length} matched · {scanned} scanned</span>
      </div>
      {doc?.metadata?.description ? <p className="choke-preview-desc">{doc.metadata.description}</p> : null}

      <div className="choke-preview-effects">
        <div><span>targets</span><strong>{(doc?.match?.binaries || []).join(", ") || "—"}</strong></div>
        <div><span>when state</span><strong>{targetStates.join(", ")}</strong></div>
        {buckets.length > 0 ? (
          <div><span>throttles</span><strong>{buckets.map((b) => `${b.dimension} @ ${b.rate_per_sec ?? "?"}/s`).join(", ")}</strong></div>
        ) : null}
        {denySyscalls.length > 0 ? <div><span>deny syscalls</span><strong>{denySyscalls.join(", ")}</strong></div> : null}
        {denyPaths.length > 0 ? <div><span>deny paths</span><strong>{denyPaths.join(", ")}</strong></div> : null}
      </div>

      {matches.length === 0 ? (
        <div className="choke-preview-nomatch">
          <strong>No live matches</strong>
          <span>
            Nothing in the tracked snapshot ({scanned} processes) matches these binaries in state{" "}
            {targetStates.join("/")}.
          </span>
          {liveSummary ? <span>Live states: {liveSummary}.</span> : null}
          <span className="choke-muted">Use “Build from live” to target what’s actually running.</span>
        </div>
      ) : (
        <div className="choke-preview-list">
          {matches.slice(0, 50).map((entry) => (
            <div key={entry.exec_id || entry.pid}>
              <StateBadge state={entry.state} />
              <span>{entry.pid || "-"}</span>
              <span className="truncate" title={entry.binary || ""}>{entry.binary || "(unknown)"}</span>
              <strong>{entry.score || 0}</strong>
            </div>
          ))}
          {matches.length > 50 ? <span className="choke-muted">+{matches.length - 50} more</span> : null}
        </div>
      )}
    </div>
  );
}
