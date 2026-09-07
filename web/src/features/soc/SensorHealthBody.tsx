/**
 * Sensor Health & Coverage — "is detection actually running, everywhere it
 * should be, and is any of it being lost?"
 *
 * This replaces the panel formerly labelled "Kprobe performance", which
 * measured posts per minute and called it performance. Throughput is not
 * overhead: that panel showed no CPU, no memory, no latency and no event loss,
 * so it could not answer the question a customer gates a deployment on. It was
 * also half-dead on the multi-tenant console, wanting nine fields from
 * /api/policy-stats where the control plane serves two.
 *
 * The per-policy post rate survives as one section here, because "is this
 * detection still firing" is a genuinely useful question — it is just not the
 * headline one.
 *
 * Everything above it comes from /api/sensor-health, which is computed
 * server-side so the console, an export and an operator all read the same
 * verdict. Where the endpoint is absent, the panel says so rather than
 * rendering zeroes: an unreported sensor is UNKNOWN, never healthy. A fleet
 * view that shows a dead agent as a quiet host is the exact failure this
 * surface exists to prevent.
 */
import { useEffect, useState } from "react";
import { AlertTriangle, CheckCircle2, HelpCircle, ShieldOff } from "lucide-react";
import { EmptyState, cx } from "./components";
import { socApiGet, useResponseAuthority } from "./api";
import { responseWithheldNow } from "./SettingsResponse";
import { postJSON } from "../../lib/api";
import type { SocPolicyStat } from "./types";

/**
 * One reporting sensor.
 *
 * Several fields are OPTIONAL because the two deployments measure different
 * things, and this panel serves both. The control plane learns backlog,
 * evidence loss and freshness from agent heartbeats; the single-tenant engine
 * IS the host, has no heartbeat, and has no evidence-loss counter — so it omits
 * those fields rather than sending zeros.
 *
 * That distinction is the whole point of this surface and it has to survive
 * into the rendering. An absent measurement renders as "not measured"; a zero
 * would assert that no evidence has been lost, which is exactly the fabricated
 * reassurance the API refuses to send. Reading `.toLocaleString()` off these
 * unguarded threw the panel into the error boundary on the engine.
 */
export interface SensorAgent {
  agent_id: string;
  version?: string;
  kernel?: string;
  last_seen_age_seconds?: number;
  fresh?: boolean;
  policies_loaded: number;
  policies_enforce: number;
  missing_policies?: string[];
  kernel_observable: boolean;
  process_plane: string;
  process_links: number;
  device_plane?: string;
  device_links?: number;
  buffer_depth?: number;
  dropped_records?: number;
  dropped_broadcast?: number;
  status: "ok" | "degraded" | "stale" | "unknown";
  issues?: SensorIssue[];
  policy_version?: string;
  /** Which mechanism answered the kernel read: "grpc" | "cli" | "unparsed". */
  kernel_read_via?: string;
  /** What this host can do to a process. Absent on an older server. */
  containment?: Containment;
  /**
   * True and worth stating, but NOT faults — a mechanism absent by deployment
   * is not a defect. Kept out of `issues` so it cannot lower the status or
   * inflate "needing attention"; alarming on an intended configuration trains
   * operators to ignore the panel.
   */
  notes?: SensorIssue[];
}

export interface SensorIssue {
  code: string;
  detail: string;
}

/**
 * What this host can actually DO to a process.
 *
 * Every field is a capability, never a backend name: "noop" means nothing to a
 * SOC analyst, "cannot rate-limit this process's traffic" does. The panel used
 * to print the backend name and compute its verdict without ever looking at it.
 */
export interface Containment {
  verdict: "full" | "partial" | "partial-degraded" | "partial-unknown" | "kill-only" | "none";
  summary: string;
  kill: string;
  freeze: string;
  resource_caps: string;
  net_process: string;
  net_device: string;
  auto: string;
  auto_device?: string;
  manual_lands: boolean;
}

const CONTAINMENT_LABEL: Record<string, string> = {
  full: "Containment: full",
  partial: "Containment: partial",
  "partial-degraded": "Containment: partial · degraded",
  "partial-unknown": "Containment: partial · not fully readable",
  "kill-only": "Containment: kill only",
  none: "Containment: NONE"
};

/**
 * What to DO about each kind of finding.
 *
 * This panel used to state problems and stop. "expected detections not loaded"
 * is a real finding and a dead end unless the reader already knows the fix
 * lives on another surface — so a SOC analyst saw a wall of numbers behind a
 * READ-ONLY badge and had no next step from any of them.
 *
 * Two of these the platform can actually fix, and they get a button. The rest
 * it genuinely cannot, and those get an instruction instead of a control that
 * would do nothing — a disabled-looking button on a problem you must solve by
 * hand is worse than a sentence telling you to go solve it.
 */
const REMEDY: Record<string, { fix: string; inDetections?: boolean }> = {
  "policies-missing": {
    fix: "This host is blind to those techniques until they are loaded. Push them from Detections — the body is already on the platform.",
    inDetections: true
  },
  "policy-enforcing": {
    fix: "An enforcing policy kills with no audit row and no kill-switch. Replace it with a monitor-mode copy from Detections, or unload it on the host.",
    inDetections: true
  },
  "no-tetragon": {
    fix: "Tetragon is not running or its socket is unreachable. Nothing this console does will fix that — restart the tetragon container on the host, then reopen this panel."
  },
  "kernel-unreadable": {
    fix: "The agent reached the host but could not read its policy set. Treat coverage here as unknown, not as zero. Check the agent's Tetragon connection on the host."
  },
  "stale-heartbeat": {
    fix: "This row describes the past. The host may be fine, off, or compromised — this console cannot tell. Check the ebpf-agent service on that machine."
  },
  "evidence-lost": {
    fix: "Telemetry was dropped and is not recoverable. Alert counts for this window are a floor, not a total. Investigate load on the host or raise the uplink cap."
  },

  // ── Enforcement findings ───────────────────────────────────────────────
  //
  // These were emitted by the server with no entry here, so the one finding
  // firing on the estate rendered as a bare sentence with nothing under it.
  // Note which of them get a BUTTON: only the operations that are both
  // possible from a console and safe to perform from a health panel. Arming
  // enforcement or releasing a kill-switch are consequential enough that they
  // belong behind the Choke Gateway page, not behind a click on a status
  // screen — a button here would make an irreversible-feeling action casual.
  "enforcement-degraded": {
    fix: "Quarantine is single-mechanism on this host: it freezes the process, and the CPU cap that should back that freeze up was rejected by the kernel. If a freeze fails or lands slowly, the process runs at full CPU. This is NOT an operator setting — the configured quota is below the kernel's minimum, so it has never applied on any host. Raise it with engineering."
  },
  "no-process-containment": {
    fix: "Three of the four ladder rungs are inert here — only sever (SIGKILL) still works. Check that /sys/fs/cgroup is a cgroup2 mount and that the engine runs as root, then restart it."
  },
  "device-plane-detached": {
    fix: "A tc program with zero links is the failure that looks healthy: device containment is recorded and touches no packet. Check the configured interface names on the host — the plane loaded, it just has nothing to sit on."
  },
  "containment-shadowed": {
    fix: "This is the only posture in which a containment action you press yourself does nothing. Nothing in the audit trail distinguishes a shadowed action from a real one at a glance. Restart the engine without -dry-run, or treat this host as an observer."
  },
  "kill-switched": {
    fix: "Someone disengaged enforcement globally — intended during an incident, dangerous afterwards. Release it from the Choke Gateway page once the reason has passed. It is deliberately not a one-click action from here."
  }
};

/**
 * Operations this panel can perform, keyed by the finding they answer.
 *
 * Every one of these was previously a sentence telling the operator to go
 * somewhere else. That is defensible for a fault nothing can fix from a
 * console; it is not defensible for `containment-manual-only`, where the
 * remedy is one API call the platform already exposes.
 *
 * They are deliberately CONFIRMED rather than one-click. Arming the ladder
 * turns on automatic killing and releasing the kill-switch re-enables
 * enforcement globally — both are the kind of act that should cost a
 * deliberate second click and record a reason, exactly as containment does
 * elsewhere in this console.
 */
const ACTION: Record<string, { label: string; confirm: string; path: string; body: Record<string, unknown> }> = {
  "kill-switched": {
    label: "Release the kill-switch",
    confirm:
      "This re-enables all containment, including automatic action. Only do this once the reason the switch was engaged has passed.",
    path: "/api/choke/kill-switch",
    // {on: false} — both planes decode `on bool`. "halt" was invented.
    body: { on: false }
  }
};

/**
 * Findings whose fix lives on another surface.
 *
 * Arming the ladder used to be an ACTION here, and the symptom that it was in
 * the wrong place was this: arming resolved the finding, so the button removed
 * itself, and the only way back was a page that never mentioned it. An
 * operation you can start in one place and can only undo in another is a
 * one-way door.
 *
 * Mode belongs to the Choke Gateway the way a policy belongs to Detections.
 * The finding routes there instead — the operator still discovers the problem
 * here, and arm and disarm live together where they can be reasoned about.
 */
const ROUTE: Record<string, { label: string; href: string }> = {};

/**
 * The enforcement-mode control, and why it lives on the containment block
 * rather than on a finding.
 *
 * It was first built as an action on the `containment-manual-only` finding.
 * Arming resolved that finding, so the control deleted itself and the only way
 * back was another page — a one-way door. The instinct was to demote it to a
 * link, but that was an over-correction: it left the panel that tells you the
 * ladder is off unable to turn it on, which is a reasonable thing to ask of a
 * surface whose whole job is "what can this host do".
 *
 * The real fault was hanging a two-way control on a one-way signal. Findings
 * only exist while something is WRONG, so an armed host had nowhere to put
 * disarm. The containment block renders in every state, so both directions fit
 * — and the panel stays honest about which state it is in.
 */
const MODE_ACTION = {
  arm: {
    label: "Arm automatic containment",
    confirm:
      "This turns the score ladder on: the platform will contain processes on its own, without a human pressing anything. " +
      "It reverts to detect-only when the engine restarts unless the config says otherwise.",
    body: { enforcing: true }
  },
  disarm: {
    label: "Return to detect-only",
    confirm:
      "The score ladder will stop acting on its own. Containment an operator presses will still reach the kernel — " +
      "that path bypasses detect-only by design.",
    body: { enforcing: false }
  }
} as const;

/**
 * Render a count that a deployment may be unable to measure.
 *
 * Never falls back to 0. On this surface a zero is a claim — "nothing was
 * dropped" — and the one thing worse than not knowing is saying you do.
 */
function measured(n: number | undefined): string {
  return typeof n === "number" ? n.toLocaleString() : "not measured";
}

export interface SensorHealth {
  agents: SensorAgent[];
  agents_total: number;
  agents_fresh: number;
  agents_losing: number;
  dropped_records?: number;
  expected_policies: string[];
  coverage_caveat: string;
  policy_versions?: Record<string, number>;
  policy_drift?: boolean;
}

const STATUS_ICON = {
  ok: CheckCircle2,
  degraded: AlertTriangle,
  stale: ShieldOff,
  unknown: HelpCircle
} as const;

/**
 * One finding: what it is, what to do, and — where the platform can actually
 * do it — a control that does it.
 *
 * Shared by issues and notes because the operator does not care which channel
 * a finding arrived on; they care whether there is something to press. The
 * channels differ in whether they alarm, not in whether they can act.
 */
function Finding({
  item,
  onOpenDetections,
  onRun,
  busy,
  withheld,
  withheldReason,
  withheldKind
}: {
  item: SensorIssue;
  onOpenDetections?: () => void;
  onRun: (code: string) => void;
  busy: string;
  /**
   * Passed down rather than re-read here, so the row and every finding inside
   * it answer "may this operator respond?" from the same value in the same
   * render. The answer itself comes from the one shared predicate — see
   * useResponseAuthority in api.ts.
   *
   * `withheld`, not `readOnlyAccount`: the second is false while whoami is
   * still in flight, which is how a kill-switch RELEASE — offered from this
   * very list — was drawn live for an account the server refuses, for as long
   * as the identity endpoint took to answer, or failed to.
   */
  withheld: boolean;
  /** The sentence for whichever refusal it is; null when nothing is withheld. */
  withheldReason: string | null;
  /**
   * WHICH of the two refusals it is, passed rather than inferred from the
   * sentence. The two are not interchangeable to the operator: "permission" is
   * a statement about their account, "pending" is a statement about what this
   * console has been told so far, and deriving one by string-matching the other
   * is how the wrong one gets printed after a copy edit.
   */
  withheldKind: "permission" | "pending" | null;
}) {
  const remedy = REMEDY[item.code];
  const action = ACTION[item.code];
  const route = ROUTE[item.code];
  return (
    <li>
      <strong>{item.detail}</strong>
      {remedy ? <span className="soc-sensor-remedy">{remedy.fix}</span> : null}
      <div className="soc-sensor-findingactions">
        {remedy?.inDetections && onOpenDetections ? (
          <button type="button" className="soc-ghost-button" onClick={onOpenDetections}>
            Fix in Detections
          </button>
        ) : null}
        {action ? (
          // Kept on the page and disabled rather than removed: this is the
          // release of a kill-switch, and a control that simply vanishes reads
          // as a deployment without one. The title names the PERMISSION, so a
          // read-only operator does not press it to find out.
          <button
            type="button"
            className="soc-ghost-button"
            disabled={withheld || busy === item.code}
            title={withheldReason ?? undefined}
            onClick={() => onRun(item.code)}
          >
            {busy === item.code ? "Working…" : action.label}
          </button>
        ) : null}
        {action && withheld ? (
          <span className="soc-sensor-remedy" data-withheld={withheldKind ?? undefined}>
            {withheldReason}
          </span>
        ) : null}
        {route ? (
          <a className="soc-ghost-button" href={route.href}>{route.label}</a>
        ) : null}
      </div>
    </li>
  );
}

function Row({ agent, onOpenDetections }: { agent: SensorAgent; onOpenDetections?: () => void }) {
  // The same permission read as the alert drill and the Settings response
  // section. This panel offers two of the three widest write controls on the
  // platform — arm/disarm and the kill-switch release — and offered both to an
  // account the control plane refuses, which is how an operator learns they
  // are read-only by watching a POST do nothing.
  // `withheld` drives every disabled below; `readOnlyAccount` only chooses the
  // sentence. Keying the controls off the latter armed both of this panel's
  // writes — arm/disarm and the kill-switch release — for the whole window in
  // which whoami had not answered, which on a control plane whose /api/whoami
  // is failing is the entire session.
  const { readOnlyAccount, withheld, withheldReason } = useResponseAuthority();
  const withheldKind = withheld ? (readOnlyAccount ? "permission" : "pending") : null;
  const [confirming, setConfirming] = useState<string>("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  // The operation itself. Reports what the server said rather than assuming
  // success — arming the ladder can be refused, and a console that says
  // "armed" over a refusal is the failure this whole panel exists to prevent.
  async function run(code: string) {
    // The guard behind the disabled buttons, asked at the moment of the
    // request rather than taken from the render that drew them: no path from
    // this panel may reach POST /api/choke/* while the answer is in flight, or
    // after the server has refused. A confirm panel opened before whoami landed
    // is exactly such a path.
    const denied = responseWithheldNow();
    if (denied) {
      setResult({ ok: false, message: denied });
      return;
    }
    // Mode lives on the containment block; everything else is a finding.
    const action =
      code === "arm" || code === "disarm"
        ? { label: MODE_ACTION[code].label, path: "/api/choke/mode", body: MODE_ACTION[code].body as Record<string, unknown> }
        : ACTION[code];
    if (!action) return;
    setBusy(code);
    setResult(null);
    try {
      await postJSON(action.path, { ...action.body, reason: reason.trim() });
      setResult({ ok: true, message: `${action.label} — applied. This panel refreshes on its next poll; confirm the change there rather than assuming it took.` });
      setConfirming("");
      setReason("");
    } catch (err) {
      setResult({ ok: false, message: err instanceof Error ? err.message : "the action failed" });
    } finally {
      setBusy("");
    }
  }

  const Icon = STATUS_ICON[agent.status] ?? HelpCircle;
  return (
    <div className={cx("soc-sensor-row", `is-${agent.status}`)}>
      <div className="soc-sensor-head">
        <Icon size={14} aria-hidden="true" />
        <strong>{agent.agent_id}</strong>
        <span className="soc-sensor-status">{agent.status}</span>
        {typeof agent.last_seen_age_seconds === "number"
          ? <em>{Math.round(agent.last_seen_age_seconds)}s ago</em>
          : <em title="This console reads the host it runs on, so there is no heartbeat to age">live</em>}
      </div>
      {/* CONTAINMENT — stated in the healthy case too.
          This panel used to look identical whether the host could contain
          anything or not: two backend names and a green tick. A customer
          reading it to answer "can I trust this platform" got a wall of nouns.
          The verdict says what the host can DO, in one sentence, always. */}
      {agent.containment ? (
        <div className={`soc-sensor-containment verdict-${agent.containment.verdict}`}>
          <strong>{CONTAINMENT_LABEL[agent.containment.verdict] ?? "Containment"}</strong>
          <span>{agent.containment.summary}</span>
          {/* Both directions, always present. The mode is part of what this
              host can DO, which is what this block states — so the control
              belongs here rather than on a finding that disappears the moment
              it is acted on. */}
          {agent.containment.auto === "enforcing" || agent.containment.auto === "detect-only" ? (
            <div className="soc-sensor-findingactions">
              <button
                type="button"
                className="soc-ghost-button"
                disabled={withheld || busy !== ""}
                title={withheldReason ?? undefined}
                onClick={() => setConfirming(agent.containment!.auto === "enforcing" ? "disarm" : "arm")}
              >
                {agent.containment.auto === "enforcing" ? MODE_ACTION.disarm.label : MODE_ACTION.arm.label}
              </button>
              {/* The verdict above stays exactly as it is — what the host can
                  DO is a reading, and readings are not withheld. Only the
                  control that changes it is, and it says whose decision that
                  was. */}
              {withheld ? (
                <span className="soc-sensor-remedy" data-withheld={withheldKind ?? undefined}>
                  {withheldReason}
                </span>
              ) : null}
            </div>
          ) : null}
        </div>
      ) : null}

      <div className="soc-sensor-kv">
        <span>policies</span>
        <strong>
          {agent.kernel_observable ? `${agent.policies_loaded} loaded` : "unknown"}
          {agent.policies_enforce > 0 ? ` · ${agent.policies_enforce} ENFORCING` : ""}
        </strong>
        <span>process plane</span>
        <strong>{agent.process_plane}{agent.process_links ? ` · ${agent.process_links} links` : ""}</strong>
        <span>device plane</span>
        <strong>{agent.device_plane
          ? `${agent.device_plane}${agent.device_links ? ` · ${agent.device_links} links` : ""}`
          : "not reported"}</strong>
        {/* Two different facts, deliberately not summed. A backlog still
            drains; a dropped record never arrives. */}
        <span>backlog</span>
        <strong>{measured(agent.buffer_depth)}</strong>
        <span>evidence lost</span>
        <strong className={agent.dropped_records ? "is-hot" : ""}>{measured(agent.dropped_records)}</strong>
      </div>
      {confirming ? (
        <div className="soc-sensor-confirm">
          <strong>{confirmLabel(confirming)}?</strong>
          <span>{confirmText(confirming)}</span>
          <label>
            <span>Reason — recorded with the action</span>
            <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="CAB-1234: arming for the maintenance window" autoFocus />
          </label>
          <div className="soc-sensor-findingactions">
            <button
              type="button"
              className="soc-action-button ok"
              disabled={withheld || busy !== "" || reason.trim().length < 3}
              title={withheldReason ?? undefined}
              onClick={() => void run(confirming)}
            >
              {busy ? "Working…" : confirmLabel(confirming)}
            </button>
            <button type="button" className="soc-ghost-button" onClick={() => { setConfirming(""); setReason(""); }}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}
      {result ? <div className={cx("soc-sensor-result", result.ok ? "ok" : "bad")}>{result.message}</div> : null}

      {agent.issues?.length ? (
        <ul className="soc-sensor-issues">
          {agent.issues.map((i) => (
            <Finding key={i.code + i.detail} item={i} onOpenDetections={onOpenDetections} onRun={setConfirming} busy={busy} withheld={withheld} withheldReason={withheldReason} withheldKind={withheldKind} />
          ))}
        </ul>
      ) : null}
      {agent.notes?.length ? (
        <ul className="soc-sensor-notes">
          {agent.notes.map((n) => (
            <Finding key={n.code + n.detail} item={n} onOpenDetections={onOpenDetections} onRun={setConfirming} busy={busy} withheld={withheld} withheldReason={withheldReason} withheldKind={withheldKind} />
          ))}
        </ul>
      ) : null}
    </div>
  );
}

export function SensorHealthBody({
  policyStats,
  open,
  onOpenDetections
}: {
  policyStats: SocPolicyStat[];
  open: boolean;
  /**
   * Jump to the surface that can fix a coverage gap. Passed in rather than
   * reimplemented here: Detections already holds the policy bodies, the push
   * path and the per-policy Restore, and a second copy of that logic would be a
   * second thing to keep honest.
   */
  onOpenDetections?: () => void;
}) {
  const [health, setHealth] = useState<SensorHealth | null>(null);
  const [supported, setSupported] = useState(true);

  useEffect(() => {
    if (!open) return undefined;
    let cancelled = false;
    const controller = new AbortController();
    const tick = async () => {
      const result = await socApiGet<SensorHealth>("/api/sensor-health", null as never, controller.signal);
      if (cancelled) return;
      if (result.ok && result.data) {
        setHealth(result.data);
        setSupported(true);
      } else {
        // A deployment without the endpoint gets an honest "not available",
        // never a zeroed table that reads as a healthy fleet.
        setHealth(null);
        setSupported(false);
      }
    };
    void tick();
    const id = window.setInterval(() => void tick(), 10_000);
    return () => {
      cancelled = true;
      controller.abort();
      window.clearInterval(id);
    };
  }, [open]);

  if (!supported) {
    return (
      <EmptyState
        title="Sensor health is not served by this deployment"
        detail="This build of the server does not expose /api/sensor-health. Nothing is inferred from its absence — the sensors may be fine or may be down; this console cannot tell."
      />
    );
  }
  if (!health) return <EmptyState title="Loading sensor health…" detail="Reading the agent registry." />;

  const degraded = health.agents.filter((a) => a.status !== "ok").length;
  // Null where the deployment does not report policy fingerprints at all —
  // distinct from an empty object, which would mean "reported, and none".
  const versions = health.policy_versions ?? null;

  return (
    <div className="soc-sensor">
      <div className="soc-sensor-summary">
        <div>
          <span className="soc-stat-label">Reporting</span>
          <strong>{health.agents_fresh}/{health.agents_total}</strong>
        </div>
        <div>
          <span className="soc-stat-label">Needing attention</span>
          <strong className={degraded ? "is-hot" : ""}>{degraded}</strong>
        </div>
        {/* CANNOT CONTAIN — the question the panel never answered.
            Counts hosts whose containment verdict is "none" (nothing reaches
            the kernel, including a pressed action) or "kill-only". Renders "—"
            rather than a green 0 when any host's posture could not be read,
            for the same reason the evidence tile does: an unmeasured zero is
            the most reassuring lie available. */}
        <div>
          <span className="soc-stat-label">Cannot contain</span>
          {(() => {
            const known = health.agents.filter((a) => a.containment);
            if (known.length === 0) {
              return <strong title="This deployment does not report containment capability">—</strong>;
            }
            if (known.some((a) => a.containment!.verdict === "partial-unknown")) {
              return <strong title="At least one host's containment posture could not be read">—</strong>;
            }
            const n = known.filter((a) => ["none", "kill-only"].includes(a.containment!.verdict)).length;
            return <strong className={n ? "is-hot" : ""}>{n}</strong>;
          })()}
        </div>
        <div>
          <span className="soc-stat-label">Evidence lost</span>
          {/* A big green 0 on this tile is the most reassuring thing the panel
              can say, so it may only appear when something actually counted.
              The engine has no evidence-loss counter and says so. */}
          <strong
            className={health.dropped_records ? "is-hot" : ""}
            title={typeof health.dropped_records === "number"
              ? undefined
              : "This deployment has no evidence-loss counter, so nothing is claimed either way"}
          >
            {typeof health.dropped_records === "number" ? health.dropped_records.toLocaleString() : "—"}
          </strong>
        </div>
      </div>
      {/* The caveat is part of the number, not a footnote to it. */}
      <p className="soc-sensor-caveat">{health.coverage_caveat}</p>

      {/* Detection drift. The agent has fingerprinted its kernel policy set on
          every heartbeat since the field existed, and nothing rendered it —
          so a host that quietly lost a detection looked identical to one that
          simply had nothing to report. An alert count cannot show you this. */}
      {/* Drift is a FLEET question: do these hosts run the same detections?
          A single-host console has nothing to compare against, so it sends no
          policy_versions and this whole block is skipped rather than rendering
          "1 policy set, no drift" — which would be a reassurance derived from
          having only one host to look at. */}
      {versions === null ? null : health.policy_drift ? (
        <div className="soc-sensor-drift is-hot">
          <strong>Detection drift</strong>
          <span>
            {Object.keys(versions).length} different kernel policy sets across the
            reporting fleet — these hosts are not running the same detections.
          </span>
          <ul>
            {Object.entries(versions).map(([version, count]) => (
              <li key={version}><code>{version.slice(0, 12)}</code> · {count} host{count === 1 ? "" : "s"}</li>
            ))}
          </ul>
        </div>
      ) : Object.keys(versions).length === 1 ? (
        <p className="soc-sensor-caveat">
          Detection set agrees across all reporting hosts (<code>
            {Object.keys(versions)[0].slice(0, 12)}
          </code>).
        </p>
      ) : null}

      {health.agents.length === 0 ? (
        <EmptyState title="No agents enrolled for this tenant" detail="Nothing is reporting, so nothing is being watched." />
      ) : (
        <div className="soc-sensor-list">
          {health.agents.map((agent) => <Row key={agent.agent_id} agent={agent} onOpenDetections={onOpenDetections} />)}
        </div>
      )}

      <div className="soc-sensor-policies">
        <span className="soc-stat-label">Detection activity · kernel posts per policy</span>
        {policyStats.length === 0 ? (
          <em className="soc-watch-quiet">no policy activity reported</em>
        ) : (
          <div className="soc-sensor-kv">
            {policyStats.slice(0, 12).map((stat) => (
              <span key={stat.name} style={{ display: "contents" }}>
                <span>{stat.name}</span>
                <strong>{(stat.posts ?? 0).toLocaleString()}</strong>
              </span>
            ))}
          </div>
        )}
      </div>
    </div>
  );
}

function confirmLabel(code: string): string {
  if (code === "arm" || code === "disarm") return MODE_ACTION[code].label;
  return ACTION[code]?.label ?? "Confirm";
}

function confirmText(code: string): string {
  if (code === "arm" || code === "disarm") return MODE_ACTION[code].confirm;
  return ACTION[code]?.confirm ?? "";
}
