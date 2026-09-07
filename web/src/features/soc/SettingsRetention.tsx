/**
 * Retention — how long this tenant's telemetry survives.
 *
 * # The caveat this replaces
 *
 * The row used to read: "a per-tenant column exists in the schema and nothing
 * reads it, so this cannot yet differ by tenant — which a data-residency
 * agreement may require." That caveat was the whole defect written down. A
 * customer contractually held to 14 days could have 14 stored in the platform
 * and keep 30, and nothing anywhere would have said so.
 *
 * # Why the control shows two numbers
 *
 * The requested horizon and the effective one. They differ in two cases, and
 * both are cases where echoing the request back would be a lie an auditor later
 * reads as a commitment:
 *
 *   clamped  below two console windows, every window-over-window delta on the
 *            dashboard compares against data that no longer exists
 *   ignored  longer than the deployment keeps — the platform-wide prune has
 *            already deleted those rows, so the request cannot be honoured
 *
 * A tenant may only ever shorten. That asymmetry is stated rather than enforced
 * silently, because a control that accepts a number and quietly does nothing
 * with it is worse than one that refuses.
 */
import { useCallback, useEffect, useState } from "react";
import { InlineNotice, cx } from "./components";
import { getJSON, putJSON } from "../../lib/api";
import { isRouteNotServed } from "./settingsModel";

export interface RetentionPolicy {
  deployment_event_days: number;
  deployment_alert_days: number;
  tenant_days: number;
  effective_event_days: number;
  effective_alert_days: number;
  floor_days: number;
  clamped: boolean;
  ignored: boolean;
}

export interface RetentionState {
  editable: boolean;
  policy?: RetentionPolicy;
  detail?: string;
  note?: string;
  error?: string;
}

interface WriteResult {
  ok?: boolean;
  policy?: RetentionPolicy;
  applies_to?: string;
  error?: string;
}

/** Days, or the empty string for "follow the deployment default". */
export function validateRetentionDays(v: string, floor: number): string {
  const s = v.trim();
  if (!s) return "";
  if (!/^\d+$/.test(s)) return "Enter a whole number of days, or leave it empty to follow the deployment.";
  const n = Number(s);
  if (n === 0) return "";
  if (n < floor) {
    return `Below ${floor} days the console has no prior window to compare against, so this will be raised to ${floor}.`;
  }
  return "";
}

export function RetentionControls({ onChanged }: { onChanged?: () => void }) {
  const [state, setState] = useState<RetentionState | null>(null);
  const [loadError, setLoadError] = useState("");
  /** The route is not registered here at all — a deployment fact, not a fault. */
  const [unsupported, setUnsupported] = useState(false);
  const [days, setDays] = useState("");
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const raw = await getJSON<Partial<RetentionState>>("/api/settings/retention");
      const s: RetentionState = {
        editable: raw?.editable === true,
        policy: raw?.policy,
        detail: raw?.detail,
        note: raw?.note,
        error: raw?.error
      };
      setState(s);
      setDays(s.policy?.tenant_days ? String(s.policy.tenant_days) : "");
      setUnsupported(false);
      setLoadError("");
    } catch (e) {
      // A single-tenant engine has no per-tenant store and does not register
      // this route. Its two siblings — change control and the access trail —
      // both branch on that already; this one did not, so a correctly
      // configured engine raised an amber warning every time an operator
      // opened Evidence. A warning that means nothing on a healthy box is how
      // a console teaches its operators to ignore warnings.
      if (isRouteNotServed(e)) {
        setUnsupported(true);
        setLoadError("");
        return;
      }
      // Absent is not "no retention set". Rendering a blank control on a failed
      // read invites an operator to set a horizon believing none exists.
      setLoadError(e instanceof Error ? e.message : "could not read the retention setting");
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  const floor = state?.policy?.floor_days ?? 14;
  const hint = validateRetentionDays(days, floor);
  const parsed = days.trim() === "" ? 0 : Number(days.trim());
  const dirty = parsed !== (state?.policy?.tenant_days ?? 0);

  async function apply() {
    setBusy(true);
    setResult(null);
    try {
      const res = await putJSON<WriteResult>("/api/settings/retention", {
        days: parsed,
        reason: reason.trim()
      });
      setResult({ ok: res.ok !== false, message: res.applies_to || "stored" });
      setReason("");
      await load();
      onChanged?.();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "failed" });
    } finally {
      setBusy(false);
    }
  }

  if (unsupported) {
    return (
      <InlineNotice tone="info" title="Not applicable to this deployment">
        This single-host engine keeps no per-tenant retention setting: telemetry is pruned on the horizon its
        deploy configured, which is not exposed to the console. Containment decisions are never pruned.
      </InlineNotice>
    );
  }
  if (loadError) {
    return (
      <InlineNotice tone="warn" title="Retention could not be read">
        {loadError}. That is not the same as no retention being set — nothing is being claimed either way.
      </InlineNotice>
    );
  }
  if (!state) return <p className="soc-settings-help">Reading the retention policy…</p>;
  if (!state.editable) {
    return (
      <InlineNotice tone="info" title="Retention is deployment-wide here">
        {state.error || "This deployment has no per-tenant store, so the platform-wide horizon applies to everyone."}
      </InlineNotice>
    );
  }

  const p = state.policy;

  return (
    <div className="soc-guardrails">
      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          <strong>What this tenant actually keeps</strong>
          <span className={cx("soc-settings-badge", p?.tenant_days ? "is-live" : "is-deploy-managed")}>
            {p?.tenant_days ? "tenant setting" : "deployment default"}
          </span>
        </div>
        <p className="soc-settings-help">
          Events for {p?.effective_event_days ?? "—"} days, alerts for {p?.effective_alert_days ?? "—"} days.
          {p && p.tenant_days > 0 && p.tenant_days !== p.effective_event_days
            ? ` The ${p.tenant_days}-day request is not what is in force.`
            : ""}
        </p>
        <p className="soc-settings-caveat">
          {state.detail ||
            "Containment decisions are never pruned — the audit chain has to outlive the telemetry it was made from."}
        </p>
        {state.note ? <InlineNotice tone="warn" title="This setting is not doing what it says">{state.note}</InlineNotice> : null}
      </div>

      <div className="soc-settings-form">
        <label>
          <span>Days to keep — empty follows the deployment ({p?.deployment_event_days ?? "—"} days)</span>
          <input
            value={days}
            onChange={(e) => setDays(e.target.value)}
            inputMode="numeric"
            placeholder={String(p?.deployment_event_days ?? 30)}
            aria-label="Retention in days"
          />
        </label>
        {hint ? <p className="soc-settings-caveat">{hint}</p> : null}
        <p className="soc-settings-caveat">
          A tenant may only shorten. Asking for longer than the deployment keeps is stored and has no effect —
          those rows are already pruned — and the result below will say so rather than accepting the number.
        </p>
        <label>
          <span>Reason — what an auditor will read next to this horizon</span>
          <input
            value={reason}
            onChange={(e) => setReason(e.target.value)}
            placeholder="data-residency agreement: 14 days maximum"
          />
        </label>
        <button
          type="button"
          className="soc-action-button ok"
          disabled={busy || !dirty || reason.trim().length < 3}
          onClick={() => void apply()}
        >
          {busy ? "Applying…" : "Set retention"}
        </button>
      </div>
      {!dirty && !busy ? <p className="soc-settings-caveat">No change to apply.</p> : null}

      {result ? <div className={cx("soc-sensor-result", result.ok ? "ok" : "bad")}>{result.message}</div> : null}
    </div>
  );
}
