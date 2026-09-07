/**
 * Change control (EN-2) — whether a second operator must approve a sever.
 *
 * # Why this was the worst read-only row on the page
 *
 * Every part of four-eyes was already built and running: the queue, the
 * approval and deny endpoints, the TTL, the rule that the requester cannot
 * approve their own request, and the rule that nothing which STOPS enforcement
 * may ever wait on a quorum. The only deploy-time thing was the switch — so a
 * team that decided mid-incident it wanted four-eyes had to edit a unit file
 * and restart the control plane, during the incident in which they decided it.
 *
 * # The floor
 *
 * If the platform was deployed with change control mandated, this console
 * cannot switch it off, and the control renders locked rather than 409-ing
 * after the operator commits. A tenant may only ever tighten from here — the
 * same asymmetry as the protected-binary floor, because a control that exists
 * to check one actor must not be removable by that actor.
 *
 * # What turning it off does not do
 *
 * It does not release what the queue is already holding. That is stated on the
 * result, because the opposite assumption is the dangerous one: an operator
 * who believed it did would walk away from a parked sever.
 */
import { useCallback, useEffect, useState } from "react";
import { Lock, ShieldCheck } from "lucide-react";
import { InlineNotice, cx } from "./components";
import { getJSON, putJSON } from "../../lib/api";
import { isRouteNotServed } from "./settingsModel";

export interface ChangeControlState {
  enabled: boolean;
  /** The deploy mandated it; this console cannot switch it off. */
  mandated: boolean;
  can_disable: boolean;
  gated: string[];
  never_gated: string[];
  /** False when this deployment has no approval queue at all. */
  available: boolean;
  pending?: number;
  reason?: string;
  actor?: string;
  updated_at?: string;
  error?: string;
}

interface WriteResult {
  ok?: boolean;
  enabled?: boolean;
  pending?: number;
  note?: string;
  applies_to?: string;
  error?: string;
}

export function ChangeControlControls({ onChanged }: { onChanged?: () => void }) {
  const [state, setState] = useState<ChangeControlState | null>(null);
  const [loadError, setLoadError] = useState("");
  const [unsupported, setUnsupported] = useState(false);
  const [confirming, setConfirming] = useState(false);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);

  const load = useCallback(async () => {
    try {
      const raw = await getJSON<Partial<ChangeControlState>>("/api/settings/change-control");
      setState({
        enabled: raw?.enabled === true,
        mandated: raw?.mandated === true,
        can_disable: raw?.can_disable === true,
        gated: Array.isArray(raw?.gated) ? raw.gated : [],
        never_gated: Array.isArray(raw?.never_gated) ? raw.never_gated : [],
        available: raw?.available !== false,
        pending: typeof raw?.pending === "number" ? raw.pending : undefined,
        reason: raw?.reason,
        actor: raw?.actor,
        updated_at: raw?.updated_at,
        error: raw?.error
      });
      setUnsupported(false);
      setLoadError("");
    } catch (e) {
      const msg = e instanceof Error ? e.message : "could not read the change-control setting";
      // A single-tenant engine has no approval queue and does not serve this
      // route. That is a different statement from "the read failed", and
      // showing a warning for it would be crying wolf on every engine console.
      if (isRouteNotServed(e)) {
        setUnsupported(true);
        setLoadError("");
      } else {
        setLoadError(msg);
      }
    }
  }, []);

  useEffect(() => {
    void load();
  }, [load]);

  async function apply(next: boolean) {
    setBusy(true);
    setResult(null);
    try {
      const res = await putJSON<WriteResult>("/api/settings/change-control", {
        enabled: next,
        reason: reason.trim()
      });
      const parts = [
        next
          ? "change control is on — quarantine and sever now wait for a second operator"
          : "change control is off — destructive actions apply immediately again"
      ];
      if (res.applies_to) parts.push(res.applies_to);
      if (res.note) parts.push(res.note);
      setResult({ ok: true, message: parts.join(". ") });
      setReason("");
      setConfirming(false);
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
        Four-eyes approval needs a control plane with an approval queue and more than one operator. This is a
        single-host engine, so there is no second operator for a request to wait on.
      </InlineNotice>
    );
  }
  if (loadError) {
    return (
      <InlineNotice tone="warn" title="Change control could not be read">
        {loadError}. That is not the same as it being off — nothing is being claimed either way.
      </InlineNotice>
    );
  }
  if (!state) return <p className="soc-settings-help">Reading the change-control posture…</p>;

  const locked = state.mandated;
  const next = !state.enabled;

  return (
    <div className="soc-guardrails">
      {state.error ? (
        <InlineNotice tone="warn" title="Stored setting unavailable">
          {state.error}
        </InlineNotice>
      ) : null}

      <div className="soc-guardrail-block">
        <div className="soc-guardrail-blockhead">
          {locked ? <Lock size={13} aria-hidden="true" /> : <ShieldCheck size={13} aria-hidden="true" />}
          <strong>{state.enabled ? "A second operator is required" : "One operator can act alone"}</strong>
          <span className={cx("soc-settings-badge", state.enabled ? "is-live" : "is-not-wired")}>
            {state.enabled ? "on" : "off"}
          </span>
          {locked ? <span className="soc-settings-badge is-deploy-managed">set by the platform</span> : null}
        </div>

        <p className="soc-settings-help">
          {state.enabled
            ? "Quarantine and sever are held in the approval queue until someone other than the requester approves them. Nothing reaches an agent while a request is held."
            : "Quarantine and sever apply as soon as one operator confirms them. Nothing is held for review."}
        </p>

        {state.gated.length > 0 ? (
          <div className="soc-chiprow">
            {state.gated.map((g) => (
              <span key={g} className="soc-chip">
                {g}
              </span>
            ))}
          </div>
        ) : null}

        <p className="soc-settings-caveat">
          Never held, whatever this is set to: {state.never_gated.join(", ")}. The way out of a bad state must not
          wait for a quorum.
        </p>

        {state.reason ? (
          <p className="soc-settings-help">
            Last changed by {state.actor || "an operator"} — “{state.reason}”
          </p>
        ) : null}

        {typeof state.pending === "number" && state.pending > 0 ? (
          <p className="soc-settings-caveat">
            {state.pending} request{state.pending === 1 ? "" : "s"} waiting in the approval queue right now.
          </p>
        ) : null}
      </div>

      {locked ? (
        <InlineNotice tone="info" title="This platform mandates change control">
          It was deployed with four-eyes required, so it cannot be switched off for one tenant here. Change it
          where the platform is deployed, with whoever owns that decision.
        </InlineNotice>
      ) : (
        <>
          {confirming ? (
            <InlineNotice
              tone={next ? "info" : "warn"}
              title={next ? "Require a second operator?" : "Let one operator sever alone?"}
            >
              {next
                ? "Quarantine and sever will be parked until a second person approves them. Containment gets slower, deliberately — and the requester cannot approve their own request."
                : "Destructive actions will apply immediately with no second pair of eyes. Anything already in the queue stays there; switching this off does not approve it."}
            </InlineNotice>
          ) : null}

          <div className="soc-settings-form">
            {confirming ? (
              <label>
                <span>Reason — stored with this setting, and what an auditor will read</span>
                <input
                  value={reason}
                  onChange={(e) => setReason(e.target.value)}
                  placeholder={
                    next
                      ? "group policy requires two approvers for destructive actions"
                      : "single on-call operator overnight; approvals would stall containment"
                  }
                />
              </label>
            ) : null}
            <div className="soc-settings-actions">
              {confirming ? (
                <>
                  <button
                    type="button"
                    className={cx("soc-action-button", next ? "ok" : "bad")}
                    disabled={busy || reason.trim().length < 3}
                    onClick={() => void apply(next)}
                  >
                    {busy ? "Applying…" : next ? "Require a second operator" : "Switch change control off"}
                  </button>
                  <button type="button" className="soc-ghost-button" disabled={busy} onClick={() => setConfirming(false)}>
                    Cancel
                  </button>
                </>
              ) : (
                <button
                  type="button"
                  className={cx("soc-action-button", next ? "ok" : "bad")}
                  disabled={!state.available}
                  onClick={() => setConfirming(true)}
                >
                  {next ? "Require a second operator" : "Switch change control off"}
                </button>
              )}
            </div>
          </div>
        </>
      )}

      {!state.available ? (
        <p className="soc-settings-caveat">
          This control plane has no approval queue, so there is nothing for a held request to wait in.
        </p>
      ) : null}

      {result ? <div className={cx("soc-sensor-result", result.ok ? "ok" : "bad")}>{result.message}</div> : null}
    </div>
  );
}
