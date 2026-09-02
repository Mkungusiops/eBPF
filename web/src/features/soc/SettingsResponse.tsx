/**
 * The Response section: the controls that decide when this platform acts.
 *
 * # Why these are controls and not readouts
 *
 * They were first rendered as read-only values because none of them survives a
 * restart. That was the wrong call. "Reverts on restart" is a caveat to state,
 * not a reason to withhold a change an operator can already make through the
 * API — and withholding it turned the settings page into a report.
 *
 * Every one of these is safe to expose today because of work done elsewhere:
 * the threshold ladder is validated at all three hops (a partial body used to
 * zero sever_at and sever every tracked process), and all four mutations now
 * write hash-chained audit rows with the operator and their reason.
 */
import { useState } from "react";
import { InlineNotice, cx } from "./components";
import { postJSON } from "../../lib/api";

export interface Thresholds {
  throttle_at: number;
  tarpit_at: number;
  quarantine_at: number;
  sever_at: number;
}

/**
 * Mirrors circuit.Config.Validate on the server, so the operator learns about
 * a bad ladder while looking at the field that caused it rather than from a
 * 400 a second later.
 *
 * Not a substitute for the server check — the server is what protects the
 * fleet, and this cannot see a request that did not come from this form.
 */
export function validateLadder(t: Thresholds): string {
  const vals = [t.throttle_at, t.tarpit_at, t.quarantine_at, t.sever_at];
  if (vals.some((v) => !Number.isFinite(v) || v <= 0)) {
    return "All four must be above zero. A sever threshold of 0 severs every tracked process.";
  }
  if (!(t.throttle_at < t.tarpit_at && t.tarpit_at < t.quarantine_at && t.quarantine_at < t.sever_at)) {
    return "They must ascend: throttle < tarpit < quarantine < sever. Otherwise the lower rungs are unreachable.";
  }
  return "";
}

export function ResponseControls({
  thresholds,
  mode,
  killSwitched,
  onChanged
}: {
  thresholds: Thresholds | null;
  mode: string;
  killSwitched: boolean | null | undefined;
  onChanged: () => void;
}) {
  const [draft, setDraft] = useState<Thresholds | null>(null);
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState("");
  const [result, setResult] = useState<{ ok: boolean; message: string } | null>(null);
  const [confirming, setConfirming] = useState("");

  const editing = draft ?? thresholds;
  const ladderError = editing ? validateLadder(editing) : "";
  const ladderChanged =
    !!draft && !!thresholds && (Object.keys(thresholds) as (keyof Thresholds)[]).some((k) => draft[k] !== thresholds[k]);

  async function run(path: string, body: Record<string, unknown>, label: string) {
    setBusy(label);
    setResult(null);
    try {
      await postJSON(path, { ...body, reason: reason.trim() });
      setResult({ ok: true, message: `${label} applied. Recorded in the audit chain with your reason.` });
      setDraft(null);
      setReason("");
      setConfirming("");
      onChanged();
    } catch (e) {
      setResult({ ok: false, message: e instanceof Error ? e.message : "failed" });
    } finally {
      setBusy("");
    }
  }

  return (
    <>
      {result ? <div className={cx("soc-sensor-result", result.ok ? "ok" : "bad")}>{result.message}</div> : null}

      {/* THE LADDER */}
      <div className="soc-settings-form">
        <div className="soc-settings-ladder">
          {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as const).map((k) => (
            <label key={k}>
              <span>{k.replace("_at", "")}</span>
              <input
                type="number"
                min={1}
                value={editing ? editing[k] : ""}
                onChange={(e) =>
                  setDraft({ ...(editing as Thresholds), [k]: Number(e.target.value) } as Thresholds)
                }
              />
            </label>
          ))}
        </div>
        {ladderError ? (
          <p className="soc-settings-caveat" role="alert">{ladderError}</p>
        ) : (
          <p className="soc-settings-help">
            A process is throttled at {editing?.throttle_at ?? "—"} points, tarpitted at {editing?.tarpit_at ?? "—"},
            quarantined at {editing?.quarantine_at ?? "—"} and severed at {editing?.sever_at ?? "—"}.
            Sever is a SIGKILL and cannot be undone.
          </p>
        )}
        <label>
          <span>Reason — recorded in the audit chain</span>
          <input value={reason} onChange={(e) => setReason(e.target.value)} placeholder="CAB-1234: tuning for the billing estate" />
        </label>
        <div className="soc-settings-actions">
          <button
            type="button"
            className="soc-action-button ok"
            disabled={!ladderChanged || !!ladderError || reason.trim().length < 3 || busy !== ""}
            onClick={() => void run("/api/choke/thresholds", { ...(editing as Thresholds) }, "New thresholds")}
          >
            {busy === "New thresholds" ? "Applying…" : "Apply thresholds"}
          </button>
          {ladderChanged ? (
            <button type="button" className="soc-ghost-button" onClick={() => setDraft(null)}>Discard</button>
          ) : null}
        </div>
      </div>

      {/* MODE — both directions, always present, so the control never vanishes
          after being used. */}
      <div className="soc-settings-actions">
        <span className="soc-settings-count">
          Ladder is <strong>{mode || "unknown"}</strong>
        </span>
        <button
          type="button"
          className="soc-ghost-button"
          disabled={busy !== "" || (mode !== "enforcing" && mode !== "detect-only")}
          onClick={() => setConfirming(mode === "enforcing" ? "disarm" : "arm")}
        >
          {mode === "enforcing" ? "Return to detect-only" : "Arm automatic containment"}
        </button>

        <span className="soc-settings-count">
          Emergency stop is{" "}
          <strong className={killSwitched ? "is-hot" : ""}>
            {killSwitched === null || killSwitched === undefined ? "not reported" : killSwitched ? "ENGAGED" : "released"}
          </strong>
        </span>
        {killSwitched === true || killSwitched === false ? (
          <button type="button" className="soc-ghost-button" disabled={busy !== ""}
            onClick={() => setConfirming(killSwitched ? "release" : "engage")}>
            {killSwitched ? "Release the kill-switch" : "Engage the kill-switch"}
          </button>
        ) : null}
      </div>

      {confirming ? (
        <div className="soc-sensor-confirm">
          <strong>{CONFIRM[confirming].label}?</strong>
          <span>{CONFIRM[confirming].detail}</span>
          <label>
            <span>Reason — recorded in the audit chain</span>
            <input value={reason} onChange={(e) => setReason(e.target.value)} autoFocus
              placeholder="CAB-1234: arming for the maintenance window" />
          </label>
          <div className="soc-settings-actions">
            <button type="button" className="soc-action-button ok"
              disabled={busy !== "" || reason.trim().length < 3}
              onClick={() => void run(CONFIRM[confirming].path, CONFIRM[confirming].body, CONFIRM[confirming].label)}>
              {busy ? "Working…" : CONFIRM[confirming].label}
            </button>
            <button type="button" className="soc-ghost-button" onClick={() => { setConfirming(""); setReason(""); }}>
              Cancel
            </button>
          </div>
        </div>
      ) : null}

      <InlineNotice tone="warn" title="These take effect immediately and are not saved">
        A restart returns this host to the values it was deployed with. Persisting them is the next piece of work,
        and until it lands a change made here is real but temporary.
      </InlineNotice>
    </>
  );
}

/**
 * The confirmations. Each states the consequence in the operator's terms —
 * "the platform will contain processes on its own" rather than "sets
 * enforcing=true" — because the person clicking is deciding a policy, not
 * setting a flag.
 */
const CONFIRM: Record<string, { label: string; detail: string; path: string; body: Record<string, unknown> }> = {
  arm: {
    label: "Arm automatic containment",
    detail:
      "The score ladder will contain processes on its own, without a human pressing anything. Protected binaries are still refused.",
    path: "/api/choke/mode",
    body: { enforcing: true }
  },
  disarm: {
    label: "Return to detect-only",
    detail:
      "The ladder stops acting on its own. Containment an operator presses still reaches the kernel — that path bypasses detect-only by design.",
    path: "/api/choke/mode",
    body: { enforcing: false }
  },
  engage: {
    label: "Engage the kill-switch",
    detail:
      "ALL containment stops, including an action an operator presses themselves. Nothing this console does will reach the kernel until it is released.",
    path: "/api/choke/kill-switch",
    body: { on: true }
  },
  release: {
    label: "Release the kill-switch",
    detail: "Containment resumes, including automatic action if the ladder is armed.",
    path: "/api/choke/kill-switch",
    body: { on: false }
  }
};
