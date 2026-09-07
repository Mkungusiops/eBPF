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
import { AUTHORITY_PENDING_REASON, READ_ONLY_ACCOUNT_REASON, responseAuthorityNow, useResponseAuthority } from "./api";
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

/**
 * WHETHER A WRITE MAY BE SENT AT ALL, read at the instant of the request rather
 * than off the render that drew the button.
 *
 * api.ts has this rule already, but only inside `jailSocAlert` and
 * `applyChokeAction` — the two containment calls that module makes itself.
 * Every other write in this feature (the score ladder, the enforcement mode,
 * the kill-switch, the suppression list) goes straight from a component to
 * `postJSON`, so a button's `disabled` was the ONLY thing between a read-only
 * account and POST /api/choke/kill-switch. That is one forgotten flag away from
 * armed, and it WAS armed: while the authority store sits at "loading" every
 * one of those surfaces read `readOnlyAccount === false` and enabled itself —
 * not merely for a first paint, but for the whole of an outage in which
 * /api/whoami never answers, which this control plane has had.
 *
 * Reading the store NOW rather than the value captured when the control
 * rendered also closes the confirm-panel window: a panel opened before whoami
 * answered carries a stale "permitted", and the operator presses it after the
 * refusal has landed.
 *
 * It lives in this file rather than in api.ts only because api.ts was not this
 * change's to edit. It belongs beside `responseWithheldReason` there, which is
 * the identical rule for the two calls api.ts owns.
 */
export function responseWithheldNow(): string | null {
  const authority = responseAuthorityNow();
  if (authority === "loading") return AUTHORITY_PENDING_REASON;
  if (authority === false) return READ_ONLY_ACCOUNT_REASON;
  return null;
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
  // Whether the SERVER will accept a write from this operator, read from the
  // one shared predicate every containment surface in this feature consumes.
  //
  // This section was the largest hole in the permission gate: the kill-switch,
  // the enforcement-mode toggle and the score ladder are the three widest
  // blast radii on the platform, and all three were armed for an account the
  // control plane refuses. A read-only operator pressed "Engage the
  // kill-switch", got a 403 they could not see, and had no way to tell a
  // refused write from a platform that had stopped enforcing.
  //
  // null — the single-tenant engine, which has no notion of a principal who
  // may not respond and never publishes the field — leaves every control
  // exactly as it was.
  //
  // `withheld` and not `readOnlyAccount` is what every `disabled` below reads.
  // The two differ in exactly the state that armed this panel: before whoami
  // answers, `readOnlyAccount` is FALSE (the server has not said no — it has
  // said nothing), so keying the controls off it painted a live kill-switch for
  // an account that may not press it. `withheld` covers that window too.
  //
  // `readOnlyAccount` is still read, but only to choose WHICH sentence to
  // print: "your account is read-only" is a claim about the operator, and
  // making it while the answer is in flight is a different lie told to a
  // responder.
  const { readOnlyAccount, pending, withheld, withheldReason, reason: readOnlyReason } = useResponseAuthority();
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
    // The disabled buttons are the affordance; THIS is the guard, and it asks
    // the authority store at the moment of the request rather than trusting the
    // render that drew the control. No path from this panel may reach
    // POST /api/choke/* while the answer is in flight or after the server has
    // refused — including a confirm panel opened before whoami landed.
    const denied = responseWithheldNow();
    if (denied) {
      setResult({ ok: false, message: denied });
      return;
    }
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

      {/* Stated once, at the top, in the language of PERMISSION — not
          "unavailable" and not "not configured", either of which sends an
          operator to debug an estate that is healthy. The controls below stay
          on the page, visibly inert: hiding them would read as a console that
          does not have a kill-switch at all. */}
      {readOnlyAccount ? (
        <InlineNotice tone="warn" title="Read-only account">
          {readOnlyReason} The thresholds, the enforcement mode and the kill-switch below are shown as readings only.
        </InlineNotice>
      ) : pending ? (
        // Deliberately NOT the read-only sentence. Until whoami answers, this
        // console does not know what the account may do, and telling a
        // responder they are read-only — for the first second of a session, or
        // for the length of a whoami outage — is a false statement of its own.
        // The controls are inert either way; only the reason differs.
        <InlineNotice tone="warn" title="Checking what this account may do">
          {AUTHORITY_PENDING_REASON} The thresholds, the enforcement mode and the kill-switch below stay inert until
          it does.
        </InlineNotice>
      ) : null}

      {/* THE LADDER */}
      <div className="soc-settings-form">
        <div className="soc-settings-ladder">
          {(["throttle_at", "tarpit_at", "quarantine_at", "sever_at"] as const).map((k) => (
            <label key={k}>
              <span>{k.replace("_at", "")}</span>
              <input
                type="number"
                min={1}
                disabled={withheld}
                title={withheldReason ?? undefined}
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
          <input
            value={reason}
            disabled={withheld}
            title={withheldReason ?? undefined}
            onChange={(e) => setReason(e.target.value)}
            placeholder="CAB-1234: tuning for the billing estate"
          />
        </label>
        <div className="soc-settings-actions">
          <button
            type="button"
            className="soc-action-button ok"
            disabled={withheld || !ladderChanged || !!ladderError || reason.trim().length < 3 || busy !== ""}
            title={withheldReason ?? undefined}
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
          disabled={withheld || busy !== "" || (mode !== "enforcing" && mode !== "detect-only")}
          title={withheldReason ?? undefined}
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
          <button type="button" className="soc-ghost-button"
            disabled={withheld || busy !== ""}
            title={withheldReason ?? undefined}
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
              disabled={withheld || busy !== "" || reason.trim().length < 3}
              title={withheldReason ?? undefined}
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
