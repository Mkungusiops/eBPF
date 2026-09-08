import { useCallback, useEffect, useRef, useState } from "react";

import {
  ACTION_FOR_RUNG,
  LABEL_FOR_RUNG,
  LADDER,
  REASON_REQUIRED,
  RUNG_FOR_ACTION,
  ladderIndex,
  type EnforcementResult,
  type EnforcementTarget,
  type Rung,
  type TerminalPolicy
} from "./enforcement";
import "./enforcement.css";

function cx(...classes: Array<string | false | null | undefined>): string {
  return classes.filter(Boolean).join(" ");
}

/**
 * ONE definition of a surface's reason policy: which rungs it refuses without a
 * typed reason, AND the words it uses to say so.
 *
 * The gate and the copy are in the same object because they drifted apart once
 * the moment they were not. The device plane refuses every jail rung without a
 * reason — throttle and tarpit included — while this component's built-in copy
 * said "required to quarantine or sever", so the device surface told an
 * operator throttle needed no reason and then refused their throttle for want
 * of one (see features/devices/utils.ts, deviceRungNeedsReason). A caller
 * passing a stricter `rungs` set without stricter wording would reproduce that
 * exactly, so the wording travels with it.
 */
export interface ReasonRule {
  /** Rungs this surface will not apply without a reason. */
  rungs: ReadonlySet<Rung>;
  /** Placeholder for the reason box — where the rule is stated to the operator. */
  placeholder: string;
  /** Title on a rung held closed only because the reason box is empty. */
  tooltip: (rung: Rung) => string;
}

/**
 * The process plane's rule, and the fallback for any surface that does not
 * state one: quarantine and sever only, which is what both servers enforce for
 * a process choke.
 */
export const DEFAULT_REASON_RULE: ReasonRule = {
  rungs: REASON_REQUIRED,
  placeholder: "Reason (required to quarantine or sever)",
  tooltip: (rung) => `A reason is required to ${ACTION_FOR_RUNG[rung]}`
};

export interface EnforcementLadderProps {
  target: EnforcementTarget;
  /** The target's rung right now, from the host page's live data. */
  state: string;
  /** Apply an action. Transport differs per surface (process vs device). */
  apply: (rung: Rung, reason: string) => Promise<EnforcementResult>;
  /**
   * Re-read this target's rung. Used to confirm the action actually landed
   * rather than trusting the accepted-response. Return undefined if unknown.
   */
  readState: () => Promise<string | undefined>;
  policy: TerminalPolicy;
  /** Called after an action settles so the host can refresh its own view. */
  onSettled?: () => void;
  /**
   * Which rungs need a reason here, and the words for it. Defaults to the
   * process plane's rule; the device plane passes a stricter one.
   */
  reasonRule?: ReasonRule;
  /** Poll budget for confirmation. Multi-tenant learns state from a 5s heartbeat. */
  confirmAttempts?: number;
  confirmIntervalMs?: number;
}

/**
 * The ladder, drawn, plus the actions that move a target along it.
 *
 * Two rules carry the weight here, and both came out of watching the real thing
 * misreport:
 *
 *  1. A 2xx means the command was ACCEPTED, not that the target moved. The
 *     control plane only learns the new rung from the agent's heartbeat, so the
 *     component says "dispatched" and then polls until the rung actually
 *     changes before it claims success.
 *  2. The top rung may or may not be terminal depending on the target kind —
 *     see TerminalPolicy.
 */
export function EnforcementLadder({
  target,
  state,
  apply,
  readState,
  policy,
  onSettled,
  reasonRule = DEFAULT_REASON_RULE,
  confirmAttempts = 8,
  confirmIntervalMs = 2000
}: EnforcementLadderProps) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<Rung | null>(null);
  const [result, setResult] = useState<EnforcementResult | null>(null);
  const [confirmTop, setConfirmTop] = useState(false);

  // Generation counter for the confirmation loop below. Bumped whenever the
  // target changes or the component unmounts, so an in-flight loop can tell it
  // has been superseded and stop before writing a stale result.
  const runIdRef = useRef(0);
  useEffect(() => {
    return () => {
      runIdRef.current += 1;
    };
  }, []);

  // A reason typed against one target must never be submitted against another.
  useEffect(() => {
    runIdRef.current += 1; // abandon any confirmation still polling for the old target
    setReason("");
    setResult(null);
    setConfirmTop(false);
  }, [target.id]);

  const current = ladderIndex(state);
  const topRung = LADDER[LADDER.length - 1];
  const isDead = policy.terminal && state === topRung;

  const run = useCallback(
    async (rung: Rung) => {
      // This run owns the ladder until something bumps the counter. The loop
      // below polls for up to confirmAttempts * confirmIntervalMs (16s by
      // default) with no way to cancel: an operator who severed process A and
      // then clicked process B during that window saw "sever confirmed" render
      // against B. Resetting the UI on target change was not enough — the loop
      // kept running and called setResult again.
      const myRun = runIdRef.current + 1;
      runIdRef.current = myRun;
      const superseded = () => runIdRef.current !== myRun;

      setBusy(rung);
      setResult(null);
      const outcome = await apply(rung, reason.trim());
      if (superseded()) return;
      setBusy(null);
      setConfirmTop(false);
      if (!outcome.ok) {
        setResult(outcome);
        onSettled?.();
        return;
      }
      setReason("");

      const action = ACTION_FOR_RUNG[rung];
      const isRelease = rung === LADDER[0];
      setResult({ ok: true, detail: `${action} dispatched — awaiting confirmation…` });
      for (let attempt = 0; attempt < confirmAttempts; attempt++) {
        await new Promise((resolve) => window.setTimeout(resolve, confirmIntervalMs));
        if (superseded()) return;
        const now = await readState();
        if (superseded()) return;
        onSettled?.();
        if (now === rung) {
          setResult({ ok: true, detail: `${action} confirmed — now ${now}` });
          return;
        }
        // A released process stops being a circuit at all on the control plane:
        // the agent drops it from its tracked set rather than reporting it as
        // pristine. Absent therefore means released, and waiting for a
        // "pristine" that will never arrive would fail a successful action.
        if (isRelease && now === undefined) {
          setResult({ ok: true, detail: "release confirmed — no longer choked" });
          return;
        }
      }
      setResult({
        ok: false,
        detail: `${action} was accepted but the agent has not reported the new state yet`
      });
    },
    [apply, confirmAttempts, confirmIntervalMs, onSettled, readState, reason]
  );

  return (
    <div className="enf-ladder" data-panel="enforcement-ladder">
      <span className="enf-ladder-label">Enforcement</span>

      {/* Drawing the rungs makes the state machine legible without docs: what
          has been passed, where the target sits, and that the top rung is a
          different KIND of thing rather than just the next step along. */}
      <ol className="enf-ladder-rungs">
        {LADDER.map((rung, index) => (
          <li
            key={rung}
            className={cx(
              "enf-ladder-rung",
              index === current && "is-current",
              index < current && "is-passed",
              rung === topRung && "is-terminal"
            )}
          >
            {rung}
          </li>
        ))}
      </ol>

      <input
        className="enf-ladder-reason"
        value={reason}
        onChange={(event) => setReason(event.target.value)}
        placeholder={reasonRule.placeholder}
        aria-label="Reason for this enforcement action"
      />

      <div className="enf-ladder-actions">
        {LADDER.map((rung, index) => {
          const isRelease = index === 0;
          const isTop = rung === topRung;
          // Monotonic: climb, or release to pristine. A rung at or below the
          // current one is disabled — and the title says WHY, rather than
          // leaving a dead button unexplained.
          const backwards = !isRelease && index <= current;
          const isCurrent = index === current;
          const needsReason = reasonRule.rungs.has(rung) && !reason.trim();
          const disabled = Boolean(busy) || isCurrent || backwards || needsReason || isDead;
          const why = isDead
            ? policy.terminalNote || "This target is in a terminal state"
            : isCurrent
              ? `Already ${rung}`
              : backwards
                ? "The ladder only climbs — use pristine to release"
                : needsReason
                  ? reasonRule.tooltip(rung)
                  : isTop && policy.terminal
                    ? "SIGKILL — cannot be undone"
                    : `Move to ${rung}`;
          return (
            <button
              key={rung}
              type="button"
              className={cx(
                "enf-ladder-btn",
                isRelease && "is-release",
                isTop && "is-terminal",
                busy === rung && "is-busy"
              )}
              disabled={disabled}
              title={why}
              onClick={() => {
                // The top rung is the most consequential move on either target
                // kind, so it always takes a second press.
                if (isTop && !confirmTop) {
                  setConfirmTop(true);
                  return;
                }
                void run(rung);
              }}
            >
              {busy === rung ? "…" : isTop && confirmTop ? "Confirm" : LABEL_FOR_RUNG[rung]}
            </button>
          );
        })}
      </div>

      {isDead && policy.terminalNote ? (
        <p className="enf-ladder-warn">{policy.terminalNote}</p>
      ) : null}

      {confirmTop ? (
        <p className="enf-ladder-warn">
          Sever {target.label}
          {target.pid ? ` (pid ${target.pid})` : ""}
          {target.host ? ` on ${target.host}` : ""} {policy.confirmNote}
        </p>
      ) : null}

      {result ? (
        <p className={cx("enf-ladder-result", result.ok ? "is-ok" : "is-bad")}>
          {result.ok ? "✓ " : "✗ "}
          {result.detail}
        </p>
      ) : null}
    </div>
  );
}

export { RUNG_FOR_ACTION };
