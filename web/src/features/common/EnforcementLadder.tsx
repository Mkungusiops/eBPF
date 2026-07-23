import { useCallback, useEffect, useState } from "react";

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
  confirmAttempts = 8,
  confirmIntervalMs = 2000
}: EnforcementLadderProps) {
  const [reason, setReason] = useState("");
  const [busy, setBusy] = useState<Rung | null>(null);
  const [result, setResult] = useState<EnforcementResult | null>(null);
  const [confirmTop, setConfirmTop] = useState(false);

  // A reason typed against one target must never be submitted against another.
  useEffect(() => {
    setReason("");
    setResult(null);
    setConfirmTop(false);
  }, [target.id]);

  const current = ladderIndex(state);
  const topRung = LADDER[LADDER.length - 1];
  const isDead = policy.terminal && state === topRung;

  const run = useCallback(
    async (rung: Rung) => {
      setBusy(rung);
      setResult(null);
      const outcome = await apply(rung, reason.trim());
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
        const now = await readState();
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
        placeholder="Reason (required to quarantine or sever)"
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
          const needsReason = REASON_REQUIRED.has(rung) && !reason.trim();
          const disabled = Boolean(busy) || isCurrent || backwards || needsReason || isDead;
          const why = isDead
            ? policy.terminalNote || "This target is in a terminal state"
            : isCurrent
              ? `Already ${rung}`
              : backwards
                ? "The ladder only climbs — use pristine to release"
                : needsReason
                  ? `A reason is required to ${ACTION_FOR_RUNG[rung]}`
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
