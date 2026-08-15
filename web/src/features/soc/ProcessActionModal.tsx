import { useEffect } from "react";
import { X } from "lucide-react";
import { EnforcementLadder } from "../common/EnforcementLadder";
import { PROCESS_TERMINAL, type Rung } from "../common/enforcement";
import { baseName, formatTime, shortGraphLabel } from "./format";
import type { ProcessInstance } from "./graphModel";

/**
 * The process action surface, as a modal.
 *
 * It used to live in the 280px selection rail, where the identity fields and a
 * five-rung ladder had no room and clipped on the right edge. The flow is now
 * click node → the rail lists the processes behind it → click one → this modal.
 * A modal gives the ladder room to breathe and puts the identity of the target
 * (binary, pid, host, exec_id) squarely in front of the operator before they
 * act — which for an irreversible action is exactly where it belongs.
 *
 * The rail keeps showing the process list underneath, so closing the modal
 * returns to the list with the rung the operator just set already reflected.
 */
export function ProcessActionModal({
  drill,
  state,
  nodeLabel,
  apply,
  readState,
  onClose
}: {
  drill: ProcessInstance;
  state: string;
  nodeLabel: string;
  apply: (rung: Rung, reason: string) => Promise<{ ok: boolean; detail: string }>;
  readState: () => Promise<string | undefined>;
  onClose: () => void;
}) {
  // Esc closes — but ONLY this modal. The graph itself is also a modal that
  // closes on Escape via a window listener, so without stopping the event here
  // one Escape would close both, dumping the operator out of the graph. Running
  // in the capture phase and halting propagation means this modal consumes the
  // Escape before the graph's bubble-phase listener ever sees it.
  useEffect(() => {
    const onKey = (event: globalThis.KeyboardEvent) => {
      if (event.key !== "Escape") return;
      event.stopImmediatePropagation();
      onClose();
    };
    window.addEventListener("keydown", onKey, { capture: true });
    return () => window.removeEventListener("keydown", onKey, { capture: true });
  }, [onClose]);

  const cls = drill.score >= 25 ? "attack" : drill.score >= 10 ? "threat" : "baseline";

  // Two narratives, tuned to the graph's lighter model and score scale (attack
  // ≥25, threat ≥10) and kept compact to fit the modal: a plain-English read
  // and a dense technical line. Same dual-narrative language as the Choke drill
  // and the alert triage panel, so it reads identically everywhere.
  const gRisk = drill.score >= 25 ? "high" : drill.score >= 10 ? "elevated" : "low";
  const gPolicies = drill.policies.length ? drill.policies.join(", ") : "";
  const gPlain = `${baseName(drill.binary)}${drill.agent ? ` on ${drill.agent}` : ""} drew ${gRisk} attention (score ${Math.round(
    drill.score
  )}).${
    drill.policies.length
      ? ` It tripped ${drill.policies.length} detection${drill.policies.length === 1 ? "" : "s"}: ${gPolicies}.`
      : ""
  } ${drill.score >= 25 ? "Consider containing it with the ladder on the right." : "Watch it; no action needed yet."}`;
  const gTech = `${drill.binary}${drill.pid ? ` · pid ${drill.pid}` : ""} · score ${Math.round(drill.score)}${
    drill.policies.length ? ` · policies: ${gPolicies}` : ""
  }.`;

  return (
    <div
      className="soc-proc-modal-back is-open"
      data-panel="process-action-modal"
      onMouseDown={(event) => {
        if (event.target === event.currentTarget) onClose();
      }}
    >
      <div className="soc-proc-modal" role="dialog" aria-modal="true" aria-label={`Enforce on ${drill.binary}`}>
        <header className="soc-proc-modal-head">
          <div className="soc-proc-modal-title">
            <span className="soc-eyebrow">Process · via {shortGraphLabel(nodeLabel, 28)}</span>
            <h2 className={`cls-${cls}`}>{drill.binary}</h2>
          </div>
          <button type="button" className="soc-close-button" onClick={onClose} aria-label="Close">
            <X size={16} aria-hidden="true" />
          </button>
        </header>

        <div className="soc-proc-modal-body">
          {/* Left: who the target is. Identity in full, so nothing is guessed. */}
          <section className="soc-proc-modal-identity">
            <span className="soc-stat-label">Identity</span>
            <dl>
              <div>
                <dt>pid</dt>
                <dd>{drill.pid ?? "—"}</dd>
              </div>
              <div>
                <dt>score</dt>
                <dd className={`cls-${cls}`}>{Math.round(drill.score)}</dd>
              </div>
              {/* Host is multi-tenant only — in single-tenant the engine IS the
                  host, so there is nothing to disambiguate. Long identifiers
                  (host, exec_id) are shown IN FULL on their own line rather than
                  truncated: an operator triaging or copying a target needs the
                  whole value at a glance, not a "…" they have to hover to read. */}
              {drill.agent ? (
                <div className="is-full">
                  <dt>host</dt>
                  <dd>{drill.agent}</dd>
                </div>
              ) : null}
              <div className="is-full">
                <dt>exec_id</dt>
                <dd>{drill.execId}</dd>
              </div>
              <div>
                <dt>last seen</dt>
                <dd>{formatTime(drill.lastSeen)}</dd>
              </div>
            </dl>

            {drill.policies.length ? (
              <div className="soc-proc-modal-policies">
                <span className="soc-stat-label">Policies fired</span>
                {drill.policies.map((policy) => (
                  <span key={policy} className="soc-graph-neighbour node-policy">
                    <i />
                    {policy}
                  </span>
                ))}
              </div>
            ) : null}
          </section>

          {/* Right: the same shared ladder as Choke Gateway and Devices, now
              with the width it needs. */}
          <section className="soc-proc-modal-action">
            <EnforcementLadder
              target={{
                id: drill.execId,
                label: drill.binary,
                pid: drill.pid,
                host: drill.agent ? shortGraphLabel(drill.agent, 18) : undefined
              }}
              state={state}
              apply={apply}
              readState={readState}
              policy={PROCESS_TERMINAL}
            />
          </section>
        </div>

        {/* Two narratives, compact for the graph modal. */}
        <section className="soc-proc-modal-narrative">
          <div className="soc-narrative soc-narrative-plain">
            <span className="soc-narrative-tag">In plain English</span>
            <p>{gPlain}</p>
          </div>
          <div className="soc-narrative soc-narrative-tech">
            <span className="soc-narrative-tag">Technical</span>
            <p>{gTech}</p>
          </div>
        </section>
      </div>
    </div>
  );
}
