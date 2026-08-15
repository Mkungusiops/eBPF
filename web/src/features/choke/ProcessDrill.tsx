// Process drill-in slide-over: everything known about one exec_id — lineage,
// kernel events, audited decisions — plus the enforcement ladder that acts on
// it. This is where a sever is usually fired from, so the ladder here is the
// shared one, not a Choke-specific reimplementation.
import { useEffect, useState } from "react";
import { EventReplay } from "../../components/EventReplay";
import { EnforcementLadder } from "../common/EnforcementLadder";
import { ACTION_FOR_RUNG, PROCESS_TERMINAL } from "../common/enforcement";
import { chokeApplied, getCircuits, manualAction, releaseProcess } from "./api";
import type { ChokeAction } from "./types";
import type { DrillState } from "./constants";
import { basename, formatTime, originLabel } from "./utils";
import { ErrorState, LoadingState, StateBadge } from "./components";

export function ProcessDrill({
  drill,
  onClose,
  onForget,
  onAnnotate,
  onCopy,
  onRefresh,
}: {
  drill: DrillState;
  onClose: () => void;
  onForget: (execId: string) => Promise<void>;
  onRefresh: () => void;
  onAnnotate: (execId: string, note: string) => Promise<void>;
  onCopy: (value: string) => void;
}) {
  const [note, setNote] = useState("");
  useEffect(() => {
    if (drill.kind === "ready") setNote(drill.payload.annotation?.note || "");
  }, [drill]);
  if (drill.kind === "closed") return null;
  const entry = drill.kind === "ready" ? drill.payload.entry || { exec_id: drill.execId } : { exec_id: drill.execId };
  const chain = drill.kind === "ready" ? drill.payload.chain || [] : [];
  const decisions = drill.kind === "ready" ? drill.payload.decisions || [] : [];
  const events = drill.kind === "ready" ? drill.payload.events || [] : [];
  const firstProcess = chain[0]?.binary || entry.binary || "process";
  const lastProcess = chain[chain.length - 1]?.binary || entry.binary || "process";
  const fullExecId = entry.exec_id || drill.execId;
  const score = entry.score || 0;
  // Two narratives for two audiences. The technical one is unchanged (analyst
  // language: chain depth, exec_id, kernel-event counts). The plain-English one
  // translates the same facts into what a non-technical stakeholder — an exec,
  // an IR lead briefing leadership — needs: what ran, how dangerous, what we
  // did, and that it is on the audit record. Same data, no jargon.
  const startName = basename(firstProcess);
  const endName = basename(lastProcess);
  const riskWord = score >= 120 ? "high" : score >= 50 ? "elevated" : "low";
  const stateWord = entry.state || "pristine";
  const CONTAINMENT_PHRASE: Record<string, string> = {
    pristine: "It is being watched, but no containment has been applied yet.",
    throttled: "It was slowed down (throttled) so it can do less while analysts review it.",
    tarpit: "It was placed in a tarpit — its actions are deliberately delayed to stall it.",
    quarantined: "It was frozen (quarantined) and can do nothing until an operator releases it.",
    severed: "It was shut down (killed) and blocked from restarting."
  };
  const narrative =
    drill.kind === "ready"
      ? `${chain.length || 1}-process chain starting from ${firstProcess} currently resolves to ${lastProcess}. ${decisions.length} audited decision${decisions.length === 1 ? "" : "s"} and ${events.length} kernel event${events.length === 1 ? "" : "s"} are linked to this exec_id. Aggregate suspicion score: ${score}.`
      : "";
  const plainNarrative =
    drill.kind === "ready"
      ? `A program called ${endName}${startName && startName !== endName ? ` (launched from ${startName})` : ""} drew attention on this host. It tripped ${events.length} kernel-level security signal${events.length === 1 ? "" : "s"}, giving it a ${riskWord} suspicion score of ${score}. ${CONTAINMENT_PHRASE[stateWord] || CONTAINMENT_PHRASE.pristine} Every step it took and every response is recorded in the tamper-evident audit trail (${decisions.length} logged decision${decisions.length === 1 ? "" : "s"}).`
      : "";
  return (
    <aside className="choke-slideover" data-panel="process-drill-in-slide-over" role="dialog" aria-modal="true">
      <header>
        <h2>Process drill-in</h2>
        <button type="button" onClick={onClose}>Close</button>
      </header>
      {drill.kind === "loading" ? <LoadingState label="loading process detail" /> : null}
      {drill.kind === "error" ? <ErrorState title="Drill failed" body={drill.message} /> : null}
      {drill.kind === "ready" ? (
        <div className="choke-drill-body">
          <div className="choke-drill-hero">
            <StateBadge state={entry.state} />
            <strong>{entry.binary || "(unknown process)"}</strong>
            <span>pid {entry.pid || "-"} · uid {entry.uid || "-"} · {formatTime(entry.last_seen || entry.start_time)} · {originLabel(entry) || "local origin"}</span>
            <button type="button" className="choke-execid-full" title="Click to copy full exec_id" onClick={() => onCopy(fullExecId)}>
              <span className="choke-execid-label">exec_id</span>
              <code>{fullExecId || "-"}</code>
            </button>
          </div>
          <div className="choke-drill-stats">
            <div><span>Score</span><strong>{entry.score || 0}</strong></div>
            <div><span>Decisions</span><strong>{decisions.length}</strong></div>
            <div><span>Events</span><strong>{events.length}</strong></div>
            <div><span>Chain depth</span><strong>{chain.length || 1}</strong></div>
          </div>
          <section>
            <h3>Response</h3>
            {/* The same ladder the correlation graph uses. Choke Gateway has
                more detail and no visualisation; the graph has visualisation
                and less detail — but the enforcement control is identical, so
                an operator never has to relearn it when switching surface. */}
            <EnforcementLadder
              target={{
                id: entry.exec_id || drill.execId,
                label: entry.binary || "(unknown process)",
                pid: entry.pid,
                host: originLabel(entry) || undefined
              }}
              state={entry.state || "pristine"}
              policy={PROCESS_TERMINAL}
              apply={async (rung, why) => {
                const execId = entry.exec_id || drill.execId;
                try {
                  if (rung === "pristine") {
                    await releaseProcess(execId, entry.pid, why, entry.agent);
                    return { ok: true, detail: "release accepted" };
                  }
                  const result = await manualAction({
                    exec_id: execId,
                    pid: entry.pid,
                    binary: entry.binary,
                    agent_id: entry.agent,
                    action: ACTION_FOR_RUNG[rung] as ChokeAction,
                    reason: why
                  });
                  // "accepted" is not "applied". The ladder must show the rung
                  // as reached only when an agent reported it actually enforced,
                  // or the operator watches the ladder climb on a process no
                  // host is running.
                  if (result?.approval_required) {
                    return {
                      ok: false,
                      detail: `queued for approval (${result.approval?.id || "pending"}) — a second operator must approve it`,
                    };
                  }
                  if (!chokeApplied(result)) {
                    return { ok: false, detail: result?.detail || result?.status || "no agent applied it" };
                  }
                  return {
                    ok: true,
                    detail: `${ACTION_FOR_RUNG[rung]} applied${result.agent ? ` on ${result.agent}` : ""}`
                  };
                } catch (error) {
                  return { ok: false, detail: (error as Error).message || "action failed" };
                }
              }}
              readState={async () => {
                const list = await getCircuits();
                return list.find((c) => c.exec_id === (entry.exec_id || drill.execId))?.state;
              }}
              onSettled={onRefresh}
            />
            <div className="choke-row-actions wide">
              <button type="button" onClick={() => void onForget(drill.execId)}>forget</button>
              <button type="button" onClick={() => onCopy(entry.exec_id || drill.execId)}>copy exec_id</button>
              {entry.pid ? <button type="button" onClick={() => onCopy(String(entry.pid))}>copy pid</button> : null}
            </div>
          </section>
          <section>
            <h3>Narrative</h3>
            <div className="choke-drill-narrative choke-narrative-plain">
              <span className="choke-narrative-tag">In plain English</span>
              <p>{plainNarrative}</p>
            </div>
            <div className="choke-drill-narrative choke-narrative-tech">
              <span className="choke-narrative-tag">Technical</span>
              <p>{narrative}</p>
            </div>
          </section>
          <section>
            <h3>Operator note</h3>
            <textarea value={note} onChange={(event) => setNote(event.target.value)} />
            <button className="choke-action-button ok" type="button" onClick={() => void onAnnotate(drill.execId, note)}>Save note</button>
          </section>
          <section>
            <h3>Process lineage</h3>
            {chain.length === 0 ? <span className="choke-muted">none</span> : null}
            {chain.map((node) => (
              <div key={node.exec_id || node.pid} className="choke-drill-row">
                <span>{node.pid || "-"}</span>
                <strong>{node.binary || "(unknown)"}</strong>
                <em>{node.score || 0}</em>
              </div>
            ))}
          </section>
          <section>
            <h3>Indicators</h3>
            <div className="choke-drill-row">
              <span>proc</span>
              <strong>{entry.binary || "(unknown)"}</strong>
              <em>{entry.state || "pristine"}</em>
            </div>
            <div className="choke-drill-row choke-drill-row-exec">
              <span>exec</span>
              <strong className="choke-execid-mono">{fullExecId || "-"}</strong>
              <em>{entry.revert_pending ? "revert pending" : "active"}</em>
            </div>
          </section>
          <section>
            <h3>Decisions</h3>
            {decisions.length === 0 ? <span className="choke-muted">none</span> : null}
            {decisions.slice(0, 20).map((decision) => (
              <div key={decision.id || `${decision.timestamp}-${decision.action}`} className="choke-drill-row">
                <span>{formatTime(decision.timestamp)}</span>
                <StateBadge state={decision.to_state || decision.action} />
                <strong>{decision.reason || decision.action}</strong>
              </div>
            ))}
          </section>
          <section>
            <h3>Event timeline</h3>
            <EventReplay
              events={events.map((event) => ({
                id: String(event.id || `${event.timestamp}-${event.event_type}`),
                time: event.timestamp ?? "",
                kind: event.event_type || "-",
                detail: event.policy_name || event.args || ""
              }))}
              emptyLabel="No process events for this exec."
            />
          </section>
        </div>
      ) : null}
    </aside>
  );
}
