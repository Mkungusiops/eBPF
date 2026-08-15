// The alert drill-down that fills the slide-over: what fired, in two registers
// (plain English for a lead briefing leadership, technical for the responder),
// the choke response form, investigator notes, lineage, indicators and the
// event replay.
import { useState } from "react";
import { EventReplay } from "../../components/EventReplay";
import { jailSocAlert } from "./api";
import { EmptyState, InlineNotice, MetricTile, SeverityBadge, StatusPill } from "./components";
import { baseName, formatTime } from "./format";
import { IocList } from "./rows";
import { extractIocs } from "./telemetry";
import type { AckState } from "./dashboard";
import type { SocAlert, SocProcessDetail } from "./types";

const SEVERITY_WORD: Record<string, string> = {
  critical: "critical",
  high: "high",
  medium: "medium",
  low: "low",
  info: "informational"
};

export function DrillPanel({
  alert,
  ack,
  note,
  processDetail,
  processDetailError,
  onAck,
  onNote,
  onActionComplete
}: {
  alert: SocAlert;
  ack: AckState;
  note: string;
  processDetail: SocProcessDetail | null;
  processDetailError: string;
  onAck: (value: AckState) => void;
  onNote: (note: string) => void;
  onActionComplete: () => void;
}) {
  const [action, setAction] = useState<"throttle" | "tarpit" | "quarantine" | "sever">("quarantine");
  const [reason, setReason] = useState("");
  const [descendants, setDescendants] = useState(true);
  const [revertAfterSeconds, setRevertAfterSeconds] = useState(0);
  const [busy, setBusy] = useState(false);
  const [result, setResult] = useState<{ tone: "ok" | "warn"; message: string } | null>(null);
  const iocs = extractIocs([alert], processDetail?.events || []);
  const chain = processDetail?.chain || [];
  const events = processDetail?.events || [];
  const firstProcess = chain[0]?.binary || alert.process || "process";
  const lastProcess = chain[chain.length - 1]?.binary || alert.process || "process";
  const eventCount = events.length || "multiple";
  const narrative = `${chain.length || 1}-process chain starting from ${firstProcess} descended into ${lastProcess} and triggered ${eventCount} kernel event${events.length === 1 ? "" : "s"}. ${
    alert.mitreId ? `Mapped to MITRE ${alert.mitreId}${alert.tactic ? ` ${alert.tactic}` : ""}. ` : ""
  }Aggregate suspicion score: ${alert.score}.`;
  // Plain-English companion — same facts, no jargon, for an analyst scanning
  // fast or a lead briefing leadership: what fired, how bad, what it means,
  // what to do. The technical line above stays for the responder.
  const sevWord = SEVERITY_WORD[alert.severity] || String(alert.severity);
  const plainName = baseName(lastProcess);
  const startName = baseName(firstProcess);
  const plainRisk = alert.score >= 120 ? "high" : alert.score >= 50 ? "elevated" : "low";
  const behaviour = alert.tactic || (alert.mitreId ? `technique ${alert.mitreId}` : "");
  const isSevere = alert.severity === "critical" || alert.severity === "high";
  const plainNarrative = `A ${sevWord} alert fired: ${plainName}${
    startName && startName !== plainName ? `, launched from ${startName},` : ""
  } behaved in a way the sensor scored as ${plainRisk} risk (${alert.score}).${
    behaviour ? ` It matches the attacker behaviour “${behaviour}”${alert.tactic && alert.mitreId ? ` (MITRE ${alert.mitreId})` : ""}.` : ""
  }${events.length ? ` ${events.length} kernel event${events.length === 1 ? "" : "s"} are tied to it.` : ""} ${
    isSevere ? "Contain the process while you investigate." : "Review before acting."
  }`;
  const canTarget = Boolean(alert.pid || alert.process);
  const canSubmit = canTarget && reason.trim().length > 2 && !busy;

  async function submitChokeAction() {
    if (!canSubmit) return;
    setBusy(true);
    setResult(null);
    try {
      await jailSocAlert({
        alert,
        action,
        reason: reason.trim(),
        descendants,
        revertAfterSeconds
      });
      setResult({ tone: "ok", message: `${action} requested for ${alert.process || alert.pid || alert.id}.` });
      onActionComplete();
    } catch (error) {
      setResult({
        tone: "warn",
        message: error instanceof Error ? error.message : String(error)
      });
    } finally {
      setBusy(false);
    }
  }

  return (
    <div className="soc-drill">
      <header className="soc-drill-hero">
        <SeverityBadge severity={alert.severity} />
        <strong>{alert.title}</strong>
        <span>
          {formatTime(alert.timestamp)} · {alert.policyName || "policy"}{alert.mitreId ? ` · ${alert.mitreId}` : ""}
        </span>
      </header>
      <div className="soc-drill-grid">
        <MetricTile label="Score" value={alert.score} tone={alert.severity} />
        <MetricTile label="Events" value={events.length || "-"} />
        <MetricTile label="Chain depth" value={chain.length || "-"} />
      </div>
      <div className="soc-drill-actions">
        <button type="button" onClick={() => onAck("ack")}>Acknowledge</button>
        <button type="button" onClick={() => onAck("resolved")}>Resolve</button>
        <StatusPill label={ack} tone={ack === "resolved" ? "ok" : ack === "ack" ? "info" : "warn"} />
      </div>
      {!canTarget ? <InlineNotice tone="warn" title="No process target">This alert has no pid or process name for /api/choke/jail.</InlineNotice> : null}
      {result ? <InlineNotice tone={result.tone} title="Choke action result">{result.message}</InlineNotice> : null}
      {processDetailError ? <InlineNotice tone="warn" title="Process detail unavailable">{processDetailError}</InlineNotice> : null}
      <section className="soc-drill-section">
        <h3>Narrative</h3>
        <div className="soc-narrative soc-narrative-plain">
          <span className="soc-narrative-tag">In plain English</span>
          <p>{plainNarrative}</p>
        </div>
        <div className="soc-narrative soc-narrative-tech">
          <span className="soc-narrative-tag">Technical</span>
          <p>{narrative}</p>
        </div>
      </section>
      <section className="soc-drill-section">
        <h3>Choke response</h3>
        <div className="soc-choke-action-grid">
          <label>
            <span>Action</span>
            <select value={action} onChange={(event) => setAction(event.target.value as typeof action)}>
              <option value="throttle">throttle</option>
              <option value="tarpit">tarpit</option>
              <option value="quarantine">quarantine</option>
              <option value="sever">sever</option>
            </select>
          </label>
          <label>
            <span>Revert after</span>
            <select value={revertAfterSeconds} onChange={(event) => setRevertAfterSeconds(Number(event.target.value))}>
              <option value={0}>manual</option>
              <option value={300}>5 minutes</option>
              <option value={900}>15 minutes</option>
              <option value={3600}>1 hour</option>
            </select>
          </label>
          <label className="soc-checkbox-row">
            <input type="checkbox" checked={descendants} onChange={(event) => setDescendants(event.target.checked)} />
            <span>Include descendants</span>
          </label>
          <label className="soc-choke-reason">
            <span>Audit reason</span>
            <input value={reason} onChange={(event) => setReason(event.target.value)} placeholder="required for /api/choke/jail" />
          </label>
          <button type="button" className="soc-danger-button" disabled={!canSubmit} onClick={() => void submitChokeAction()}>
            {busy ? "Sending" : `Send ${action}`}
          </button>
        </div>
      </section>
      <label className="soc-notes">
        <span>Investigator notes</span>
        <textarea value={note} onChange={(event) => onNote(event.target.value)} placeholder="Saved locally as soc.alertNotes" />
      </label>
      <div className="soc-drill-section">
        <h3>Process lineage</h3>
        {chain.length ? (
          chain.map((node, index) => (
            <div key={`${node.execId || node.pid || index}`} className="soc-lineage-row">
              <span>{index + 1}</span>
              <code>{node.binary || node.execId || "process"}</code>
              <em>{node.pid ? `pid ${node.pid}` : ""}</em>
            </div>
          ))
        ) : (
          <EmptyState title="No lineage loaded" detail={alert.execId ? "Waiting on /api/process/{exec_id}." : "This alert has no exec_id."} />
        )}
      </div>
      <div className="soc-drill-section">
        <h3>Indicators</h3>
        <IocList files={iocs.files} peers={iocs.peers} />
      </div>
      <div className="soc-drill-section">
        <h3>Event timeline</h3>
        <EventReplay
          events={events.map((event) => ({
            id: event.id,
            time: event.timestamp,
            kind: event.eventType,
            detail:
              event.path ||
              event.args ||
              (event.destIp ? `${event.destIp}${event.destPort ? `:${event.destPort}` : ""}` : "")
          }))}
        />
      </div>
    </div>
  );
}
