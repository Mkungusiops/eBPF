// The four-card brief that sits above the correlation canvas.
//
// A force graph shows structure but not scale, so an operator opening it cold
// cannot tell whether they are looking at a quiet estate or an incident. These
// cards answer that in one line each — how much of the signal is critical, how
// dense the fabric is, how much of it a policy explains, and where it is coming
// from — before any node is clicked.
import { useMemo } from "react";
import { FileText, GitBranch, Server, ShieldAlert } from "lucide-react";
import { countSeverities } from "./analytics";
import { cx } from "./components";
import { shortGraphLabel } from "./format";
import { extractFilePath, isLoopbackPeer, peerFromEvent } from "./telemetry";
import type { SocAlert, SocEvent } from "./types";

export function GraphBrief({
  alerts,
  events,
  topProcesses,
  meta,
  live
}: {
  alerts: SocAlert[];
  events: SocEvent[];
  topProcesses: Array<{ process: string; score: number; count: number; execId?: string }>;
  meta: { processes: number; edges: number };
  live: boolean;
}) {
  const graphCounts = useMemo(() => countSeverities(alerts), [alerts]);
  const policyCount = useMemo(() => new Set(events.map((event) => event.policyName).filter(Boolean)).size, [events]);
  const policyEventCount = useMemo(() => events.filter((event) => event.policyName).length, [events]);
  // Count indicators the SAME way the canvas draws them (graphModel.ts).
  //
  // This read only `event.path`, a field the single-tenant engine has never
  // had — store.Event is {timestamp, event_type, pid, parent_pid, exec_id,
  // binary, args, uid, policy_name} and nothing else. So the card printed
  // "0 indicators observed" on every window, forever, while the graph two
  // inches away drew /etc/passwd, /etc/shadow and /etc/sudoers nodes pulled
  // out of `args` by the very same derivation. Measured live 2026-08-22 on a
  // 30m window: 0 reported against 6 on the canvas.
  //
  // The loopback filter is the second half of "the same way the canvas draws
  // them": graphModel puts every peer through `!isLoopbackPeer(p)` before it
  // adds a node, and this did not, so a host's own health checks inflated the
  // count. Measured on the engine's ten-day store, 397 of 559 IPv4-carrying
  // events are `curl 127.0.0.1:8090` — hundreds of "indicators observed"
  // claimed two inches from a canvas correctly drawing none of them.
  const indicatorCount = useMemo(
    () =>
      new Set(
        events
          .map((event) => {
            const file = event.path || (event.policyName ? extractFilePath(event.args) : undefined);
            if (file) return file;
            const peer = peerFromEvent(event);
            return peer && !isLoopbackPeer(peer) ? peer : undefined;
          })
          .filter(Boolean)
      ).size,
    [events]
  );
  const criticalPathCount = graphCounts.critical + graphCounts.high;
  const criticalShare = alerts.length ? Math.round((criticalPathCount / alerts.length) * 100) : 0;
  const fabricDensity = meta.processes ? Math.min(100, Math.round((meta.edges / Math.max(1, meta.processes * 1.6)) * 100)) : 0;
  const policyCoverage = events.length ? Math.round((policyEventCount / events.length) * 100) : 0;
  const dominant = topProcesses[0];
  const dominantProcess = dominant?.process || "No dominant process";
  const dominantDisplay = dominant ? shortGraphLabel(dominant.process, 18) : "No source";
  const graphBriefCards = [
    {
      key: "critical",
      tone: "tone-critical",
      icon: ShieldAlert,
      label: "Critical paths",
      badge: criticalPathCount ? "Escalated" : "Clear",
      value: String(criticalPathCount),
      title: String(criticalPathCount),
      meta: "high-confidence chains",
      detail: `${graphCounts.critical} critical · ${graphCounts.high} high`,
      fill: criticalShare
    },
    {
      key: "fabric",
      tone: "tone-accent",
      icon: GitBranch,
      label: "Signal fabric",
      badge: live ? "Live" : "Paused",
      value: `${meta.processes}/${meta.edges}`,
      title: `${meta.processes} processes / ${meta.edges} edges`,
      meta: "processes / edges",
      detail: `${indicatorCount} indicators observed`,
      fill: fabricDensity
    },
    {
      key: "policies",
      tone: "tone-medium",
      icon: FileText,
      label: "Policies",
      badge: policyCount ? "Mapped" : "Idle",
      value: String(policyCount),
      title: String(policyCount),
      meta: "mapped controls",
      detail: `${policyEventCount} policy events`,
      fill: policyCoverage
    },
    {
      key: "origin",
      tone: "tone-good",
      icon: Server,
      label: "Primary origin",
      badge: dominant ? "Top source" : "Waiting",
      value: dominantDisplay,
      title: dominantProcess,
      meta: dominant ? `${dominant.count} alert${dominant.count === 1 ? "" : "s"} · score ${Math.round(dominant.score)}` : "no source process yet",
      detail: `${indicatorCount} observed indicators`,
      fill: dominant ? Math.max(8, Math.min(100, Math.round(dominant.score))) : 0
    }
  ];

  return (
    <div className="soc-graph-brief">
      {graphBriefCards.map((card) => {
        const Icon = card.icon;
        return (
          <div key={card.key} className={cx("soc-graph-brief-card", card.tone)}>
            <div className="soc-graph-card-head">
              <span className="soc-graph-card-icon"><Icon size={14} aria-hidden="true" /></span>
              <span>{card.label}</span>
              <em className="soc-graph-card-badge">{card.badge}</em>
            </div>
            <strong title={card.title}>{card.value}</strong>
            <div className="soc-graph-card-meter" aria-hidden="true">
              <span style={{ width: `${card.fill}%` }} />
            </div>
            <div className="soc-graph-card-detail">
              <span>{card.meta}</span>
              <em>{card.detail}</em>
            </div>
          </div>
        );
      })}
    </div>
  );
}
