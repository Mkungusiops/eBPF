// The correlation graph's data model: what a node is, what an edge means, and
// how a window of alerts + events becomes the graph the D3 bridge renders.
//
// Deliberately free of both React and D3 so the shape of the graph can be
// reasoned about (and tested) without a simulation running — the imperative
// renderer lives in SocRoute.tsx alongside the surface that owns the <svg>.
import type { Selection as D3Selection, SimulationLinkDatum, SimulationNodeDatum } from "d3";
import { shortGraphLabel } from "./format";
import { processChainFromAlert } from "./analytics";
import { extractFilePath, isDevicePeer, peerFromEvent } from "./telemetry";
import type { SocAlert, SocEvent } from "./types";

export type GraphClass = "attack" | "threat" | "baseline";

// One real process behind a graph node. A process node is keyed by BINARY, so
// "/usr/bin/nc" may stand for many live processes; enforcement needs the
// specific exec_id/pid, which is why these are carried rather than aggregated
// away. Only process nodes populate this — the panel resolves a policy/file/peer
// node to processes by walking its edges, so there is one source of truth.
//
// The ladder itself (rungs, ordering, the "only climbs" rule, the copy) lives in
// features/common/enforcement so the graph, Choke Gateway and Devices cannot
// drift apart.
export interface ProcessInstance {
  execId: string;
  pid?: number;
  binary: string;
  score: number;
  agent?: string;
  policies: string[];
  lastSeen: string;
}

export interface GraphNode extends SimulationNodeDatum {
  id: string;
  label: string;
  fullLabel?: string;
  group: "process" | "policy" | "peer" | "file" | "device";
  weight: number;
  processes?: ProcessInstance[];
  // Max alert score touching this process — drives node colour (attack/threat/
  // baseline). Only meaningful for process nodes; context nodes inherit neutral.
  score?: number;
  cls?: GraphClass;
}

export function classifyGraphScore(score: number): GraphClass {
  if (score >= 25) return "attack";
  if (score >= 10) return "threat";
  return "baseline";
}

export interface GraphLink extends SimulationLinkDatum<GraphNode> {
  source: string | GraphNode;
  target: string | GraphNode;
  weight: number;
}

export interface CorrelationGraphData {
  nodes: GraphNode[];
  links: GraphLink[];
}

export interface GraphControls {
  zoomIn: () => void;
  zoomOut: () => void;
  reset: () => void;
  fit: () => void;
}

export type GraphLayout = "force" | "radial" | "decay";

export type GraphLinkSel = D3Selection<SVGLineElement, GraphLink, SVGGElement, unknown>;
export type GraphNodeSel = D3Selection<SVGGElement, GraphNode, SVGGElement, unknown>;

export function graphLinkKey(link: GraphLink): string {
  const source = typeof link.source === "object" ? link.source.id : link.source;
  const target = typeof link.target === "object" ? link.target.id : link.target;
  return `${source}->${target}`;
}

// Drop process nodes whose classification is hidden, plus any context node
// (policy/file/peer) that no longer attaches to a visible process.
export function filterGraph(data: CorrelationGraphData, show: Set<GraphClass>): CorrelationGraphData {
  if (show.size >= 3) return data;
  const linkEnds = (link: GraphLink) => {
    const s = typeof link.source === "object" ? link.source.id : String(link.source);
    const t = typeof link.target === "object" ? link.target.id : String(link.target);
    return [s, t] as const;
  };
  const keep = new Set<string>();
  for (const node of data.nodes) {
    if (node.group === "process" && node.cls && show.has(node.cls)) keep.add(node.id);
  }
  for (const link of data.links) {
    const [s, t] = linkEnds(link);
    if (keep.has(s)) keep.add(t);
    if (keep.has(t)) keep.add(s);
  }
  return {
    nodes: data.nodes.filter((node) => keep.has(node.id)),
    links: data.links.filter((link) => {
      const [s, t] = linkEnds(link);
      return keep.has(s) && keep.has(t);
    })
  };
}

export function graphMeta(data: CorrelationGraphData) {
  return { processes: data.nodes.filter((node) => node.group === "process").length, edges: data.links.length };
}

export const GRAPH_CLASSES: Array<{ key: GraphClass; label: string }> = [
  { key: "attack", label: "ATTACK" },
  { key: "threat", label: "THREAT" },
  { key: "baseline", label: "BASELINE" }
];

export function buildCorrelationGraph(alerts: SocAlert[], events: SocEvent[]): CorrelationGraphData {
  // On this engine alerts carry only an opaque exec_id (the command lives in the
  // title chain) while the binary, policy, and accessed-file context live on the
  // correlated events. Resolve a readable binary label per exec_id from events,
  // then key every process node by that label so alert + event signal merges into
  // one node instead of drifting into disconnected base64 dots.
  const binaryByExec = new Map<string, string>();
  for (const event of events) {
    if (!event.execId || !event.process) continue;
    const current = binaryByExec.get(event.execId);
    // Prefer an absolute binary path, but a bare comm name still beats a base64 exec_id.
    if (!current || (!current.startsWith("/") && event.process.startsWith("/"))) {
      binaryByExec.set(event.execId, event.process);
    }
  }
  const labelFor = (execId: string | undefined, fallback: string | undefined) =>
    (execId ? binaryByExec.get(execId) : undefined) || fallback || execId || "process";

  type ProcAgg = {
    key: string;
    label: string;
    weight: number;
    score: number;
    policies: Set<string>;
    files: Set<string>;
    peers: Set<string>;
    // exec_id -> the live process behind this binary node
    instances: Map<string, ProcessInstance>;
  };
  const procs = new Map<string, ProcAgg>();
  const ensureProc = (label: string, weight: number, score = 0) => {
    const key = `process:${label}`;
    let agg = procs.get(key);
    if (!agg) {
      agg = {
        key, label, weight, score,
        policies: new Set(), files: new Set(), peers: new Set(),
        instances: new Map(),
      };
      procs.set(key, agg);
    } else {
      agg.weight += weight;
      if (score > agg.score) agg.score = score;
    }
    return agg;
  };

  // Record the concrete process behind a node. Keyed by exec_id (stable across
  // PID reuse); keeps the highest score seen and unions the policies that fired.
  const noteInstance = (
    agg: ProcAgg,
    execId: string | undefined,
    pid: number | undefined,
    binary: string,
    score: number,
    agent: string | undefined,
    policy: string | undefined,
    at: string
  ) => {
    if (!execId) return; // without an exec_id there is nothing to enforce against
    const existing = agg.instances.get(execId);
    if (existing) {
      if (score > existing.score) existing.score = score;
      if (pid && !existing.pid) existing.pid = pid;
      if (agent && !existing.agent) existing.agent = agent;
      if (policy && !existing.policies.includes(policy)) existing.policies.push(policy);
      if (at > existing.lastSeen) existing.lastSeen = at;
      return;
    }
    agg.instances.set(execId, {
      execId,
      pid,
      binary,
      score,
      agent,
      policies: policy ? [policy] : [],
      lastSeen: at,
    });
  };

  // Process lineage edges (runc → sh → pg_isready) parsed from the alert title.
  const chainLinks = new Set<string>();

  for (const alert of alerts) {
    const chain = processChainFromAlert(alert);
    const leafLabel = labelFor(alert.execId, chain.at(-1) || alert.process);
    const leafAgg = ensureProc(leafLabel, Math.max(1, alert.score / 18), alert.score);
    noteInstance(leafAgg, alert.execId, alert.pid, leafLabel, alert.score, alert.agent, alert.policyName, alert.timestamp);
    let prev: string | undefined;
    chain.forEach((token, index) => {
      const label = index === chain.length - 1 ? leafLabel : token;
      ensureProc(label, 0.4, index === chain.length - 1 ? alert.score : 0);
      if (prev && prev !== label) chainLinks.add(`process:${prev}||process:${label}`);
      prev = label;
    });
  }

  for (const event of events) {
    const evLabel = labelFor(event.execId, event.process);
    const agg = ensureProc(evLabel, 0.3);
    noteInstance(agg, event.execId, event.pid, evLabel, 0, event.agent, event.policyName, event.timestamp);
    if (event.policyName) agg.policies.add(event.policyName);
    const file = event.path || (event.policyName ? extractFilePath(event.args) : undefined);
    if (file) agg.files.add(file);
    const peer = peerFromEvent(event);
    if (peer) agg.peers.add(peer);
  }

  // Keep the heaviest processes so the graph stays legible, then attach each
  // one's correlated policy / file / peer nodes and the edges between them.
  const topProcs = [...procs.values()].sort((a, b) => b.weight - a.weight).slice(0, 26);
  const keptProcKeys = new Set(topProcs.map((proc) => proc.key));

  const nodes = new Map<string, GraphNode>();
  const links = new Map<string, GraphLink>();
  const addNode = (id: string, label: string, group: GraphNode["group"], weight: number, score?: number) => {
    const existing = nodes.get(id);
    if (existing) {
      existing.weight += weight;
      if (score !== undefined && score > (existing.score ?? 0)) {
        existing.score = score;
        existing.cls = classifyGraphScore(score);
      }
      return;
    }
    nodes.set(id, {
      id,
      label: shortGraphLabel(label),
      fullLabel: label,
      group,
      weight,
      score,
      cls: group === "process" ? classifyGraphScore(score ?? 0) : undefined
    });
  };
  const addLink = (source: string, target: string, weight: number) => {
    if (source === target) return;
    const key = `${source}->${target}`;
    const existing = links.get(key);
    if (existing) existing.weight += weight;
    else links.set(key, { source, target, weight });
  };

  for (const proc of topProcs) {
    addNode(proc.key, proc.label, "process", Math.max(2, proc.weight), proc.score);
    // Attach the concrete processes this binary node stands for, worst first —
    // the enforcement panel acts on these, not on the node itself.
    const node = nodes.get(proc.key);
    if (node) {
      node.processes = [...proc.instances.values()].sort(
        (a, b) => b.score - a.score || (b.lastSeen > a.lastSeen ? 1 : -1)
      );
    }
    for (const policy of proc.policies) {
      const id = `policy:${policy}`;
      addNode(id, policy, "policy", 1.5);
      addLink(proc.key, id, 2);
    }
    for (const file of [...proc.files].slice(0, 4)) {
      const id = `file:${file}`;
      addNode(id, file, "file", 1);
      addLink(proc.key, id, 1);
    }
    for (const peer of [...proc.peers].slice(0, 4)) {
      // A LAN destination becomes a device node (this process talked to a host
      // on our network); a public one stays a peer (reached out to the internet).
      const device = isDevicePeer(peer);
      const id = device ? `device:${peer}` : `peer:${peer}`;
      addNode(id, peer, device ? "device" : "peer", 1);
      addLink(proc.key, id, 1);
    }
  }
  for (const pair of chainLinks) {
    const [source, target] = pair.split("||");
    if (keptProcKeys.has(source) && keptProcKeys.has(target)) addLink(source, target, 1.5);
  }

  const graphNodes = [...nodes.values()];
  const nodeIds = new Set(graphNodes.map((node) => node.id));
  const graphLinks = [...links.values()].filter(
    (link) => nodeIds.has(String(link.source)) && nodeIds.has(String(link.target))
  );

  return { nodes: graphNodes, links: graphLinks };
}
